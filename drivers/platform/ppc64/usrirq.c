/*
 * Copyright 2017 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/interrupt.h>
#include <linux/eventfd.h>
#include <asm/xive.h>
#include <asm/opal.h>

#include <uapi/linux/usrirq.h>

#define DRIVER_NAME		"usrirq"
#define USRIRQ_MINOR_NUM	1
#define MAX_IRQ_PER_CLIENT	0x8000 /* fxb to check with pHyp */

struct usrirq_data {
	struct cdev cdev;
};

struct client_data {
	struct mutex irq_idr_lock;
	struct idr irq_idr;
	pid_t pid; /* only used for debugging */
	struct address_space *mapping;
};

struct usrirq {
	int id;
	int hw_irq;
	unsigned int virq;
	char *name;
	u64 trigger_page;
	struct rcu_head rcu;
	struct eventfd_ctx *ev_ctx;
};

static dev_t usrirq_devt;
static struct class *usrirq_class;


static int irq_offset_to_id(u64 offset)
{
	return offset >> PAGE_SHIFT;
}

static u64 irq_id_to_offset(int id)
{
	return (u64) id << PAGE_SHIFT;
}

static irqreturn_t usrirq_handler(int virq, void *data)
{
	struct usrirq *irq = (struct usrirq *) data;

	pr_debug("Received interrupt id %d (virq:%d)\n", irq->id, virq);
	if (irq->ev_ctx)
		eventfd_signal(irq->ev_ctx, 1);
	return IRQ_HANDLED;
}

static int usrirq_open(struct inode *inode, struct file *file)
{
	struct client_data *cli;

	pr_debug("%s for process %d\n", __func__, current->tgid);

	cli = kzalloc(sizeof(struct client_data), GFP_KERNEL);
	if (!cli)
		return -ENOMEM;
	idr_init(&cli->irq_idr);
	mutex_init(&cli->irq_idr_lock);
	cli->mapping = inode->i_mapping;
	cli->pid = current->tgid;
	file->private_data = cli;
	return 0;
}

static int setup_usrirq(struct usrirq *irq)
{
	int rc;

	irq->virq = irq_create_mapping(NULL, irq->hw_irq);
	if (!irq->virq) {
		pr_err("irq_create_mapping failed\n");
		return -ENOMEM;
	}
	pr_debug("hw_irq %d mapped to virq %u\n", irq->hw_irq, irq->virq);

	irq->name = kasprintf(GFP_KERNEL, "usrirq-%u", irq->virq);
	if (!irq->name) {
		irq_dispose_mapping(irq->virq);
		return -ENOMEM;
	}

	rc = request_irq(irq->virq, usrirq_handler, 0, irq->name, irq);
	if (rc) {
		kfree(irq->name);
		irq->name = NULL;
		irq_dispose_mapping(irq->virq);
		pr_err("request_irq failed: %d\n", rc);
		return rc;
	}
	return 0;
}

static void release_irq(struct usrirq *irq)
{
	free_irq(irq->virq, irq);
	irq_dispose_mapping(irq->virq);
	kfree(irq->name);
	irq->name = NULL;
}

static int alloc_xive_irq(struct usrirq *irq)
{
	__be64 flags, trigger_page;
	s64 rc;

	irq->hw_irq = xive_native_alloc_irq();
	if (irq->hw_irq == 0)
		return -ENOENT;

	rc = opal_xive_get_irq_info(irq->hw_irq, &flags, NULL, &trigger_page,
				NULL, NULL);
	if (rc || !trigger_page) {
		pr_err("Can't get irq trigger page: %lld\n", rc);
		xive_native_free_irq(irq->hw_irq);
		return -ENOENT;
	}
	irq->trigger_page = be64_to_cpu(trigger_page);
	return 0;
}

static void free_xive_irq(struct usrirq *irq)
{
	if (irq->hw_irq != 0) {
		pr_debug("freeing hw_irq %d\n", irq->hw_irq);
		xive_native_free_irq(irq->hw_irq);
		irq->hw_irq = 0;
	}
}

static int alloc_usrirq(struct client_data *cli, u64 *irq_offset)
{
	struct usrirq *irq;
	int rc;

	irq = kzalloc(sizeof(struct usrirq), GFP_KERNEL);
	if (!irq)
		return -ENOMEM;

	mutex_lock(&cli->irq_idr_lock);
	irq->id = idr_alloc(&cli->irq_idr, irq, 1, MAX_IRQ_PER_CLIENT,
				GFP_KERNEL);
	mutex_unlock(&cli->irq_idr_lock);
	if (irq->id < 0) {
		rc = irq->id;
		goto err_free;
	}

	rc = alloc_xive_irq(irq);
	if (rc)
		goto err_idr;

	rc = setup_usrirq(irq);
	if (rc)
		goto err_xive;

	/* alloc event fd */
	*irq_offset = irq_id_to_offset(irq->id);
	pr_debug("Process %d: allocated irq id %d (virq:%d hw_irq:%d mmio:%#llx)\n",
		cli->pid, irq->id, irq->virq, irq->hw_irq, irq->trigger_page);
	return 0;

err_xive:
	free_xive_irq(irq);
err_idr:
	mutex_lock(&cli->irq_idr_lock);
	idr_remove(&cli->irq_idr, irq->id);
	mutex_unlock(&cli->irq_idr_lock);
err_free:
	kfree(irq);
	return rc;
}

static void reclaim_usrirq(struct rcu_head *rcu)
{
	struct usrirq *irq = container_of(rcu, struct usrirq, rcu);

	free_xive_irq(irq);
	kfree(irq);
}

static void __free_usrirq(struct usrirq *irq, struct address_space *mapping,
			pid_t pid)
{
	pr_debug("Freeing irq %d (virq:%d hw_irq:%d) for process %d\n",
		irq->id, irq->virq, irq->hw_irq, pid);
	release_irq(irq);
	unmap_mapping_range(mapping, irq_id_to_offset(irq->id),
			1 << PAGE_SHIFT, 1);
	if (irq->ev_ctx) {
		eventfd_ctx_put(irq->ev_ctx);
		irq->ev_ctx = NULL;
	}
	call_rcu(&irq->rcu, reclaim_usrirq);
}

static int free_usrirq(struct client_data *cli, u64 irq_offset)
{
	struct usrirq *irq;
	int id = irq_offset_to_id(irq_offset);

	mutex_unlock(&cli->irq_idr_lock);
	irq = idr_remove(&cli->irq_idr, id);
	if (!irq) {
		mutex_unlock(&cli->irq_idr_lock);
		return -EINVAL;
	}
	mutex_unlock(&cli->irq_idr_lock);
	__free_usrirq(irq, cli->mapping, cli->pid);
	return 0;
}

static int set_fd_usrirq(struct client_data *cli, struct usrirq_event *ev)
{
	struct usrirq *irq;
	struct eventfd_ctx *ctx;
	int id = irq_offset_to_id(ev->irq_offset);

	ctx = eventfd_ctx_fdget(ev->eventfd);
	if (IS_ERR(ctx))
		return -EINVAL;

	rcu_read_lock();
	irq = idr_find(&cli->irq_idr, id);
	if (!irq) {
		rcu_read_unlock();
		eventfd_ctx_put(ctx);
		return -EINVAL;
	}
	irq->ev_ctx = ctx;
	rcu_read_unlock();
	pr_debug("eventfd %d associated to irq id %d (virq:%d)\n",
		ev->eventfd, irq->id, irq->virq);
	return 0;
}

#define CMD_STR(x) (x == USRIRQ_ALLOC ? "ALLOC" :			\
			x == USRIRQ_FREE ? "FREE" :			\
			x == USRIRQ_SET_EVENTFD ? "SET_EVENTFD" :	\
			"UNKNOWN")

static long usrirq_ioctl(struct file *file, unsigned int cmd,
			unsigned long args)
{
	struct client_data *cli = file->private_data;
	struct usrirq_event event;
	u64 irq_offset;
	int rc;

	pr_debug("%s for process %d, command %s\n", __func__, cli->pid,
		CMD_STR(cmd));

	switch (cmd) {
	case USRIRQ_ALLOC:
		rc = alloc_usrirq(cli, &irq_offset);
		if (!rc) {
			rc = copy_to_user((u64 *) args, &irq_offset,
					sizeof(irq_offset));
			if (rc)
				free_usrirq(cli, irq_offset);
		}
		break;
	case USRIRQ_FREE:
		rc = copy_from_user(&irq_offset, (u64 *) args,
				sizeof(irq_offset));
		if (rc)
			return -EFAULT;
		rc = free_usrirq(cli, irq_offset);
		break;
	case USRIRQ_SET_EVENTFD:
		rc = copy_from_user(&event, (u64 *) args, sizeof(event));
		if (rc)
			return -EFAULT;
		rc = set_fd_usrirq(cli, &event);
		break;
	default:
		rc = -EINVAL;
	}
	return rc;
}

static long usrirq_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long args)
{
	return usrirq_ioctl(file, cmd, args);
}

static int usrirq_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct client_data *cli = file->private_data;
	struct usrirq *irq;
	u64 len;
	int id, rc;

	pr_debug("%s for process %d, %#lx-%#lx, offset %lx\n", __func__,
		cli->pid, vma->vm_start, vma->vm_end, vma->vm_pgoff);
	len = vma->vm_end - vma->vm_start;
	if (len != (1 << PAGE_SHIFT))
		return -EINVAL;

	/* Check validity of the offset */
	id = vma->vm_pgoff; /* page shift already taken into account */
	rcu_read_lock();
	irq = idr_find(&cli->irq_idr, id);
	rcu_read_unlock();
	if (!irq)
		return -EINVAL;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	rc = io_remap_pfn_range(vma, vma->vm_start, irq->trigger_page >> PAGE_SHIFT,
				vma->vm_end - vma->vm_start,
				vma->vm_page_prot);
	return rc;
}

static int usrirq_release(struct inode *inode, struct file *file)
{
	struct client_data *cli = file->private_data;
	struct usrirq *usrirq;
	int id;

	pr_debug("%s for process %d\n", __func__, cli->pid);

	mutex_lock(&cli->irq_idr_lock);
	idr_for_each_entry(&cli->irq_idr, usrirq, id)
		__free_usrirq(usrirq, cli->mapping, cli->pid);
	mutex_unlock(&cli->irq_idr_lock);

	idr_destroy(&cli->irq_idr);
	kfree(cli);
	return 0;
}

static const struct file_operations usrirq_fops = {
	.owner		= THIS_MODULE,
	.open           = usrirq_open,
	.release        = usrirq_release,
	.unlocked_ioctl = usrirq_ioctl,
	.compat_ioctl   = usrirq_compat_ioctl,
	.mmap           = usrirq_mmap,
};


static int create_chardev(struct device *dev, struct usrirq_data *data)
{
	int rc;

	cdev_init(&data->cdev, &usrirq_fops);
	rc = cdev_add(&data->cdev, MKDEV(MAJOR(usrirq_devt), 0),
		USRIRQ_MINOR_NUM);
	if (rc) {
		pr_err("Can't create char device: %d\n", rc);
		return rc;
	}
	device_create(usrirq_class, dev, usrirq_devt, NULL, "%s", DRIVER_NAME);
	return 0;
}

static void delete_chardev(struct usrirq_data *data)
{
	device_destroy(usrirq_class, usrirq_devt);
	cdev_del(&data->cdev);
}

static int usrirq_probe(struct platform_device *pdev)
{
	struct usrirq_data *data;
	int rc;

	data = kzalloc(sizeof(struct usrirq_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	rc = create_chardev(&pdev->dev, data);
	if (rc) {
		kfree(data);
		return rc;
	}
	dev_set_drvdata(&pdev->dev, data);
	return 0;
}

static int usrirq_remove(struct platform_device *pdev)
{
	struct usrirq_data *data;

	data = dev_get_drvdata(&pdev->dev);
	if (!data)
		return 0;
	delete_chardev(data);
	kfree(data);
	return 0;
}

static void usrirq_shutdown(struct platform_device *pdev)
{
	usrirq_remove(pdev);
}

static const struct of_device_id usrirq_match[] = {
	{ .compatible = "ibm,opal-xive-pe",},
	{},
};
MODULE_DEVICE_TABLE(of, usrirq_match);

static struct platform_driver usrirq_driver = {
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table = usrirq_match,
		.owner = THIS_MODULE
	},
	.probe = usrirq_probe,
	.remove = usrirq_remove,
	.shutdown = usrirq_shutdown,
};

static int __init init_usrirq(void)
{
	int rc;

	rc = alloc_chrdev_region(&usrirq_devt, 0, USRIRQ_MINOR_NUM, "usrirq");
	if (rc) {
		pr_err("Can't allocate device major number: %d\n", rc);
		return rc;
	}

	usrirq_class = class_create(THIS_MODULE, "usrirq");
	if (IS_ERR(usrirq_class)) {
		pr_err("Unable to create usrirq class\n");
		unregister_chrdev_region(usrirq_devt, USRIRQ_MINOR_NUM);
		return PTR_ERR(usrirq_class);
	}

	rc = platform_driver_register(&usrirq_driver);
	if (rc) {
		pr_err("Can't register driver: %d\n", rc);
		class_destroy(usrirq_class);
		unregister_chrdev_region(usrirq_devt, USRIRQ_MINOR_NUM);
		return rc;
	}
	return 0;
}

static void exit_usrirq(void)
{
	platform_driver_unregister(&usrirq_driver);
	class_destroy(usrirq_class);
	unregister_chrdev_region(usrirq_devt, USRIRQ_MINOR_NUM);
}

module_init(init_usrirq);
module_exit(exit_usrirq);

MODULE_DESCRIPTION("IBM user irq");
MODULE_LICENSE("GPL");
