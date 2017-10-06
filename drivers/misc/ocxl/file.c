/*
 * Copyright 2017 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <uapi/misc/ocxl.h>
#include "ocxl_internal.h"


#define OCXL_NUM_MINORS 256 /* Total to reserve */

static dev_t ocxl_dev;
static struct class *ocxl_class;
static struct mutex minors_idr_lock;
static struct idr minors_idr;

static struct ocxl_afu *find_and_get_afu(dev_t devno)
{
	struct ocxl_afu *afu;
	int afu_minor;

	afu_minor = MINOR(devno);
	/*
	 * We don't declare an RCU critical section here, as our AFU
	 * is protected by a reference counter on the device. By the time the
	 * minor number of a device is removed from the idr, the ref count of
	 * the device is already at 0, so no user API will access that AFU and
	 * this function can't return it.
	 */
	afu = idr_find(&minors_idr, afu_minor);
	if (afu)
		ocxl_afu_get(afu);
	return afu;
}

static int allocate_afu_minor(struct ocxl_afu *afu)
{
	int minor;

	mutex_lock(&minors_idr_lock);
	minor = idr_alloc(&minors_idr, afu, 0, OCXL_NUM_MINORS, GFP_KERNEL);
	mutex_unlock(&minors_idr_lock);
	return minor;
}

static void free_afu_minor(struct ocxl_afu *afu)
{
	mutex_lock(&minors_idr_lock);
	idr_remove(&minors_idr, MINOR(afu->dev.devt));
	mutex_unlock(&minors_idr_lock);
}

static int afu_open(struct inode *inode, struct file *file)
{
	struct ocxl_afu *afu;
	struct ocxl_context *ctx;
	int rc;

	pr_debug("%s for device %x\n", __func__, inode->i_rdev);

	afu = find_and_get_afu(inode->i_rdev);
	if (!afu)
		return -ENODEV;

	ctx = ocxl_context_alloc();
	if (!ctx) {
		rc = -ENOMEM;
		goto put_afu;
	}

	rc = ocxl_context_init(ctx, afu, inode->i_mapping);
	if (rc)
		goto put_afu;
	file->private_data = ctx;
	ocxl_afu_put(afu);
	return 0;

put_afu:
	ocxl_afu_put(afu);
	return rc;
}

static long afu_ioctl_attach(struct ocxl_context *ctx,
			struct ocxl_ioctl_attach __user *uarg)
{
	struct ocxl_ioctl_attach arg;
	u64 amr = 0;
	int rc;

	pr_debug("%s for context %d\n", __func__, ctx->pasid);

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	/* Make sure reserved fields are not set for forward compatibility */
	if (arg.reserved1 || arg.reserved2 || arg.reserved3)
		return -EINVAL;

	amr = arg.amr & mfspr(SPRN_UAMOR);
	rc = ocxl_context_attach(ctx, amr);
	return rc;
}

static long afu_ioctl(struct file *file, unsigned int cmd,
		unsigned long args)
{
	struct ocxl_context *ctx = file->private_data;

	if (ctx->status == CLOSED)
		return -EIO;

	switch (cmd) {
	case OCXL_IOCTL_ATTACH:
		return afu_ioctl_attach(ctx,
				 (struct ocxl_ioctl_attach __user *) args);
	default:
		return -EINVAL;
	}
}

static long afu_compat_ioctl(struct file *file, unsigned int cmd,
			unsigned long args)
{
	return afu_ioctl(file, cmd, args);
}

static int afu_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct ocxl_context *ctx = file->private_data;

	pr_debug("%s for context %d\n", __func__, ctx->pasid);
	/* Process must attach to access MMIO */
	if (ctx->status != ATTACHED)
		return -EIO;

	return ocxl_context_iomap(ctx, vma);
}

static unsigned int afu_poll(struct file *file, struct poll_table_struct *wait)
{
	struct ocxl_context *ctx = file->private_data;

	pr_debug("%s for context %d\n", __func__, ctx->pasid);

	/* fxb to do: need to notify user land of translation errors */
	return 0;
}

static ssize_t afu_read(struct file *file, char __user *buf, size_t count,
			loff_t *off)
{
	/* fxb to do: need to notify user land of translation errors */
	return -ENOSYS;
}

static int afu_release(struct inode *inode, struct file *file)
{
	struct ocxl_context *ctx = file->private_data;
	int rc;

	pr_debug("%s for device %x\n", __func__, inode->i_rdev);
	rc = ocxl_context_detach(ctx);
	mutex_lock(&ctx->mapping_lock);
	ctx->mapping = NULL;
	mutex_unlock(&ctx->mapping_lock);
	if (rc != -EBUSY)
		ocxl_context_free(ctx);
	return 0;
}

static const struct file_operations ocxl_afu_fops = {
	.owner		= THIS_MODULE,
	.open           = afu_open,
	.unlocked_ioctl = afu_ioctl,
	.compat_ioctl   = afu_compat_ioctl,
	.mmap           = afu_mmap,
	.poll           = afu_poll,
	.read           = afu_read,
	.release        = afu_release,
};

int ocxl_create_cdev(struct ocxl_afu *afu)
{
	int rc;

	cdev_init(&afu->cdev, &ocxl_afu_fops);
	rc = cdev_add(&afu->cdev, afu->dev.devt, 1);
	if (rc) {
		dev_err(&afu->dev, "Unable to add afu char device: %d\n", rc);
		return rc;
	}
	return 0;
}

void ocxl_destroy_cdev(struct ocxl_afu *afu)
{
	cdev_del(&afu->cdev);
}

int ocxl_register_afu(struct ocxl_afu *afu)
{
	int minor;

	minor = allocate_afu_minor(afu);
	if (minor < 0)
		return minor;
	afu->dev.devt = MKDEV(MAJOR(ocxl_dev), minor);
	afu->dev.class = ocxl_class;
	return device_register(&afu->dev);
}

void ocxl_unregister_afu(struct ocxl_afu *afu)
{
	free_afu_minor(afu);
}

int ocxl_register_function(struct ocxl_fn *fn)
{
	/* fxb set ocxl class ? If not, move back to pci.c */
	return device_register(&fn->dev);
}

static char *ocxl_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "ocxl/%s", dev_name(dev));
}

int ocxl_file_init(void)
{
	int rc;

	mutex_init(&minors_idr_lock);
	idr_init(&minors_idr);

	rc = alloc_chrdev_region(&ocxl_dev, 0, OCXL_NUM_MINORS, "ocxl");
	if (rc) {
		pr_err("Unable to allocate ocxl major number: %d\n", rc);
		return rc;
	}

	ocxl_class = class_create(THIS_MODULE, "ocxl");
	if (IS_ERR(ocxl_class)) {
		pr_err("Unable to create ocxl class\n");
		unregister_chrdev_region(ocxl_dev, OCXL_NUM_MINORS);
		return PTR_ERR(ocxl_class);
	}

	ocxl_class->devnode = ocxl_devnode;
	return 0;
}

void ocxl_file_exit(void)
{
	class_destroy(ocxl_class);
	unregister_chrdev_region(ocxl_dev, OCXL_NUM_MINORS);
	idr_destroy(&minors_idr);
}
