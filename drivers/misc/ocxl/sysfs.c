/*
 * Copyright 2017 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/sysfs.h>
#include "ocxl_internal.h"

static ssize_t global_mmio_size_show(struct device *device,
				struct device_attribute *attr,
				char *buf)
{
	struct ocxl_afu *afu = to_ocxl_afu(device);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			afu->config.global_mmio_size);
}

static ssize_t pp_mmio_size_show(struct device *device,
				struct device_attribute *attr,
				char *buf)
{
	struct ocxl_afu *afu = to_ocxl_afu(device);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			afu->config.pp_mmio_stride);
}

static ssize_t afu_version_show(struct device *device,
				struct device_attribute *attr,
				char *buf)
{
	struct ocxl_afu *afu = to_ocxl_afu(device);

	return scnprintf(buf, PAGE_SIZE, "%hhu:%hhu\n",
			afu->config.version_major,
			afu->config.version_minor);
}

static ssize_t contexts_show(struct device *device,
		struct device_attribute *attr,
		char *buf)
{
	struct ocxl_afu *afu = to_ocxl_afu(device);

	return scnprintf(buf, PAGE_SIZE, "%d/%d\n",
			afu->pasid_count, afu->pasid_max);
}

static struct device_attribute afu_attrs[] = {
	__ATTR_RO(global_mmio_size),
	__ATTR_RO(pp_mmio_size),
	__ATTR_RO(afu_version),
	__ATTR_RO(contexts),
};

static ssize_t global_mmio_read(struct file *filp, struct kobject *kobj,
				struct bin_attribute *bin_attr, char *buf,
				loff_t off, size_t count)
{
	struct ocxl_afu *afu = to_ocxl_afu(kobj_to_dev(kobj));
	loff_t aligned_start, aligned_end;
	size_t aligned_length;
	void *tbuf;

	if (count == 0 || off < 0 ||
		off >= afu->config.global_mmio_size)
		return 0;

	/* calculate aligned read window */
	count = min((size_t) (afu->config.global_mmio_size - off), count);
	aligned_start = round_down(off, 8);
	aligned_end = round_up(off + count, 8);
	aligned_length = aligned_end - aligned_start;

	/* max we can copy in one read is PAGE_SIZE */
	if (aligned_length > PAGE_SIZE) {
		aligned_length = PAGE_SIZE;
		count = PAGE_SIZE - (off & 0x7);
	}

	/* fxb why? */
	/* use bounce buffer for copy */
	tbuf = (void *) __get_free_page(GFP_KERNEL);
	if (!tbuf)
		return -ENOMEM;

	printk("fxb reading mmio at %llx, %lx\n", afu->global_mmio_start + aligned_start, aligned_length);
	/* perform aligned read from the mmio region */
	memcpy_fromio(tbuf, (void *) (afu->global_mmio_start + aligned_start),
		aligned_length);
	memcpy(buf, tbuf + (off & 0x7), count);

	free_page((unsigned long) tbuf);

	return count;
}

static int global_mmio_mmap(struct file *filp, struct kobject *kobj,
			struct bin_attribute *bin_attr,
			struct vm_area_struct *vma)
{
	struct ocxl_afu *afu = to_ocxl_afu(kobj_to_dev(kobj));
	unsigned long offset;
	int rc;

	if ((vma->vm_pgoff + vma_pages(vma)) > afu->config.global_mmio_size)
		return -EINVAL;

	vma->vm_flags |= VM_IO | VM_PFNMAP;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	offset = vma->vm_pgoff << PAGE_SHIFT;
	offset += afu->global_mmio_start;

	rc = io_remap_pfn_range(vma, vma->vm_start, offset >> PAGE_SHIFT,
				vma->vm_end - vma->vm_start,
				vma->vm_page_prot);
	return rc;
}


int ocxl_sysfs_add_afu(struct ocxl_afu *afu)
{
	int i, rc;

	for (i = 0; i < ARRAY_SIZE(afu_attrs); i++) {
		rc = device_create_file(&afu->dev, &afu_attrs[i]);
		if (rc)
			goto err;
	}

	sysfs_attr_init(&afu->attr_global_mmio.attr);
	afu->attr_global_mmio.attr.name = "global_mmio_area";
	afu->attr_global_mmio.attr.mode = 0600;
	afu->attr_global_mmio.size = afu->config.global_mmio_size;
	afu->attr_global_mmio.read = global_mmio_read;
	afu->attr_global_mmio.mmap = global_mmio_mmap;
	rc = device_create_bin_file(&afu->dev, &afu->attr_global_mmio);
	if (rc) {
		dev_err(&afu->dev,
			"Unable to create global mmio attr for afu: %d\n",
			rc);
		goto err;
	}

	return 0;

err:
	for (i--; i >= 0; i--) {
		device_remove_file(&afu->dev, &afu_attrs[i]);
	}
	return rc;
}

void ocxl_sysfs_remove_afu(struct ocxl_afu *afu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(afu_attrs); i++) {
		device_remove_file(&afu->dev, &afu_attrs[i]);
	}
	device_remove_bin_file(&afu->dev, &afu->attr_global_mmio);
}
