/*
 * Copyright 2017 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/sched/mm.h>
#include "trace.h"
#include "ocxl_internal.h"

struct ocxl_context *ocxl_context_alloc(void)
{
	return kzalloc(sizeof(struct ocxl_context), GFP_KERNEL);
}

int ocxl_context_init(struct ocxl_context *ctx, struct ocxl_afu *afu,
		struct address_space *mapping)
{
	int pasid;

	ctx->afu = afu;

	mutex_lock(&afu->contexts_lock);
	pasid = idr_alloc(&afu->contexts_idr, ctx, afu->pasid_base,
			afu->pasid_base + afu->pasid_max, GFP_KERNEL);
	if (pasid < 0) {
		mutex_unlock(&afu->contexts_lock);
		return pasid;
	}
	afu->pasid_count++;
	mutex_unlock(&afu->contexts_lock);

	ctx->pasid = pasid;
	ctx->status = OPENED;
	mutex_init(&ctx->status_mutex);
	ctx->mapping = mapping;
	mutex_init(&ctx->mapping_lock);
	/*
	 * Keep a reference on the AFU to make sure it's valid for the
	 * duration of the life of the context
	 */
	ocxl_afu_get(afu);
	return 0;
}

int ocxl_context_attach(struct ocxl_context *ctx, u64 amr)
{
	int rc;

	mutex_lock(&ctx->status_mutex);
	if (ctx->status != OPENED) {
		rc = -EIO;
		goto out;
	}

	rc = ocxl_spa_add_pe(ctx->afu->fn->link_token, ctx->pasid,
			current->mm->context.id, 0, amr, current->mm);
	if (rc)
		goto out;

	ctx->status = ATTACHED;
out:
	mutex_unlock(&ctx->status_mutex);
	return rc;
}

static int ocxl_mmap_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct ocxl_context *ctx = vma->vm_file->private_data;
	u64 mmio_area, offset;
	int pasid_off;

	offset = vmf->pgoff << PAGE_SHIFT;

	pr_debug("%s: pasid %d address 0x%lx offset 0x%llx\n", __func__,
		ctx->pasid, vmf->address, offset);

	if (offset >= ctx->afu->config.pp_mmio_stride)
		return VM_FAULT_SIGBUS;

	pasid_off = ctx->pasid - ctx->afu->pasid_base;
	mmio_area = ctx->afu->pp_mmio_start +
		pasid_off * ctx->afu->config.pp_mmio_stride +
		offset;

	mutex_lock(&ctx->status_mutex);
	if (ctx->status != ATTACHED) {
		mutex_unlock(&ctx->status_mutex);
		pr_debug("%s: Context not attached, failing pp mmio access\n",
			__func__);
		return VM_FAULT_SIGBUS;
	}
	vm_insert_pfn(vma, vmf->address, mmio_area >> PAGE_SHIFT);
	mutex_unlock(&ctx->status_mutex);
	return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct ocxl_mmap_vmops = {
	.fault = ocxl_mmap_fault,
};

int ocxl_context_iomap(struct ocxl_context *ctx, struct vm_area_struct *vma)
{
	u64 start = vma->vm_pgoff << PAGE_SHIFT;
	u64 len = vma->vm_end - vma->vm_start;

	if (start + len > ctx->afu->config.pp_mmio_stride)
		return -EINVAL;

	vma->vm_flags |= VM_IO | VM_PFNMAP;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_ops = &ocxl_mmap_vmops;
	return 0;
}

int ocxl_context_detach(struct ocxl_context *ctx)
{
	struct pci_dev *dev;
	int afu_control_pos;
	enum ocxl_context_status status;
	int rc;

	mutex_lock(&ctx->status_mutex);
	status = ctx->status;
	ctx->status = CLOSED;
	mutex_unlock(&ctx->status_mutex);
	if (status != ATTACHED)
		return 0;

	dev = to_pci_dev(ctx->afu->fn->dev.parent);
	afu_control_pos = ctx->afu->config.dvsec_afu_control_pos;

	mutex_lock(&ctx->afu->afu_control_lock);
	rc = ocxl_config_terminate_pasid(dev, afu_control_pos, ctx->pasid);
	mutex_unlock(&ctx->afu->afu_control_lock);
	trace_ocxl_terminate_pasid(ctx->pasid, rc);
	if (rc) {
		/*
		 * to be toned down after EEH work. If link is down, we'd
		 * get a zillion such entries
		 *
		 * If the link is up, but we timeout waiting for the
		 * AFU to terminate the pasid, then it's dangerous to
		 * clean up the Process Element entry in the SPA, as
		 * it may be referenced in the future by the AFU. In
		 * which case, we would checkstop because of an
		 * invalide PE access (FIR register 2, bit 42).
		 * So leave the PE defined. Caller shouldn't free the
		 * context so that PASID remains allocated.
		 */
		if (rc == -EBUSY)
			return rc;
	}
	rc = ocxl_spa_remove_pe(dev, ctx->afu->fn->link_token, ctx->pasid);
	if (rc) {
		dev_warn(&ctx->afu->dev,
			"Couldn't remove PE entry cleanly: %d\n", rc);
	}
	return 0;
}

void ocxl_context_detach_all(struct ocxl_afu *afu)
{
	struct ocxl_context *ctx;
	int tmp;

	mutex_lock(&afu->contexts_lock);
	idr_for_each_entry(&afu->contexts_idr, ctx, tmp) {
		ocxl_context_detach(ctx);
		/*
		 * We are force detaching - remove any active mmio
		 * mappings so userspace cannot interfere with the
		 * card if it comes back.  Easiest way to exercise
		 * this is to unbind and rebind the driver via sysfs
		 * while it is in use.
		 */
		mutex_lock(&ctx->mapping_lock);
		if (ctx->mapping)
			unmap_mapping_range(ctx->mapping, 0, 0, 1);
		mutex_unlock(&ctx->mapping_lock);
	}
	mutex_unlock(&afu->contexts_lock);
}

void ocxl_context_free(struct ocxl_context *ctx)
{
	mutex_lock(&ctx->afu->contexts_lock);
	ctx->afu->pasid_count--;
	idr_remove(&ctx->afu->contexts_idr, ctx->pasid);
	mutex_unlock(&ctx->afu->contexts_lock);
	/*
	 * Drop the reference to the AFU device taken during
	 * ocxl_context_init
	 */
	ocxl_afu_put(ctx->afu);
	kfree(ctx);
}
