/*
 * Copyright 2017 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/idr.h>
#include <asm/pnv-ocxl.h>
#include "ocxl_internal.h"

static const struct pci_device_id ocxl_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x062B), },
	{ }
};
MODULE_DEVICE_TABLE(pci, ocxl_pci_tbl);


struct ocxl_afu *ocxl_afu_get(struct ocxl_afu *afu)
{
	return (get_device(&afu->dev) == NULL) ? NULL : afu;
}

void ocxl_afu_put(struct ocxl_afu *afu)
{
	put_device(&afu->dev);
}

static struct ocxl_afu *alloc_afu(struct ocxl_fn *fn)
{
	struct ocxl_afu *afu;

	afu = kzalloc(sizeof(struct ocxl_afu), GFP_KERNEL);
	if (!afu)
		return NULL;

	mutex_init(&afu->contexts_lock);
	mutex_init(&afu->afu_control_lock);
	idr_init(&afu->contexts_idr);
	afu->fn = fn;
	return afu;
}

static void free_afu(struct ocxl_afu *afu)
{
	idr_destroy(&afu->contexts_idr);
	kfree(afu);
}

static void free_afu_dev(struct device *dev)
{
	struct ocxl_afu *afu = to_ocxl_afu(dev);

	ocxl_unregister_afu(afu);
	free_afu(afu);
}

static int set_afu_device(struct ocxl_afu *afu, const char *location)
{
	struct ocxl_fn *fn = afu->fn;
	int rc;

	afu->dev.parent = &fn->dev;
	afu->dev.release = free_afu_dev;
	rc = dev_set_name(&afu->dev, "%s.%s.%hhu", afu->config.name, location,
		afu->config.idx);
	return rc;
}

static int assign_afu_actag(struct ocxl_afu *afu, struct pci_dev *dev)
{
	struct ocxl_fn *fn = afu->fn;
	int actag_count, actag_offset;

	actag_count = afu->config.actag_supported;
	actag_offset = ocxl_actag_afu_alloc(fn, actag_count);
	if (actag_offset < 0) {
		dev_err(&afu->dev, "Can't allocate %d actags for AFU: %d\n",
			actag_count, actag_offset);
		return actag_offset;
	}
	afu->actag_base = fn->actag_base + actag_offset;
	afu->actag_length = actag_count;

	ocxl_config_set_afu_actag(dev, afu->config.dvsec_afu_control_pos,
				afu->actag_base, afu->actag_length);
	dev_dbg(&afu->dev, "actag base=%d length=%d\n",
		afu->actag_base, afu->actag_length);
	return 0;
}

static void reclaim_afu_actag(struct ocxl_afu *afu)
{
	struct ocxl_fn *fn = afu->fn;
	int start_offset, size;

	start_offset = afu->actag_base - fn->actag_base;
	size = afu->actag_length;
	ocxl_actag_afu_free(afu->fn, start_offset, size);
}

static int assign_afu_pasid(struct ocxl_afu *afu, struct pci_dev *dev)
{
	struct ocxl_fn *fn = afu->fn;
	int pasid_count, pasid_offset;

	/*
	 * We only support the case where the function configuration
	 * requested enough PASIDs to cover all AFUs.
	 */
	pasid_count = 1 << afu->config.pasid_supported_log;
	pasid_offset = ocxl_pasid_afu_alloc(fn, pasid_count);
	if (pasid_offset < 0) {
		dev_err(&afu->dev, "Can't allocate %d PASIDs for AFU: %d\n",
			pasid_count, pasid_offset);
		return pasid_offset;
	}
	afu->pasid_base = fn->pasid_base + pasid_offset;
	afu->pasid_count = 0;
	afu->pasid_max = pasid_count;

	ocxl_config_set_afu_pasid(dev, afu->config.dvsec_afu_control_pos,
				afu->pasid_base,
				afu->config.pasid_supported_log);
	dev_dbg(&afu->dev, "PASID base=%d, enabled=%d\n",
		afu->pasid_base, pasid_count);
	return 0;
}

static void reclaim_afu_pasid(struct ocxl_afu *afu)
{
	struct ocxl_fn *fn = afu->fn;
	int start_offset, size;

	start_offset = afu->pasid_base - fn->pasid_base;
	size = 1 << afu->config.pasid_supported_log;
	ocxl_pasid_afu_free(afu->fn, start_offset, size);
}

static void define_mmio_ranges(struct ocxl_afu *afu, struct pci_dev *dev)
{
	afu->global_mmio_start =
		pci_resource_start(dev, afu->config.global_mmio_bar) +
		afu->config.global_mmio_offset;
	afu->pp_mmio_start =
		pci_resource_start(dev, afu->config.pp_mmio_bar) +
		afu->config.pp_mmio_offset;
}

static int configure_afu(struct ocxl_afu *afu, u8 afu_idx, struct pci_dev *dev)
{
	int rc;

	rc = ocxl_config_read_afu(dev, &afu->fn->config, &afu->config, afu_idx);
	if (rc)
		return rc;

	rc = set_afu_device(afu, dev_name(&dev->dev));
	if (rc)
		return rc;

	rc = assign_afu_actag(afu, dev);
	if (rc)
		return rc;

	rc = assign_afu_pasid(afu, dev);
	if (rc)
		return rc;

	define_mmio_ranges(afu, dev);
	return 0;
}

static void deconfigure_afu(struct ocxl_afu *afu)
{
	reclaim_afu_pasid(afu);
	reclaim_afu_actag(afu);
}

static int activate_afu(struct pci_dev *dev, struct ocxl_afu *afu)
{
	int rc;

	ocxl_config_set_afu_state(dev, afu->config.dvsec_afu_control_pos, 1);
	/*
	 * Char device creation is the last step, as processes can
	 * call our driver immediately, so all our inits must be finished.
	 */
	rc = ocxl_create_cdev(afu);
	if (rc)
		return rc;
	return 0;
}

static void deactivate_afu(struct ocxl_afu *afu)
{
	/* fxb should disable AFU ? */
	ocxl_destroy_cdev(afu);
}

static int init_afu(struct pci_dev *dev, struct ocxl_fn *fn, u8 afu_idx)
{
	int rc;
	struct ocxl_afu *afu;

	afu = alloc_afu(fn);
	if (!afu)
		return -ENOMEM;

	rc = configure_afu(afu, afu_idx, dev);
	if (rc) {
		free_afu(afu);
		return rc;
	}

	rc = ocxl_register_afu(afu);
	if (rc)
		goto err;

	rc = ocxl_sysfs_add_afu(afu);
	if (rc)
		goto err;

	rc = activate_afu(dev, afu);
	if (rc)
		goto err_sys;

	list_add_tail(&afu->list, &fn->afu_list);
	return 0;

err_sys:
	ocxl_sysfs_remove_afu(afu);
err:
	deconfigure_afu(afu);
	device_unregister(&afu->dev);
	return rc;
}

static void remove_afu(struct ocxl_afu *afu)
{
	list_del(&afu->list);
	ocxl_context_detach_all(afu);
	deactivate_afu(afu);
	ocxl_sysfs_remove_afu(afu);
	deconfigure_afu(afu);
	device_unregister(&afu->dev);
}

static struct ocxl_fn *alloc_function(struct pci_dev *dev)
{
	struct ocxl_fn *fn;

	fn = kzalloc(sizeof(struct ocxl_fn), GFP_KERNEL);
	if (!fn)
		return NULL;

	INIT_LIST_HEAD(&fn->afu_list);
	INIT_LIST_HEAD(&fn->pasid_list);
	INIT_LIST_HEAD(&fn->actag_list);
	mutex_init(&fn->pasid_list_lock);
	mutex_init(&fn->actag_list_lock);
	return fn;
}

static void free_function(struct ocxl_fn *fn)
{
	WARN_ON(!list_empty(&fn->afu_list));
	WARN_ON(!list_empty(&fn->pasid_list));
	kfree(fn);
}

static void free_function_dev(struct device *dev)
{
	struct ocxl_fn *fn = to_ocxl_function(dev);

	free_function(fn);
}

static int set_function_device(struct ocxl_fn *fn, struct pci_dev *dev)
{
	int rc;

	fn->dev.parent = &dev->dev;
	fn->dev.release = free_function_dev;
	rc = dev_set_name(&fn->dev, "ocxlfn.%s", dev_name(&dev->dev));
	if (rc)
		return rc;
	pci_set_drvdata(dev, fn);
	return 0;
}

static int assign_function_actag(struct ocxl_fn *fn)
{
	struct pci_dev *dev = to_pci_dev(fn->dev.parent);

	/* fxb actag can be shared by multiple functions */
	fn->actag_base = 0;
	fn->actag_length = pnv_ocxl_get_max_actag();

	ocxl_config_set_actag(dev, fn->config.dvsec_function_pos,
			fn->actag_base,
			fn->actag_length);
	dev_dbg(&fn->dev, "actag range starting at %d, length %d\n",
		fn->actag_base, fn->actag_length);
	return 0;
}

static int assign_function_pasid(struct ocxl_fn *fn)
{
	int pasid_count, pasid_base;

	if (fn->config.max_pasid_log < 0)
		return 0;

	pasid_count = 1 << fn->config.max_pasid_log;
	pasid_base = ocxl_pasid_alloc(pasid_count);
	if (pasid_base < 0) {
		dev_err(&fn->dev,
			"Couldn't allocate %d PASIDs for function: %d\n",
			pasid_count, pasid_base);
		return pasid_base;
	}
	dev_dbg(&fn->dev, "PASID range starting at %d, enabled=%d\n",
		pasid_base, pasid_count);
	fn->pasid_base = pasid_base;
	return 0;
}

static void reclaim_function_pasid(struct ocxl_fn *fn)
{
	int size;

	if (fn->config.max_pasid_log != -1) {
		size = 1 << fn->config.max_pasid_log;
		ocxl_pasid_free(fn->pasid_base, size);
	}
}

static int configure_function(struct ocxl_fn *fn, struct pci_dev *dev)
{
	int rc;

	rc = pci_enable_device(dev);
	if (rc) {
		dev_err(&dev->dev, "pci_enable_device failed: %d\n", rc);
		return rc;
	}

	/*
	 * fxb afu sanitise: reset, from afu_control dvsec
	 * would also reset all the AFUs
	 *
	 * Can't be done yet for lab bringup, as the adapter doesn't
	 * support it
	 *
	 * some hints for implementation:
	 * - there's not status bit to know when the reset is done. We
	 *    should try reading the config space to know when it's
         *    done.
	 * - Brian thinks we should follow how it's done for PCI:
	 *	Reset
	 *	wait 100ms
	 *	issue config cycles
	 *	allow device up to 1 sec to return success on config
	 *	read before declaring it broken
	 */

	rc = ocxl_config_read_function(dev, &fn->config);
	if (rc)
		return rc;

	rc = set_function_device(fn, dev);
	if (rc)
		return rc;

	rc = assign_function_actag(fn);
	if (rc)
		return rc;

	rc = assign_function_pasid(fn);
	if (rc)
		return rc;

	rc = ocxl_spa_setup(dev, &fn->link_token);
	if (rc)
		return rc;

	rc = ocxl_config_set_TL(dev, fn->config.dvsec_tl_pos);
	if (rc) {
		ocxl_spa_release(dev, fn->link_token);
		return rc;
	}
	return 0;
}

static void deconfigure_function(struct ocxl_fn *fn)
{
	struct pci_dev *dev = to_pci_dev(fn->dev.parent);

	ocxl_spa_release(dev, fn->link_token);
	reclaim_function_pasid(fn);
	pci_disable_device(dev);
}

static struct ocxl_fn *init_function(struct pci_dev *dev)
{
	struct ocxl_fn *fn;
	int rc;

	fn = alloc_function(dev);
	if (!fn)
		return ERR_PTR(-ENOMEM);

	rc = configure_function(fn, dev);
	if (rc) {
		free_function(fn);
		return ERR_PTR(rc);
	}

	rc = ocxl_register_function(fn);
	if (rc) {
		deconfigure_function(fn);
		device_unregister(&fn->dev);
		return ERR_PTR(rc);
	}
	return fn;
}

static void remove_function(struct ocxl_fn *fn)
{
	deconfigure_function(fn);
	device_unregister(&fn->dev);
}

static int ocxl_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int rc, afu_count = 0;
	u8 afu;
	struct ocxl_fn *fn;

	if (!radix_enabled()) {
		dev_err(&dev->dev, "Unsupported memory model (hash)\n");
		return -ENODEV;
	}

	fn = init_function(dev);
	if (IS_ERR(fn)) {
		dev_err(&dev->dev, "function init failed: %li\n",
			PTR_ERR(fn));
		return PTR_ERR(fn);
	}

	for (afu = 0; afu <= fn->config.max_afu_index; afu++) {
		rc = ocxl_config_check_afu_index(dev, &fn->config, afu);
		if (rc > 0) {
			rc = init_afu(dev, fn, afu);
			if (rc) {
				dev_err(&dev->dev,
					"Can't initialize AFU index %d\n", afu);
				continue;
			}
			afu_count++;
		}
	}
	dev_info(&dev->dev, "%d AFU(s) configured\n", afu_count);
	return 0;
}

static void ocxl_remove(struct pci_dev *dev)
{
	struct ocxl_afu *afu, *tmp;
	struct ocxl_fn *fn = pci_get_drvdata(dev);

	list_for_each_entry_safe(afu, tmp, &fn->afu_list, list) {
		remove_afu(afu);
	}
	remove_function(fn);
}

struct pci_driver ocxl_pci_driver = {
	.name = "ocxl",
	.id_table = ocxl_pci_tbl,
	.probe = ocxl_probe,
	.remove = ocxl_remove,
	.shutdown = ocxl_remove,
};
