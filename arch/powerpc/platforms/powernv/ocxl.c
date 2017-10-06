/*
 * Copyright 2017 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <asm/pnv-ocxl.h>
#include <asm/opal.h>

#include "pci.h"

#define PNV_OCXL_TL_P9_RECV_CAP		0x000000000000000Full
#define PNV_OCXL_ACTAG_MAX		64
/* PASIDs are 20-bit, but on P9, NPU can only handle 15 bits */
#define PNV_OCXL_PASID_BITS		15
#define PNV_OCXL_PASID_MAX		((1 << PNV_OCXL_PASID_BITS) - 1)

struct npu_link {
	u64 phb_opal_id;
	unsigned int dev;
};

static void set_templ_rate(unsigned int templ, unsigned int rate, char *buf)
{
	int shift, idx;

	WARN_ON(templ > PNV_OCXL_TL_MAX_TEMPLATE);
	idx = (PNV_OCXL_TL_MAX_TEMPLATE - templ) / 2;
	shift = 4 * (1 - ((PNV_OCXL_TL_MAX_TEMPLATE - templ) % 2));
	buf[idx] |= rate << shift;
}

int pnv_ocxl_get_tl_cap(struct pci_dev *dev, long *cap,
			char *rate_buf, int rate_buf_size)
{
	if (rate_buf_size != PNV_OCXL_TL_RATE_BUF_SIZE)
		return -EINVAL;
	/*
	 * The TL capabilities are a characteristic of the NPU, so
	 * we go with hard-coded values.
	 *
	 * The receiving rate of each template is encoded on 4 bits.
	 *
	 * On P9:
	 * - templates 0 -> 3 are supported
	 * - templates 0, 1 and 3 have a 0 receiving rate
	 * - template 2 has receiving rate of 1 (extra cycle)
	 */
	memset(rate_buf, 0, rate_buf_size);
	set_templ_rate(2, 1, rate_buf);
	*cap = PNV_OCXL_TL_P9_RECV_CAP;
	return 0;
}
EXPORT_SYMBOL_GPL(pnv_ocxl_get_tl_cap);

int pnv_ocxl_set_tl_conf(struct pci_dev *dev, long cap,
			uint64_t rate_buf_phys, int rate_buf_size)
{
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;
	int rc;

	if (rate_buf_size != PNV_OCXL_TL_RATE_BUF_SIZE)
		return -EINVAL;

	rc = opal_npu_tl_set(phb->opal_id, dev->devfn, cap,
			rate_buf_phys, rate_buf_size);
	if (rc) {
		dev_err(&dev->dev, "Can't configure host TL: %d\n", rc);
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(pnv_ocxl_set_tl_conf);

int pnv_ocxl_get_max_pasid_value(void)
{
	return PNV_OCXL_PASID_MAX;
}
EXPORT_SYMBOL_GPL(pnv_ocxl_get_max_pasid_value);

int pnv_ocxl_get_max_actag(void)
{
	return PNV_OCXL_ACTAG_MAX;
}
EXPORT_SYMBOL_GPL(pnv_ocxl_get_max_actag);

int pnv_ocxl_spa_setup(struct pci_dev *dev, void *spa_mem, void **platform_data)
{
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;
	struct npu_link *link;
	unsigned int device;
	int rc;

	link = kzalloc(sizeof(*link), GFP_KERNEL);
	if (!link)
		return -ENOMEM;

	device = PCI_SLOT(dev->devfn);
	rc = opal_npu_spa_setup(phb->opal_id, device, virt_to_phys(spa_mem), 0);
	if (rc) {
		dev_err(&dev->dev, "Can't setup Shared Process Area: %d\n", rc);
		kfree(link);
		return rc;
	}
	link->phb_opal_id = phb->opal_id;
	link->dev = device;
	*platform_data = (void *) link;
	return 0;
}
EXPORT_SYMBOL_GPL(pnv_ocxl_spa_setup);

void pnv_ocxl_spa_release(void *platform_data)
{
	struct npu_link *link = (struct npu_link *) platform_data;
	int rc;

	rc = opal_npu_spa_setup(link->phb_opal_id, link->dev, 0, 0);
	WARN_ON(rc);
	kfree(link);
}
EXPORT_SYMBOL_GPL(pnv_ocxl_spa_release);

int pnv_ocxl_spa_remove_pe(void *platform_data, int pe_handle)
{
	struct npu_link *link = (struct npu_link *) platform_data;
	int rc;

	rc = opal_npu_spa_clear_cache(link->phb_opal_id, link->dev, pe_handle);
	return rc;
}
EXPORT_SYMBOL_GPL(pnv_ocxl_spa_remove_pe);
