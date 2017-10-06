/*
 * Copyright 2017 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _ASM_PVN_OCXL_H
#define _ASM_PVN_OCXL_H

#include <linux/pci.h>

#define PNV_OCXL_TL_MAX_TEMPLATE        63
#define PNV_OCXL_TL_BITS_PER_RATE       4
#define PNV_OCXL_TL_RATE_BUF_SIZE       ((PNV_OCXL_TL_MAX_TEMPLATE+1) * PNV_OCXL_TL_BITS_PER_RATE / 8)

extern int pnv_ocxl_get_tl_cap(struct pci_dev *dev, long *cap,
			char *rate_buf, int rate_buf_size);
extern int pnv_ocxl_set_tl_conf(struct pci_dev *dev, long cap,
			uint64_t rate_buf_phys, int rate_buf_size);
extern int pnv_ocxl_get_max_pasid_value(void);
extern int pnv_ocxl_get_max_actag(void);

extern int pnv_ocxl_spa_setup(struct pci_dev *dev, void *spa_mem,
			void **platform_data);
extern void pnv_ocxl_spa_release(void *platform_data);
extern int pnv_ocxl_spa_remove_pe(void *platform_data, int pe_handle);

#endif /* _ASM_PVN_OCXL_H */
