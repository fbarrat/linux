/*
 * Copyright 2017 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _OCXL_H_
#define _OCXL_H_

#include <linux/pci.h>

#define OCXL_AFU_NAME_SZ      (24+1)  /* add 1 for NULL termination */

struct ocxl_afu_config {
	u8 idx;
	int dvsec_afu_control_pos;
	char name[OCXL_AFU_NAME_SZ];
	u8 version_major;
	u8 version_minor;
	u8 afuc_type;
	u8 afum_type;
	u8 profile;
	u8 global_mmio_bar;
	u64 global_mmio_offset;
	u32 global_mmio_size;
	u8 pp_mmio_bar;
	u64 pp_mmio_offset;
	u32 pp_mmio_stride;
	u8 log_mem_size;
	u8 pasid_supported_log;
	u16 actag_supported;
};

struct ocxl_fn_config {
	int dvsec_tl_pos;
	int dvsec_function_pos;
	int dvsec_afu_info_pos;
	s8 max_pasid_log;
	s8 max_afu_index;
};

struct ocxl_process_element {
	u64 config_state;
	u32 reserved1[11];
	u32 lpid;
	u32 tid;
	u32 pid;
	u32 reserved2[10];
	u64 amr;
	u32 reserved3[3];
	u32 software_state;
};


extern int ocxl_config_check_afu_index(struct pci_dev *dev,
				struct ocxl_fn_config *fn, int afu_idx);
extern int ocxl_config_read_function(struct pci_dev *dev,
				struct ocxl_fn_config *fn);
extern int ocxl_config_read_afu(struct pci_dev *dev,
				struct ocxl_fn_config *fn,
				struct ocxl_afu_config *afu,
				u8 afu_idx);
extern void ocxl_config_set_afu_pasid(struct pci_dev *dev, int pos,
				int pasid_base, u32 pasid_count_log);
extern void ocxl_config_set_actag(struct pci_dev *dev, int func_dvsec,
				u32 tag_first, u32 tag_count);
extern void ocxl_config_set_afu_actag(struct pci_dev *dev, int pos,
				int actag_base, int actag_count);
extern void ocxl_config_set_afu_state(struct pci_dev *dev, int pos,
				int enable);

extern int ocxl_config_set_TL(struct pci_dev *dev, int tl_dvsec);
/*
 * We can only terminate one PASID at a time, so caller to
 * ocxl_config_terminate_pasid() must guarantee some kind of
 * serialization
 */
extern int ocxl_config_terminate_pasid(struct pci_dev *dev, int afu_control,
				int pasid);

extern int ocxl_spa_setup(struct pci_dev *dev, void **token);
extern void ocxl_spa_release(struct pci_dev *dev, void *token);
extern int ocxl_spa_add_pe(void *token, int pasid, u32 pid, u32 tid,
			u64 amr, struct mm_struct *mm);
extern int ocxl_spa_remove_pe(struct pci_dev *dev, void *token, int pasid);

#endif /* _OCXL_H_ */
