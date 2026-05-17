#ifndef _LINUX_ABK_EBPF_ROOT_H
#define _LINUX_ABK_EBPF_ROOT_H

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/types.h>

#include <uapi/linux/abk_ebpf_root_uapi.h>

bool abk_bpf_is_granted(kuid_t uid, const char *comm);
u64 abk_bpf_capability_mask(kuid_t uid, const char *comm);
long abk_ebpf_root_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

#endif
