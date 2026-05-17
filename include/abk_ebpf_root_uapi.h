#ifndef _UAPI_ABK_EBPF_ROOT_H
#define _UAPI_ABK_EBPF_ROOT_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define ABK_EBPF_ROOT_IOC_MAGIC 0xa4

#define ABK_EBPF_ROOT_PROFILE_SHELL 1U
#define ABK_EBPF_ROOT_PROFILE_CAPS_ONLY 2U

#define ABK_EBPF_ROOT_NAME_LEN 128
#define ABK_EBPF_ROOT_SHA256_HEX_LEN 65

struct abk_ebpf_root_grant {
	__s32 uid;
	__u32 profile_id;
	__u64 expires_at_ms;
	__u8 one_shot;
	char package_name[ABK_EBPF_ROOT_NAME_LEN];
	char cert_sha256[ABK_EBPF_ROOT_SHA256_HEX_LEN];
	char audit_tag[ABK_EBPF_ROOT_NAME_LEN];
};

struct abk_ebpf_root_grant_list {
	__u32 count;
	struct abk_ebpf_root_grant grants[32];
};

#define ABK_EBPF_ROOT_IOC_ADD_GRANT _IOW(ABK_EBPF_ROOT_IOC_MAGIC, 0x01, struct abk_ebpf_root_grant)
#define ABK_EBPF_ROOT_IOC_DEL_GRANT _IOW(ABK_EBPF_ROOT_IOC_MAGIC, 0x02, struct abk_ebpf_root_grant)
#define ABK_EBPF_ROOT_IOC_LIST_GRANTS _IOR(ABK_EBPF_ROOT_IOC_MAGIC, 0x03, struct abk_ebpf_root_grant_list)
#define ABK_EBPF_ROOT_IOC_FLUSH_EXPIRED _IO(ABK_EBPF_ROOT_IOC_MAGIC, 0x04)

#endif
