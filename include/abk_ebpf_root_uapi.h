#ifndef _UAPI_ABK_EBPF_ROOT_H
#define _UAPI_ABK_EBPF_ROOT_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define ABK_EBPF_ROOT_IOC_MAGIC 0xa4

#define ABK_EBPF_ROOT_NAME_LEN 128
#define ABK_EBPF_ROOT_SHA256_HEX_LEN 65
#define ABK_EBPF_ROOT_STATUS_VERSION 1U

#define ABK_EBPF_ROOT_FLAG_AUDIT_ONLY (1U << 0)
#define ABK_EBPF_ROOT_FLAG_DEVCTL_ONLY (1U << 1)

#define ABK_EBPF_ROOT_CAP_BROKER_CLIENT (1ULL << 0)
#define ABK_EBPF_ROOT_CAP_STATUS_READ (1ULL << 1)
#define ABK_EBPF_ROOT_CAP_POLICY_READ (1ULL << 2)
#define ABK_EBPF_ROOT_CAP_AUDIT_READ (1ULL << 3)

#define ABK_EBPF_ROOT_GRANT_F_ONE_SHOT (1U << 0)
#define ABK_EBPF_ROOT_GRANT_F_REQUIRE_USER_APPROVAL (1U << 1)
#define ABK_EBPF_ROOT_GRANT_F_BINDER_CALLER_ONLY (1U << 2)

struct abk_ebpf_root_grant {
	__s32 uid;
	__u32 profile_id;
	__u64 expires_at_ms;
	/*
	 * Capability metadata for a privileged broker. The audit-only kernel
	 * implementation does not mutate task credentials directly.
	 */
	__u64 capability_mask;
	__u32 grant_flags;
	/* Legacy compatibility bit; prefer ABK_EBPF_ROOT_GRANT_F_ONE_SHOT. */
	__u8 one_shot;
	__u8 reserved0[3];
	char package_name[ABK_EBPF_ROOT_NAME_LEN];
	char cert_sha256[ABK_EBPF_ROOT_SHA256_HEX_LEN];
	char audit_tag[ABK_EBPF_ROOT_NAME_LEN];
};

struct abk_ebpf_root_grant_list {
	__u32 count;
	struct abk_ebpf_root_grant grants[32];
};

struct abk_ebpf_root_status {
	__u32 abi_version;
	__u32 flags;
	__u32 max_grants;
	__u32 grant_count;
};

#define ABK_EBPF_ROOT_IOC_ADD_GRANT _IOW(ABK_EBPF_ROOT_IOC_MAGIC, 0x01, struct abk_ebpf_root_grant)
#define ABK_EBPF_ROOT_IOC_DEL_GRANT _IOW(ABK_EBPF_ROOT_IOC_MAGIC, 0x02, struct abk_ebpf_root_grant)
#define ABK_EBPF_ROOT_IOC_LIST_GRANTS _IOR(ABK_EBPF_ROOT_IOC_MAGIC, 0x03, struct abk_ebpf_root_grant_list)
#define ABK_EBPF_ROOT_IOC_FLUSH_EXPIRED _IO(ABK_EBPF_ROOT_IOC_MAGIC, 0x04)
#define ABK_EBPF_ROOT_IOC_GET_STATUS _IOR(ABK_EBPF_ROOT_IOC_MAGIC, 0x05, struct abk_ebpf_root_status)

#endif
