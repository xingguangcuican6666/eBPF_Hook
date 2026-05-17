/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

enum abk_audit_event_type {
	ABK_AUDIT_EVENT_BPRM = 1,
	ABK_AUDIT_EVENT_EXEC = 2,
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} audit_ringbuf SEC(".maps");

struct audit_event {
	__u32 uid;
	__u32 tgid;
	__u32 event_type;
	__u32 matched_grant;
	char comm[16];
};

static __always_inline void emit_event(__u32 uid, __u32 tgid, __u32 event_type,
					 __u32 matched_grant)
{
	struct audit_event *event;

	event = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*event), 0);
	if (!event)
		return;
	event->uid = uid;
	event->tgid = tgid;
	event->event_type = event_type;
	event->matched_grant = matched_grant;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	bpf_ringbuf_submit(event, 0);
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(abk_bprm_check_security, struct linux_binprm *bprm, int ret)
{
	const __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffff);
	const __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

	if (ret)
		return ret;
	if (!bprm || !bprm->filename)
		return 0;

	/*
	 * The v1 PoC is audit-only. Keep the original kernel execution path
	 * untouched and emit events for userspace verification instead.
	 */
	emit_event(uid, tgid, ABK_AUDIT_EVENT_BPRM, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int abk_sched_process_exec(void *ctx)
{
	const __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffff);
	const __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

	emit_event(uid, tgid, ABK_AUDIT_EVENT_EXEC, 0);
	return 0;
}
