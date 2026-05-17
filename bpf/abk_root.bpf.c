/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} audit_ringbuf SEC(".maps");

struct audit_event {
	__u32 uid;
	__u32 profile;
	char comm[16];
};

static __always_inline void emit_event(__u32 uid, __u32 profile)
{
	struct audit_event *event;

	event = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*event), 0);
	if (!event)
		return;
	event->uid = uid;
	event->profile = profile;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	bpf_ringbuf_submit(event, 0);
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(abk_bprm_check_security, struct linux_binprm *bprm, int ret)
{
	const __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffff);

	if (ret)
		return ret;
	if (!bprm || !bprm->filename)
		return 0;

	/*
	 * This PoC intentionally leaves the privileged transition to the
	 * in-kernel control plane. The BPF side is where grant checks,
	 * policy matching, and audit hooks belong.
	 */
	emit_event(uid, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int abk_sched_process_exec(void *ctx)
{
	const __u32 uid = (__u32)(bpf_get_current_uid_gid() & 0xffffffff);

	emit_event(uid, 0);
	return 0;
}
