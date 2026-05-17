# Privileged Broker Model

This repository should not hand a generic root channel to third-party Android
apps. If ABK wants to expose controlled functionality to userspace, keep the
privileged surface in a broker owned by ABK and let apps talk to that broker
over Binder.

## Recommended Shape

- the kernel module stays audit-only and stores short-lived grant metadata
- ABK owns the privileged broker and opens `/dev/abk_ebpf_rootctl`
- external apps never receive raw ioctl, unrestricted `su`, or arbitrary shell
- Binder caller identity is the primary security boundary for app requests

## Caller Verification

For every Binder request, the broker should:

1. read the caller UID from Binder instead of trusting app-supplied fields
2. resolve package names for that UID through `PackageManager`
3. verify the signing certificate digest against the stored allowlist
4. reject shared-UID or package-mismatch cases unless explicitly allowed
5. require foreground user confirmation for any state-changing action

The kernel grant list can cache `(uid, package, cert digest, expiry, caps)` to
help the broker make quick decisions, but it should not replace Android-side
package and certificate validation.

## Capability Design

Default grants should stay narrow and read-oriented:

- `ABK_EBPF_ROOT_CAP_BROKER_CLIENT`: caller may talk to the broker
- `ABK_EBPF_ROOT_CAP_STATUS_READ`: caller may read runtime status
- `ABK_EBPF_ROOT_CAP_POLICY_READ`: caller may read its own policy view
- `ABK_EBPF_ROOT_CAP_AUDIT_READ`: caller may read its own audit history

Do not expose generic capabilities such as arbitrary command execution, raw
ioctl passthrough, unrestricted profile writes, or direct SELinux policy
changes. If a write action is needed, route it through a broker-owned operation
table with explicit UI confirmation and auditing.

## ABK Integration Notes

- keep `/dev/abk_ebpf_rootctl` mode restrictive and let only ABK open it
- persist human-readable policy in ABK, not only in the kernel cache
- treat `one_shot` and expiry as UI policy hints that the broker consumes
- log every allow and deny decision with caller UID, package, cert digest, and
  requested capability

## What To Avoid

- direct root shell handoff to apps
- package-name-only trust
- long-lived blanket grants
- app-provided command strings executed by the broker
