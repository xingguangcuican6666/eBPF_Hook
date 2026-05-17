# ABK eBPF Root PoC

This repository builds a narrow proof of concept for Android 14 GKI `6.1.75`
with security patch level `2024-05`.

## Design

- The in-kernel module owns the privileged primitive.
- eBPF owns the policy and audit hooks.
- `abkebpfd` is the trusted loader that pins programs and maps.
- `/dev/abk_ebpf_rootctl` is the only grant management interface.
- Grants are bound to `uid + package_name + cert_sha256`.

## Build path

- GitHub Actions reuses the ABK GKI build workflow.
- The current repository clones itself as an `after_patch` custom module.
- `ABK_control_module` can also be injected as a `before_build` module.
- The local setup script copies kernel files, enables Kconfig, and stages
  daemon and BPF assets into the build output and AnyKernel payload.

## Limits of this PoC

- It does not yet patch `abkebpfd` into the final ramdisk automatically.
- The BPF program is a policy/audit scaffold rather than a complete grant path.
- No Magisk compatibility or root hiding is provided.
