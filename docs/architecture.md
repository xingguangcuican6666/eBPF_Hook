# eBPF Root PoC

This repository builds a narrow proof of concept for Android 14 GKI `6.1.75`
with security patch level `2024-05`.

## Design

- The in-kernel module is a `/dev` control plane, not a root engine.
- eBPF owns the policy and audit hooks.
- `/dev/abk_ebpf_rootctl` is the only grant management interface.
- Grants are bound to `uid + package_name + cert_sha256`.
- v1 is audit-only and does not change task credentials.

## Build path

- GitHub Actions syncs the Android common kernel source for `android14-6.1-2024-05`.
- The local setup script copies kernel files, enables Kconfig, and stages
  BPF source, UAPI headers, and notes into the build output.
- Delivery stays aligned with the ABK baseline: AnyKernel3 is the primary flash
  artifact, not a simplified raw `boot.img`.

## Device baseline

- The connected device target uses a split boot chain:
  - `boot_a` = `100663296` bytes
  - `init_boot_a` = `8388608` bytes
  - `vendor_boot_a` = `100663296` bytes
- `boot_a` and `init_boot_a` both use Android boot header version `4`.
- `vendor_boot_a` uses the `VNDRBOOT` vendor boot format.
- Because of that layout, kernel delivery should preserve the existing boot
  structure instead of assuming a standalone CI-generated `boot.img` is safe.

## Limits of this PoC

- The BPF program is a policy/audit scaffold rather than a complete grant path.
- No executables are added to `/system`.
- No KernelSU compatibility or root hiding is provided.
