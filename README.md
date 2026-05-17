# eBPF_Hook

Android 14 / GKI 6.1.75 eBPF-assisted root PoC.

This repository reuses the ABK GKI workflow and injects a local module that:

- adds a minimal in-kernel root control plane under `security/abk_ebpf_root/`
- stages an `abkebpfd` loader, `abksu` helper, init rc, and sepolicy samples
- carries a sample BPF LSM program for audit/policy scaffolding
- optionally chains `ABK_control_module` in `before_build`

## Entry points

- Workflow: `.github/workflows/main.yml`
- Local build injection module: `setup.sh`
- Kernel patch logic: `scripts/install_abk_ebpf_root.sh`
- BPF sample: `bpf/abk_root.bpf.c`
- Architecture notes: `docs/architecture.md`

## Trusted manager defaults

- Package: `com.abk.kernel`
- Cert size: `1407`
- Cert SHA-256: `34e5e843952277759603cd0f949770b24c868530d80d7baeff08776a7e132b16`

## Notes

- The first target is fixed to `android14-6.1.75` with patch level `2024-05`.
- The PoC keeps the privileged state transition in a tiny in-tree kernel module.
- eBPF is used for hook placement, audit, and future grant matching.
