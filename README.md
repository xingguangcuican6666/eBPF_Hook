# eBPF_Hook

Android 14 / GKI 6.1.75 audit-only eBPF root PoC.

This repository builds a boot-safe kernel experiment that:

- adds a minimal in-kernel control plane under `security/abk_ebpf_root/`
- exposes grant management only through `/dev/abk_ebpf_rootctl`
- carries a sample BPF LSM program for audit and grant matching scaffolding
- avoids KernelSU compatibility, `/system` payloads, and boot-time helpers

## Entry points

- Workflow: `.github/workflows/main.yml`
- Local build injection module: `setup.sh`
- Kernel patch logic: `scripts/install_abk_ebpf_root.sh`
- BPF sample: `bpf/abk_root.bpf.c`
- Architecture notes: `docs/architecture.md`

## Notes

- The first target is fixed to `android14-6.1.75` with patch level `2024-05`.
- The in-kernel component is audit-only and does not mutate credentials.
- eBPF is used for hook placement, audit, and future grant matching.
- No executables are installed to `/system`.
