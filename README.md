# eBPF Hook

`eBPF_Hook` is an **ABK custom external module** repository.

It is not a standalone kernel build repo anymore. ABK is responsible for the
bootable Android 14 / 6.1.75 packaging baseline and flashable outputs. This
repository only injects staged kernel-tree changes through `setup.sh`.

## What It Provides

- a layered `security/abk_ebpf_root/` kernel experiment
- an audit-only `/dev/abk_ebpf_rootctl` control plane
- capability-scoped grant metadata for an ABK-side privileged broker
- a staged BPF sample source file at the highest integration level
- no `/system` executables, no init rc, no SELinux payloads
- no direct credential mutation or third-party app root handoff
- no KernelSU or ABK Control compatibility logic

## ABK Usage

Use this repository as an ABK external module in the `after_patch` stage:

```text
https://github.com/xingguangcuican6666/eBPF_Hook.git;after_patch
```

`before_build` is intentionally ignored.

## Injection Levels

The module supports five levels selected by `ABK_EBPF_HOOK_LEVEL` when the
caller can inject custom environment variables. If not provided, `module.conf`
defaults to `L0`.

- `L0`: no-op; only emit staging metadata and docs
- `L1`: copy source and wire Kconfig/Makefile, but do not enable the module
- `L2`: enable a minimal built-in module with `GET_STATUS` only
- `L3`: enable the full audit-only control plane with grant storage
- `L4`: `L3` plus a staged BPF audit sample source file

## Safe Userspace Delegation

If ABK consumes this repository as an external module, keep privileged behavior
inside a broker owned by ABK. External apps should receive only narrow,
capability-scoped Binder RPC after package/signature verification instead of a
generic `su` channel. See [docs/privileged-broker.md](docs/privileged-broker.md).

## Development

- Entry point: `setup.sh`
- Installer: `scripts/install_abk_ebpf_root.sh`
- Minimal kernel source: `src/kernel/abk_ebpf_root_minimal.c`
- Full kernel source: `src/kernel/abk_ebpf_root_full.c`
- Smoke test: `tests/module_smoke.sh`

Run local checks:

```sh
bash -n setup.sh scripts/install_abk_ebpf_root.sh tests/module_smoke.sh
bash tests/module_smoke.sh
```
