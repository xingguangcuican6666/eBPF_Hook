# eBPF Hook Architecture

This repository is designed to be consumed by ABK through the custom external
module mechanism. ABK remains the source of truth for building and packaging a
bootable kernel. `eBPF_Hook` only changes the kernel source tree.

## Design

- `/dev/abk_ebpf_rootctl` is the only runtime interface.
- The experiment stays audit-only and does not mutate credentials.
- grant entries are capability-scoped metadata for a privileged ABK broker,
  not a direct userspace root handoff
- eBPF sample code is staged for later manual loading; it is never auto-loaded.
- The repository never installs `/system` payloads.

## Integration Levels

- `L0`: no-op integration, used to validate that the ABK external module path
  itself does not cause boot regressions.
- `L1`: source-only integration; Kconfig and Makefile are wired, but the module
  remains disabled in defconfig.
- `L2`: minimal built-in integration; only `GET_STATUS` is supported.
- `L3`: full audit-only control plane; grant add/delete/list paths are enabled.
- `L4`: full control plane plus staged BPF sample source.

## Why The Split Exists

- `L2` exists to test whether a tiny built-in `miscdevice` alone boots safely.
- `L3` isolates the grant storage and ioctl complexity from the registration path.
- `L4` keeps BPF assets separate so kernel boot and userspace loading can be
  validated independently.

## Privileged App Model

- untrusted apps should never receive a generic root shell or raw ioctl access
- a privileged ABK broker should verify caller UID, package name, and signing
  certificate before exposing any narrow RPC
- kernel grant storage is only a fast policy cache and audit source; package and
  certificate validation must still happen in userspace
- capability bits should stay read-oriented by default, while mutating actions
  remain behind explicit manager-side confirmation

## Device Baseline

The current target device baseline still matters because ABK packaging must stay
compatible with its split boot chain. See [device-baseline.md](device-baseline.md).
