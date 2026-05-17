#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

make_tree() {
  local tree="$1"
  mkdir -p \
    "$tree/common/security/selinux" \
    "$tree/common/include/linux" \
    "$tree/common/include/uapi/linux" \
    "$tree/common/arch/arm64/configs" \
    "$tree/out"
  printf 'source "security/selinux/Kconfig"\n' > "$tree/common/security/Kconfig"
  : > "$tree/common/security/Makefile"
  printf '# base\n' > "$tree/common/arch/arm64/configs/gki_defconfig"
}

run_level() {
  local level="$1"
  local tree="$TMP_DIR/$level"

  make_tree "$tree"
  KERNEL_ROOT="$tree" \
  DEFCONFIG="$tree/common/arch/arm64/configs/gki_defconfig" \
  CUSTOM_EXTERNAL_MODULE_STAGE=after_patch \
  ABK_EBPF_HOOK_LEVEL="$level" \
  bash "$ROOT_DIR/setup.sh"

  test -f "$tree/out/abk-ebpf-hook/docs/privileged-broker.md"

  case "$level" in
    L0)
      test ! -e "$tree/common/security/abk_ebpf_root"
      test ! -e "$tree/common/include/linux/abk_ebpf_root.h"
      grep -q '^level=L0$' "$tree/out/abk-ebpf-hook/meta/level.txt"
      ;;
    L1)
      test -f "$tree/common/security/abk_ebpf_root/abk_ebpf_root.c"
      grep -q 'minimal /dev control plane' "$tree/common/security/abk_ebpf_root/abk_ebpf_root.c"
      ! grep -q '^CONFIG_ABK_EBPF_ROOT=y$' "$tree/common/arch/arm64/configs/gki_defconfig"
      ;;
    L2)
      test -f "$tree/common/security/abk_ebpf_root/abk_ebpf_root.c"
      grep -q 'minimal /dev control plane' "$tree/common/security/abk_ebpf_root/abk_ebpf_root.c"
      grep -q '^CONFIG_ABK_EBPF_ROOT=y$' "$tree/common/arch/arm64/configs/gki_defconfig"
      ;;
    L3)
      test -f "$tree/common/security/abk_ebpf_root/abk_ebpf_root.c"
      grep -q 'full audit-only /dev control plane' "$tree/common/security/abk_ebpf_root/abk_ebpf_root.c"
      test ! -f "$tree/out/abk-ebpf-hook/bpf/abk_root.bpf.c"
      ;;
    L4)
      test -f "$tree/common/security/abk_ebpf_root/abk_ebpf_root.c"
      grep -q 'full audit-only /dev control plane' "$tree/common/security/abk_ebpf_root/abk_ebpf_root.c"
      test -f "$tree/out/abk-ebpf-hook/bpf/abk_root.bpf.c"
      ;;
  esac
}

for level in L0 L1 L2 L3 L4; do
  run_level "$level"
done

echo "module smoke test passed"
