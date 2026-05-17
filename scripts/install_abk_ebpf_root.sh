#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
KERNEL_ROOT="${KERNEL_ROOT:?KERNEL_ROOT is required}"
DEFCONFIG="${DEFCONFIG:?DEFCONFIG is required}"
MODULE_CONF="$ROOT_DIR/module.conf"

if [ -f "$MODULE_CONF" ]; then
  # shellcheck disable=SC1090
  source "$MODULE_CONF"
fi

log() {
  printf '[eBPF_Hook] %s\n' "$*"
}

die() {
  printf '[eBPF_Hook][ERROR] %s\n' "$*" >&2
  exit 1
}

normalize_level() {
  local raw="${1:-L0}"
  raw="$(printf '%s' "$raw" | tr '[:lower:]' '[:upper:]')"
  case "$raw" in
    0|L0|NOOP) printf 'L0\n' ;;
    1|L1|SOURCE_ONLY|SOURCE-ONLY) printf 'L1\n' ;;
    2|L2|MINIMAL) printf 'L2\n' ;;
    3|L3|FULL) printf 'L3\n' ;;
    4|L4|BPF|AUDIT_BPF|AUDIT-BPF) printf 'L4\n' ;;
    *) return 1 ;;
  esac
}

LEVEL_RAW="${ABK_EBPF_HOOK_LEVEL:-${ABK_MODULE_LEVEL:-${ABK_EBPF_HOOK_LEVEL_DEFAULT:-L0}}}"
LEVEL="$(normalize_level "$LEVEL_RAW")" || die "Unsupported ABK_EBPF_HOOK_LEVEL: $LEVEL_RAW"
STAGE="${CUSTOM_EXTERNAL_MODULE_STAGE:-after_patch}"

if [ -d "$KERNEL_ROOT/common/security" ]; then
  COMMON_ROOT="$KERNEL_ROOT/common"
elif [ -d "$KERNEL_ROOT/security" ]; then
  COMMON_ROOT="$KERNEL_ROOT"
else
  die "Unable to find kernel security directory under $KERNEL_ROOT"
fi

SECURITY_DIR="$COMMON_ROOT/security"
INCLUDE_DIR="$COMMON_ROOT/include/linux"
UAPI_INCLUDE_DIR="$COMMON_ROOT/include/uapi/linux"
MODULE_DIR="$SECURITY_DIR/abk_ebpf_root"
STAGING_DIR="$KERNEL_ROOT/out/abk-ebpf-hook"
STAGING_BPF_DIR="$STAGING_DIR/bpf"
STAGING_DOC_DIR="$STAGING_DIR/docs"
STAGING_INCLUDE_DIR="$STAGING_DIR/include"
STAGING_META_DIR="$STAGING_DIR/meta"

mkdir -p "$STAGING_BPF_DIR" "$STAGING_DOC_DIR" "$STAGING_INCLUDE_DIR" "$STAGING_META_DIR"

append_once() {
  local line="$1"
  local file="$2"
  grep -qF "$line" "$file" || printf '%s\n' "$line" >> "$file"
}

insert_after() {
  local anchor="$1"
  local line="$2"
  local file="$3"
  grep -qF "$line" "$file" && return 0
  if ! grep -qF "$anchor" "$file"; then
    die "Anchor not found in $file: $anchor"
  fi
  sed -i "/$(printf '%s' "$anchor" | sed 's/[^^]/[&]/g; s/\^/\\^/g')/a $line" "$file"
}

install_kernel_tree() {
  local source_variant="$1"
  mkdir -p "$MODULE_DIR" "$UAPI_INCLUDE_DIR" "$INCLUDE_DIR"
  install -m 0644 "$ROOT_DIR/src/kernel/Kconfig" "$MODULE_DIR/Kconfig"
  install -m 0644 "$ROOT_DIR/src/kernel/Makefile" "$MODULE_DIR/Makefile"
  install -m 0644 "$ROOT_DIR/include/abk_ebpf_root.h" "$INCLUDE_DIR/abk_ebpf_root.h"
  install -m 0644 "$ROOT_DIR/include/abk_ebpf_root_uapi.h" "$UAPI_INCLUDE_DIR/abk_ebpf_root_uapi.h"
  install -m 0644 "$ROOT_DIR/src/kernel/$source_variant" "$MODULE_DIR/abk_ebpf_root.c"
  insert_after 'source "security/selinux/Kconfig"' 'source "security/abk_ebpf_root/Kconfig"' "$SECURITY_DIR/Kconfig"
  append_once 'obj-$(CONFIG_ABK_EBPF_ROOT) += abk_ebpf_root/' "$SECURITY_DIR/Makefile"
}

enable_config() {
  local cfg
  for cfg in \
    'CONFIG_BPF=y' \
    'CONFIG_BPF_SYSCALL=y' \
    'CONFIG_BPF_JIT=y' \
    'CONFIG_BPF_EVENTS=y' \
    'CONFIG_BPF_LSM=y' \
    'CONFIG_DEBUG_INFO_BTF=y' \
    'CONFIG_ABK_EBPF_ROOT=y'
  do
    append_once "$cfg" "$DEFCONFIG"
  done
}

stage_common_docs() {
  install -m 0644 "$ROOT_DIR/docs/architecture.md" "$STAGING_DOC_DIR/architecture.md"
  install -m 0644 "$ROOT_DIR/docs/device-baseline.md" "$STAGING_DOC_DIR/device-baseline.md"
  install -m 0644 "$ROOT_DIR/include/abk_ebpf_root_uapi.h" "$STAGING_INCLUDE_DIR/abk_ebpf_root_uapi.h"
  install -m 0644 "$ROOT_DIR/module.conf" "$STAGING_META_DIR/module.conf"
  cat > "$STAGING_META_DIR/level.txt" <<EOF
level=$LEVEL
stage=$STAGE
kernel_root=$KERNEL_ROOT
module_dir=$MODULE_DIR
EOF
}

stage_l4_bpf() {
  install -m 0644 "$ROOT_DIR/bpf/abk_root.bpf.c" "$STAGING_BPF_DIR/abk_root.bpf.c"
}

cat > "$STAGING_DIR/README.txt" <<'EOF'
ABK eBPF Hook staging assets

- meta/level.txt: resolved injection level and stage
- docs/*.md: design and device baseline notes
- include/abk_ebpf_root_uapi.h: userspace ioctl definitions
- bpf/abk_root.bpf.c: only present at L4

This staging directory intentionally contains no /system executables,
no init scripts, and no SELinux policy payloads.
EOF

stage_common_docs

case "$LEVEL" in
  L0)
    log "L0 selected: no-op mode; only staging metadata is emitted."
    ;;
  L1)
    log "L1 selected: source-only wiring without enabling CONFIG_ABK_EBPF_ROOT."
    install_kernel_tree "abk_ebpf_root_minimal.c"
    ;;
  L2)
    log "L2 selected: minimal built-in control plane with GET_STATUS only."
    install_kernel_tree "abk_ebpf_root_minimal.c"
    enable_config
    ;;
  L3)
    log "L3 selected: full audit-only control plane with grant storage."
    install_kernel_tree "abk_ebpf_root_full.c"
    enable_config
    ;;
  L4)
    log "L4 selected: full audit-only control plane plus staged BPF sample."
    install_kernel_tree "abk_ebpf_root_full.c"
    enable_config
    stage_l4_bpf
    ;;
esac

log "completed level=$LEVEL stage=$STAGE common_root=$COMMON_ROOT"
