#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
KERNEL_ROOT="${KERNEL_ROOT:?KERNEL_ROOT is required}"
DEFCONFIG="${DEFCONFIG:?DEFCONFIG is required}"
ANYKERNEL3="${ANYKERNEL3:-}"
MANAGER_PACKAGE="${ABK_MANAGER_PACKAGE:-com.abk.kernel}"
MANAGER_CERT_SIZE="${ABK_MANAGER_CERT_SIZE:-1407}"
MANAGER_CERT_SHA256="${ABK_MANAGER_CERT_SHA256:-34e5e843952277759603cd0f949770b24c868530d80d7baeff08776a7e132b16}"

if [ -d "$KERNEL_ROOT/common/security" ]; then
  COMMON_ROOT="$KERNEL_ROOT/common"
elif [ -d "$KERNEL_ROOT/security" ]; then
  COMMON_ROOT="$KERNEL_ROOT"
else
  echo "[ERROR] Unable to find kernel security directory under $KERNEL_ROOT"
  exit 1
fi

SECURITY_DIR="$COMMON_ROOT/security"
INCLUDE_DIR="$COMMON_ROOT/include/linux"
UAPI_INCLUDE_DIR="$COMMON_ROOT/include/uapi/linux"
MODULE_DIR="$SECURITY_DIR/abk_ebpf_root"
STAGING_DIR="$KERNEL_ROOT/out/abk-ebpf-root"

mkdir -p "$MODULE_DIR" "$UAPI_INCLUDE_DIR" "$INCLUDE_DIR" "$STAGING_DIR"

install -m 0644 "$ROOT_DIR/src/kernel/abk_ebpf_root.c" "$MODULE_DIR/abk_ebpf_root.c"
install -m 0644 "$ROOT_DIR/src/kernel/Kconfig" "$MODULE_DIR/Kconfig"
install -m 0644 "$ROOT_DIR/src/kernel/Makefile" "$MODULE_DIR/Makefile"
install -m 0644 "$ROOT_DIR/include/abk_ebpf_root.h" "$INCLUDE_DIR/abk_ebpf_root.h"
install -m 0644 "$ROOT_DIR/include/abk_ebpf_root_uapi.h" "$UAPI_INCLUDE_DIR/abk_ebpf_root_uapi.h"

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
    echo "[ERROR] Anchor not found in $file: $anchor"
    exit 1
  fi
  sed -i "/$(printf '%s' "$anchor" | sed 's/[^^]/[&]/g; s/\^/\\^/g')/a $line" "$file"
}

insert_after 'source "security/selinux/Kconfig"' 'source "security/abk_ebpf_root/Kconfig"' "$SECURITY_DIR/Kconfig"
append_once 'obj-$(CONFIG_ABK_EBPF_ROOT) += abk_ebpf_root/' "$SECURITY_DIR/Makefile"

for cfg in \
  'CONFIG_BPF=y' \
  'CONFIG_BPF_SYSCALL=y' \
  'CONFIG_BPF_JIT=y' \
  'CONFIG_CGROUP_BPF=y' \
  'CONFIG_BPF_EVENTS=y' \
  'CONFIG_BPF_LSM=y' \
  'CONFIG_DEBUG_INFO_BTF=y' \
  'CONFIG_ABK_EBPF_ROOT=y'
do
  append_once "$cfg" "$DEFCONFIG"
done

cat > "$STAGING_DIR/manager_identity.env" <<EOF
ABK_MANAGER_PACKAGE=$MANAGER_PACKAGE
ABK_MANAGER_CERT_SIZE=$MANAGER_CERT_SIZE
ABK_MANAGER_CERT_SHA256=$MANAGER_CERT_SHA256
EOF

install -m 0755 "$ROOT_DIR/daemon/abkebpfd.sh" "$STAGING_DIR/abkebpfd"
install -m 0755 "$ROOT_DIR/daemon/abksu.sh" "$STAGING_DIR/abksu"
install -m 0644 "$ROOT_DIR/init/abkebpfd.rc" "$STAGING_DIR/abkebpfd.rc"
install -m 0644 "$ROOT_DIR/sepolicy/abkebpfd.te" "$STAGING_DIR/abkebpfd.te"
install -m 0644 "$ROOT_DIR/bpf/abk_root.bpf.c" "$STAGING_DIR/abk_root.bpf.c"
install -m 0644 "$ROOT_DIR/docs/architecture.md" "$STAGING_DIR/architecture.md"

if [ -n "$ANYKERNEL3" ] && [ -d "$ANYKERNEL3" ]; then
  mkdir -p "$ANYKERNEL3/tools/abk-ebpf-root"
  install -m 0755 "$ROOT_DIR/daemon/abkebpfd.sh" "$ANYKERNEL3/tools/abk-ebpf-root/abkebpfd"
  install -m 0755 "$ROOT_DIR/daemon/abksu.sh" "$ANYKERNEL3/tools/abk-ebpf-root/abksu"
  install -m 0644 "$ROOT_DIR/init/abkebpfd.rc" "$ANYKERNEL3/tools/abk-ebpf-root/abkebpfd.rc"
  install -m 0644 "$ROOT_DIR/sepolicy/abkebpfd.te" "$ANYKERNEL3/tools/abk-ebpf-root/abkebpfd.te"
  install -m 0644 "$ROOT_DIR/bpf/abk_root.bpf.c" "$ANYKERNEL3/tools/abk-ebpf-root/abk_root.bpf.c"
  install -m 0644 "$ROOT_DIR/docs/architecture.md" "$ANYKERNEL3/tools/abk-ebpf-root/README.txt"
fi

echo "ABK eBPF root PoC injected into $COMMON_ROOT"
