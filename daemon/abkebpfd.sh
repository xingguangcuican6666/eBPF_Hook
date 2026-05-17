#!/system/bin/sh
set -eu

LOG_TAG="abkebpfd"
BASE_DIR="/data/adb/abk-ebpf-root"
PIN_DIR="/sys/fs/bpf/abk_root"
OBJ="$BASE_DIR/abk_root.bpf.o"
CTL="/dev/abk_ebpf_rootctl"

mkdir -p "$BASE_DIR"
mkdir -p "$PIN_DIR"

log -t "$LOG_TAG" "starting; pin dir=$PIN_DIR ctl=$CTL"

if [ ! -e "$CTL" ]; then
  log -t "$LOG_TAG" "control device missing: $CTL"
  exit 1
fi

if command -v bpftool >/dev/null 2>&1 && [ -f "$OBJ" ]; then
  bpftool prog loadall "$OBJ" "$PIN_DIR" pinmaps "$PIN_DIR/maps" || {
    log -t "$LOG_TAG" "bpftool load failed"
    exit 1
  }
  log -t "$LOG_TAG" "bpf programs loaded"
else
  log -t "$LOG_TAG" "bpftool or bpf object missing; this PoC expects userspace packaging to provide them"
fi

sleep infinity
