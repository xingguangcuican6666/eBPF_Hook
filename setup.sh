#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if [ -z "${KERNEL_ROOT:-}" ]; then
  echo "[ERROR] KERNEL_ROOT is not set."
  exit 1
fi

exec "$ROOT_DIR/scripts/install_abk_ebpf_root.sh"
