#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
MODULE_CONF="$ROOT_DIR/module.conf"

if [ -f "$MODULE_CONF" ]; then
  # shellcheck disable=SC1090
  source "$MODULE_CONF"
fi

if [ -z "${KERNEL_ROOT:-}" ]; then
  echo "[ERROR] KERNEL_ROOT is not set."
  exit 1
fi

case "${CUSTOM_EXTERNAL_MODULE_STAGE:-after_patch}" in
  after_patch)
    ;;
  before_build)
    echo "[INFO] eBPF Hook skips before_build; after_patch is the only supported stage."
    exit 0
    ;;
  *)
    echo "[ERROR] Unsupported CUSTOM_EXTERNAL_MODULE_STAGE: ${CUSTOM_EXTERNAL_MODULE_STAGE:-unknown}"
    exit 1
    ;;
esac

exec "$ROOT_DIR/scripts/install_abk_ebpf_root.sh"
