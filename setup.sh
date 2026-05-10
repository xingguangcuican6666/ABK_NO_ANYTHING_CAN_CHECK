#!/usr/bin/env bash
set -euo pipefail

MODULE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$MODULE_DIR/module.conf" ]; then
  # shellcheck disable=SC1091
  source "$MODULE_DIR/module.conf"
fi

# shellcheck disable=SC1091
source "$MODULE_DIR/scripts/libabk.sh"

abk_require_env KERNEL_ROOT DEFCONFIG CUSTOM_EXTERNAL_MODULE_STAGE

abk_log "module: ${ABK_MODULE_NAME:-ABK external module}"
abk_log "version: ${ABK_MODULE_VERSION:-unknown}"
abk_log "stage: $CUSTOM_EXTERNAL_MODULE_STAGE"
abk_log "config: ${CONFIG:-unknown}"
abk_log "kernel root: $KERNEL_ROOT"

case "$CUSTOM_EXTERNAL_MODULE_STAGE" in
  after_patch)
    abk_log "after_patch: cleaning dirty SELinux policy grants"
    ABK_DIRTY_SEPOLICY_MODE=cleanup \
      DIRTY_SEPOLICY_MODULE_DIR="$MODULE_DIR" \
      bash "$MODULE_DIR/scripts/dirty_sepolicy_guard.sh"
    ;;

  before_build)
    abk_log "before_build: auditing dirty SELinux policy grants"
    ABK_DIRTY_SEPOLICY_MODE=audit \
      DIRTY_SEPOLICY_MODULE_DIR="$MODULE_DIR" \
      bash "$MODULE_DIR/scripts/dirty_sepolicy_guard.sh"
    ;;

  *)
    abk_die "unsupported CUSTOM_EXTERNAL_MODULE_STAGE: $CUSTOM_EXTERNAL_MODULE_STAGE"
    ;;
esac

abk_log "done"
