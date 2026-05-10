#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$WORK_DIR"
}

trap cleanup EXIT

mkdir -p "$WORK_DIR/kernel/common/security/sepolicy"
mkdir -p "$WORK_DIR/kernel/KernelSU/kernel/selinux"
mkdir -p "$WORK_DIR/kernel/irrelevant"
mkdir -p "$WORK_DIR/kernel_patches"
mkdir -p "$WORK_DIR/module"

POLICY_FILE="$WORK_DIR/kernel/common/security/sepolicy/app.te"
C_FILE="$WORK_DIR/kernel/KernelSU/kernel/selinux/rules.c"
PATCH_FILE="$WORK_DIR/kernel_patches/dirty.patch"

cat > "$POLICY_FILE" <<'EOF'
allow system_server self:process execmem;
allow untrusted_app KSU:binder call;
allow untrusted_app Magisk:binder { call transfer };
allow untrusted_app lsposed_file:file { read open getattr map };
allow shell shell:process sigchld;
EOF

cat > "$C_FILE" <<'EOF'
void install_rules(void)
{
    ksu_allow(db, "untrusted_app", "kernelsu", "binder", "call");
    ksu_allow(db, "shell", "shell", "process", "sigchld");
}
EOF

cat > "$PATCH_FILE" <<'EOF'
diff --git a/app.te b/app.te
index 1111111..2222222 100644
--- a/app.te
+++ b/app.te
@@ -1,2 +1,5 @@
 allow shell shell:process sigchld;
+allow system_server self:process execmem;
+allow untrusted_app ksu:binder call;
+allow untrusted_app lsposed_file:file read;
 allow shell shell:file read;
EOF

for i in $(seq 1 200); do
  printf 'allow untrusted_app ksu:binder call;\n' > "$WORK_DIR/kernel/irrelevant/file-$i.txt"
done

run_guard() {
  KERNEL_ROOT="$WORK_DIR/kernel" \
  KERNEL_PATCHES="$WORK_DIR/kernel/KernelSU" \
  SUKISU_PATCHES="$WORK_DIR/kernel_patches" \
  GITHUB_WORKSPACE="$WORK_DIR" \
  DIRTY_SEPOLICY_MODULE_DIR="$WORK_DIR/module" \
  ABK_DIRTY_SEPOLICY_MODE=cleanup \
  ABK_DIRTY_SEPOLICY_STRICT=1 \
    bash "$ROOT_DIR/scripts/dirty_sepolicy_guard.sh" >/tmp/dirty_sepolicy_guard_test.log
}

run_guard
run_guard

if grep -q "$WORK_DIR/kernel/KernelSU$" /tmp/dirty_sepolicy_guard_test.log; then
  echo "nested KernelSU root was scanned separately" >&2
  exit 1
fi

if ! grep -q 'total unique candidates: 3' /tmp/dirty_sepolicy_guard_test.log; then
  echo "candidate prefilter did not keep the expected focused file set" >&2
  cat /tmp/dirty_sepolicy_guard_test.log >&2
  exit 1
fi

if grep -Eq 'system_server.*execmem|untrusted_app.*(ksu|magisk).*binder.*call|untrusted_app.*lsposed_file' "$POLICY_FILE"; then
  echo "dirty policy rule remained in policy file" >&2
  exit 1
fi

if grep -Eq 'untrusted_app.*kernelsu.*binder.*call' "$C_FILE"; then
  echo "dirty policy rule remained in C source" >&2
  exit 1
fi

if grep -Eq '^\+.*(system_server.*execmem|untrusted_app.*ksu.*binder.*call|untrusted_app.*lsposed_file)' "$PATCH_FILE"; then
  echo "dirty policy rule remained in patch additions" >&2
  exit 1
fi

if ! grep -q '^@@ -1,2 +1,2 @@' "$PATCH_FILE"; then
  echo "patch hunk counts were not recomputed" >&2
  exit 1
fi

if ! grep -q 'allow shell shell:process sigchld;' "$POLICY_FILE"; then
  echo "clean policy rule was removed" >&2
  exit 1
fi

if ! grep -q 'ksu_allow(db, "shell", "shell", "process", "sigchld");' "$C_FILE"; then
  echo "clean C rule was removed" >&2
  exit 1
fi

FAIL_DIR="$(mktemp -d "$WORK_DIR/fail.XXXXXX")"
mkdir -p "$FAIL_DIR/kernel/common/security/sepolicy" "$FAIL_DIR/module"
cat > "$FAIL_DIR/kernel/common/security/sepolicy/multiline.te" <<'EOF'
allow untrusted_app ksu:binder {
  call
};
EOF

if KERNEL_ROOT="$FAIL_DIR/kernel" \
  DIRTY_SEPOLICY_MODULE_DIR="$FAIL_DIR/module" \
  ABK_DIRTY_SEPOLICY_MODE=cleanup \
  ABK_DIRTY_SEPOLICY_STRICT=1 \
    bash "$ROOT_DIR/scripts/dirty_sepolicy_guard.sh" >/tmp/dirty_sepolicy_guard_fail_test.log 2>&1; then
  echo "strict mode allowed a multi-line dirty policy rule" >&2
  exit 1
fi

if ! grep -q 'multiline' /tmp/dirty_sepolicy_guard_fail_test.log; then
  echo "strict failure did not report the multi-line dirty policy rule" >&2
  exit 1
fi

AUDIT_DIRECT_DIR="$(mktemp -d "$WORK_DIR/audit-direct.XXXXXX")"
mkdir -p "$AUDIT_DIRECT_DIR/kernel/common/security/sepolicy" "$AUDIT_DIRECT_DIR/module"
AUDIT_DIRECT_FILE="$AUDIT_DIRECT_DIR/kernel/common/security/sepolicy/app.te"
cat > "$AUDIT_DIRECT_FILE" <<'EOF'
allow untrusted_app ksu:binder call;
allow shell shell:process sigchld;
EOF

if KERNEL_ROOT="$AUDIT_DIRECT_DIR/kernel" \
  DIRTY_SEPOLICY_MODULE_DIR="$AUDIT_DIRECT_DIR/module" \
  ABK_DIRTY_SEPOLICY_MODE=audit \
  ABK_DIRTY_SEPOLICY_STRICT=1 \
    bash "$ROOT_DIR/scripts/dirty_sepolicy_guard.sh" >/tmp/dirty_sepolicy_guard_audit_direct.log 2>&1; then
  echo "audit mode allowed a direct dirty policy rule" >&2
  exit 1
fi

if ! grep -q 'allow untrusted_app ksu:binder call;' "$AUDIT_DIRECT_FILE"; then
  echo "audit mode modified a direct dirty policy file" >&2
  exit 1
fi

AUDIT_RUNTIME_DIR="$(mktemp -d "$WORK_DIR/audit-runtime.XXXXXX")"
mkdir -p "$AUDIT_RUNTIME_DIR/kernel/KernelSU/kernel" "$AUDIT_RUNTIME_DIR/module"
cat > "$AUDIT_RUNTIME_DIR/kernel/KernelSU/kernel/core_hook.c" <<'EOF'
void install_runtime_policy(void)
{
    policydb_update(db);
    const char *source = "untrusted_app";
    const char *target = "kernelsu";
    const char *klass = "binder";
    const char *perm = "call";
}
EOF

if KERNEL_ROOT="$AUDIT_RUNTIME_DIR/kernel" \
  DIRTY_SEPOLICY_MODULE_DIR="$AUDIT_RUNTIME_DIR/module" \
  ABK_DIRTY_SEPOLICY_MODE=audit \
  ABK_DIRTY_SEPOLICY_STRICT=1 \
    bash "$ROOT_DIR/scripts/dirty_sepolicy_guard.sh" >/tmp/dirty_sepolicy_guard_audit_runtime.log 2>&1; then
  echo "audit mode allowed a suspicious runtime policy source" >&2
  exit 1
fi

if ! grep -q 'runtime_untrusted_app_ksu_binder_policy_source' /tmp/dirty_sepolicy_guard_audit_runtime.log; then
  echo "audit mode did not report the runtime policy source category" >&2
  cat /tmp/dirty_sepolicy_guard_audit_runtime.log >&2
  exit 1
fi

echo "dirty sepolicy guard tests passed"
