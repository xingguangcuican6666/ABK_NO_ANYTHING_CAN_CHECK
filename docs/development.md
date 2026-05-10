# ABK Dirty SELinux Guard Development

This repository is an ABK external module. During a build, ABK clones the
repository and runs `setup.sh` at the configured stage. This module performs
dirty SELinux policy cleanup at `after_patch` and final read-only audit at
`before_build`.

## Input Format

```text
repo_url;stage|repo_url;stage
```

Example:

```text
https://github.com/xingguangcuican6666/ABK_NO_ANYTHING_CAN_CHECK.git;after_patch|https://github.com/xingguangcuican6666/ABK_NO_ANYTHING_CAN_CHECK.git;before_build
```

Rules:

- `repo_url` supports `https://`, `http://`, `git://`, `ssh://`, and `git@`.
- `stage` supports `after_patch` and `before_build`.
- Every module repository must provide `setup.sh` at the repository root.
- ABK runs the entry point with `bash setup.sh`.

## Stage Selection

### after_patch

The guard runs here because ABK built-in source integrations have already
applied their patches, while compilation has not started yet. It scans:

- `$KERNEL_ROOT`
- `$SUSFS4KSU`, `$KERNEL_PATCHES`, and `$SUKISU_PATCHES` when present
- `$GITHUB_WORKSPACE` as a fallback, excluding this module directory

It removes direct one-line targeted grants from text policy/source files and
patch-added lines in unified diffs. It also patches KernelSU-family
`*/selinux/rules.c` files by removing the broad `domain -> ksu:binder` allow
and adding a runtime guard to `apply_one_sepolicy_cmd()`.

### before_build

The guard runs in read-only audit mode here. It does not edit files. It fails
strict builds when direct dirty rules remain or when likely runtime policy
injection sources still mention the targeted subjects, types, classes, and
permissions. It also fails if a KernelSU-family `rules.c` still contains the
broad binder allow or is missing the runtime guard.

Use both `after_patch` and `before_build` entries when debugging devices that
are still detected after cleanup.

## Environment Variables

| Variable | Meaning |
| --- | --- |
| `GITHUB_WORKSPACE` | GitHub Actions workspace and ABK repository root |
| `CONFIG` | Build tuple such as `android15-6.6-118` |
| `KERNEL_ROOT` | Kernel source directory |
| `DEFCONFIG` | GKI defconfig path |
| `ZZH_PATCHES` | ABK repository root |
| `SUSFS4KSU` | Expected SUSFS repository path |
| `KERNEL_PATCHES` | `WildKernels/kernel_patches` clone path |
| `SUKISU_PATCHES` | `ShirkNeko/SukiSU_patch` clone path |
| `ANYKERNEL3` | AnyKernel3 clone path |
| `ACTION_BUILD` | Action-Build clone path |
| `CUSTOM_EXTERNAL_MODULES_MANIFEST` | Parsed custom-module manifest TSV file |
| `CUSTOM_EXTERNAL_MODULE_STAGE` | Current stage |
| `REPO` | Android `repo` tool path |
| `REMOTE_BRANCH` | Queried `kernel/common` target branch |
| `ACTUAL_SUBLEVEL` | Actual sublevel read from the kernel `Makefile` |
| `BRANCH` | KernelSU setup branch argument |
| `KSU_LATEST_COMMIT_DATE` | Latest KernelSU commit date |
| `SUSFS_LATEST_COMMIT_DATE` | Latest SUSFS commit date, or `disabled`/localized value when disabled |
| `AVBTOOL` / `MKBOOTIMG` / `UNPACK_BOOTIMG` / `BOOT_SIGN_KEY_PATH` | Packaging and signing tools |
| `CCACHE_DIR` | ccache directory |

Conditional variables:

- `KSU_VERSION`: set for KernelSU Official builds.
- `KBUILD_BUILD_TIMESTAMP` and `KBUILD_BUILD_VERSION`: guaranteed only in
  `before_build`.
- Standard GitHub Actions variables such as `GITHUB_REPOSITORY`, `GITHUB_REF`,
  `GITHUB_SHA`, `GITHUB_RUN_ID`, `RUNNER_OS`, `RUNNER_TEMP`, `HOME`, and `PATH`
  are also available.

## Guard Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `ABK_DIRTY_SEPOLICY_STRICT` | `1` | Fail when targeted dirty rules remain after cleanup |
| `ABK_DIRTY_SEPOLICY_MODE` | `cleanup` | `cleanup` edits safe direct rules; `audit` is read-only |

## Helper Functions

`setup.sh` loads `scripts/libabk.sh`.

| Function | Purpose |
| --- | --- |
| `abk_log "msg"` | Print a normal log line |
| `abk_warn "msg"` | Print a warning |
| `abk_die "msg"` | Print an error and exit |
| `abk_require_env VAR...` | Require environment variables |
| `abk_common_dir` | Print `$KERNEL_ROOT/common` |
| `abk_kernel_version` | Print `major.minor.sublevel` from `common/Makefile` |
| `abk_stage_is after_patch` | Test the current stage |
| `abk_enable_config CONFIG_FOO` | Idempotently set a defconfig symbol to `y` |
| `abk_module_config CONFIG_FOO` | Idempotently set a defconfig symbol to `m` |
| `abk_disable_config CONFIG_FOO` | Idempotently disable a defconfig symbol |
| `abk_append_line_once file line` | Append one line only if missing |
| `abk_apply_patch file.patch [target_dir]` | Idempotently apply one patch |
| `abk_apply_patch_dir patches/dir [target_dir]` | Apply all `*.patch` files in lexical order |
| `abk_copy_into_kernel source relative_target` | Copy a file or directory under `$KERNEL_ROOT` |

## Common Patterns

Apply patches by kernel version:

```bash
kernel_version="$(abk_kernel_version)"
case "$kernel_version" in
  5.10.*)
    abk_apply_patch_dir "$MODULE_DIR/patches/5.10"
    ;;
  5.15.*)
    abk_apply_patch_dir "$MODULE_DIR/patches/5.15"
    ;;
  6.1.*|6.6.*|6.12.*)
    abk_apply_patch_dir "$MODULE_DIR/patches/6.x"
    ;;
  *)
    abk_die "unsupported kernel version: $kernel_version"
    ;;
esac
```

Edit defconfig only in `before_build`:

```bash
if abk_stage_is before_build; then
  abk_enable_config CONFIG_EXAMPLE_FEATURE
fi
```

Copy source files:

```bash
if abk_stage_is after_patch; then
  abk_copy_into_kernel "$MODULE_DIR/files/example_driver" "common/drivers/example_driver"
fi
```

## Pre-commit Checks

At minimum, run:

```bash
bash -n setup.sh scripts/libabk.sh scripts/dirty_sepolicy_guard.sh tests/dirty_sepolicy_guard_test.sh
bash tests/dirty_sepolicy_guard_test.sh
```

Check the ABK build log and confirm:

- Re-running the module does not duplicate changes.
- Removed dirty rules are logged with file and line numbers.
- KernelSU-family `rules.c` files report `removed broad domain -> ksu binder
  rule` during cleanup when needed.
- Remaining targeted rules fail clearly in strict mode.
- `before_build` audit mode reports suspicious runtime policy sources without
  modifying files.

## Compatibility Advice

- Do not assume one fixed kernel sublevel. Read `CONFIG` or use
  `abk_kernel_version`.
- Handle Android 12/13 5.x and Android 14+ Bazel/Kleaf differences explicitly.
- Do not hardcode paths such as `$GITHUB_WORKSPACE/android15-6.6-118`; use
  `$KERNEL_ROOT`.
- Pin external dependencies to tags or commits when reproducibility matters.
