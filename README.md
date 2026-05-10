# ABK Dirty SELinux Guard

External module for AnyBase Kernel (ABK) builds that cleans and blocks known
dirty SELinux policy grants after ABK source patching.

The module targets direct SELinux rules associated with dirty sepolicy
detection:

- `system_server` granted `execmem`.
- `untrusted_app*` granted binder `call` access to Magisk binder types.
- `untrusted_app*` granted binder `call` access to KernelSU/KSU binder types.
- `untrusted_app*` granted read-like access to `lsposed_file`.

It removes direct one-line rules from text policy/source files and unified diff
patch additions. If a targeted rule remains after cleanup, strict mode fails the
build by default.

## Usage

Enable "custom external modules" in the ABK app or GitHub Actions, then pass
this repository with the `after_patch` stage:

```text
https://github.com/your-name/ABK_NO_ANYTHING_CAN_CHECK.git;after_patch
```

For ABK APP

```
https://github.com/your-name/ABK_NO_ANYTHING_CAN_CHECK.git
```
Then choose `after_patch`.

Multiple modules are separated with `|`:

```text
https://github.com/your-name/module-a.git;after_patch|https://github.com/your-name/module-b.git;before_build
```

Supported stages:

| Stage | Timing | Typical use |
| --- | --- | --- |
| `after_patch` | After ABK finishes built-in source integrations such as SUSFS, ZRAM, BBG, DDK, Re-Kernel, NTsync, IPSet, and BBR | Apply source patches, copy driver files, edit Kconfig or Makefile files |
| `before_build` | After ABK sets the kernel name and build timestamp, immediately before compilation | Final defconfig edits, generated files, validation checks |

`befor_build` is accepted by ABK as a compatibility alias, but new modules
should use `before_build`.

## Behavior

- `after_patch`: scans `$KERNEL_ROOT`, known ABK patch repositories, and the
  GitHub workspace fallback.
- `before_build`: logs and exits; cleanup belongs before compilation inputs are
  finalized.
- `ABK_DIRTY_SEPOLICY_STRICT=1`: default. Remaining targeted rules fail the
  build.
- `ABK_DIRTY_SEPOLICY_STRICT=0`: logs remaining matches and continues.

The scanner is intentionally conservative. It cleans direct one-line rules only;
unknown multi-line constructs are reported and blocked by strict mode.

## Common Environment Variables

| Variable | Meaning |
| --- | --- |
| `GITHUB_WORKSPACE` | GitHub Actions workspace and ABK repository root |
| `CONFIG` | Build tuple, for example `android15-6.6-118` |
| `KERNEL_ROOT` | Kernel source directory |
| `DEFCONFIG` | GKI defconfig path |
| `CUSTOM_EXTERNAL_MODULE_STAGE` | Current stage, `after_patch` or `before_build` |
| `CUSTOM_EXTERNAL_MODULES_MANIFEST` | Parsed ABK module manifest |
| `ZZH_PATCHES` | ABK repository root |
| `SUSFS4KSU` | SUSFS repository path when SUSFS is enabled |
| `KERNEL_PATCHES` | `WildKernels/kernel_patches` repository path |
| `SUKISU_PATCHES` | `ShirkNeko/SukiSU_patch` repository path |
| `ANYKERNEL3` | AnyKernel3 repository path |
| `ACTION_BUILD` | Action-Build repository path |
| `KBUILD_BUILD_TIMESTAMP` | Available in `before_build` |
| `KBUILD_BUILD_VERSION` | Available in `before_build` |

See [docs/development.md](docs/development.md) for the full development guide.

## Verification

Run local checks:

```bash
bash -n setup.sh scripts/libabk.sh scripts/dirty_sepolicy_guard.sh tests/dirty_sepolicy_guard_test.sh
bash tests/dirty_sepolicy_guard_test.sh
```

## Safety Rules

- Do not commit tokens, private keys, device private data, or opaque binaries.
- Do not download and execute unaudited remote scripts.
- Validate kernel versions and target files before modifying the source tree.
- Fail clearly with `exit 1` when a required condition is not met.
- Prefer changing only `$KERNEL_ROOT`, `$DEFCONFIG`, or files inside this
  module repository.

## License

GPL-3.0. Make sure any third-party code or patches you add are compatible with
the target kernel and this repository license.
