# ABK Dirty SELinux Guard

这是一个 AnyBase Kernel (ABK) 自定义外部模块，用于在 ABK 内置补丁完成后清理并阻断已知的 dirty SELinux policy 规则。

模块分两阶段运行：

- `after_patch`：清理构建输入中可安全删除的直接 dirty allow 规则。
- `before_build`：最终只读审计，发现残留规则或疑似运行时 policy 注入源就失败并输出证据。

它不会修改 Android Framework、App Zygote 或 `SELinux.checkSELinuxAccess` 行为；目标是移除或阻断构建输入中不应继续存在的高暴露 SELinux 规则来源。

## 处理范围

当前覆盖四类直接规则：

- `system_server` 被授予 `process execmem`。
- `untrusted_app*` 被授予调用 Magisk binder 类型的 `binder call`。
- `untrusted_app*` 被授予调用 KernelSU/KSU/SukiSU/ReSukiSU binder 类型的 `binder call`。
- `untrusted_app*` 被授予读取 `lsposed_file` 的 read/open/getattr/map/ioctl/lock 类权限。

模块会在 `after_patch` 自动删除可安全识别的单行规则和补丁新增行。多行、无法安全改写的规则、以及疑似运行时 policy 注入代码不会被盲改；`before_build` 严格审计会直接让构建失败，并在日志里给出文件、行号、分类和上下文。

对 KernelSU/SukiSU/ReSukiSU，模块还会 patch `kernel/selinux/rules.c`：

- 移除默认的 `domain -> ksu:binder *` broad allow，因为它会覆盖 `untrusted_app -> ksu:binder call`。
- 在 `apply_one_sepolicy_cmd()` 中插入过滤器，阻止模块 `sepolicy.rule`、profile sepolicy 或 `ksud sepolicy` 在运行时重新加入这些检测特征规则。

## ABK 使用方式

在 ABK App 或 GitHub Actions 中启用“自定义外部模块”，并配置本仓库。

GitHub Actions 模块字符串需要同时配置两个阶段：

```text
https://github.com/xingguangcuican6666/ABK_NO_ANYTHING_CAN_CHECK.git;after_patch|https://github.com/xingguangcuican6666/ABK_NO_ANYTHING_CAN_CHECK.git;before_build
```

ABK App：

```text
https://github.com/xingguangcuican6666/ABK_NO_ANYTHING_CAN_CHECK.git
```

先添加一次并选择 `after_patch`，再添加一次并选择 `before_build`。如果 App 当前只支持一个阶段，优先用 `after_patch` 清理；但最终排查被检测问题时必须跑 `before_build` 审计。

## 行为说明

- 扫描 `$KERNEL_ROOT`。
- 扫描 `$SUSFS4KSU`、`$KERNEL_PATCHES`、`$SUKISU_PATCHES`，如果这些目录存在。
- 在没有其他可用扫描根目录时，回退扫描 `$GITHUB_WORKSPACE`。
- 自动定位并 patch KernelSU 源码里的 `*/selinux/rules.c`。
- 跳过 `.git`、`.repo`、常见构建输出目录、压缩包、镜像和二进制文件。
- 默认严格模式：发现残留目标规则就失败。
- `before_build` 为只读审计模式，不会修改任何文件。

严格模式开关：

```bash
ABK_DIRTY_SEPOLICY_STRICT=1  # 默认，残留目标规则会失败
ABK_DIRTY_SEPOLICY_STRICT=0  # 只警告，不阻断构建
```

内部模式开关由 `setup.sh` 按阶段设置：

```bash
ABK_DIRTY_SEPOLICY_MODE=cleanup  # after_patch
ABK_DIRTY_SEPOLICY_MODE=audit    # before_build
```

## 本地验证

```bash
bash -n setup.sh scripts/libabk.sh scripts/dirty_sepolicy_guard.sh tests/dirty_sepolicy_guard_test.sh
bash tests/dirty_sepolicy_guard_test.sh
```

测试覆盖：

- 四类目标规则的清理。
- patch hunk 行数重算。
- 重复运行幂等。
- 多行目标规则在严格模式下失败。
- KernelSU broad binder 规则会被移除。
- KernelSU runtime sepolicy handler 会插入过滤器且保持幂等。
- `before_build` 审计失败时不修改文件。
- 疑似运行时 policy 注入源会被审计拦截。
- 非目标规则保留。

## 主要文件

- `setup.sh`：ABK 执行入口。
- `scripts/dirty_sepolicy_guard.sh`：dirty SELinux 规则清理和残留扫描逻辑。
- `tests/dirty_sepolicy_guard_test.sh`：本地 shell fixture 测试。
- `docs/development.md`：开发细节和 ABK 外部模块上下文。

## 许可证

GPL-3.0。引入第三方代码或补丁时，请确认其许可证与目标内核和本仓库兼容。
