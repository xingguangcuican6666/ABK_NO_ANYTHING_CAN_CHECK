# ABK Dirty SELinux Guard

这是一个 AnyBase Kernel (ABK) 自定义外部模块，用于在 ABK 内置补丁完成后清理并阻断已知的 dirty SELinux policy 规则。

模块运行在 `after_patch` 阶段，只处理构建树里的文本策略、源码片段和 unified diff 补丁。它不会修改 Android Framework、App Zygote 或 `SELinux.checkSELinuxAccess` 行为；目标是移除构建输入中不应继续存在的高暴露 SELinux allow 规则。

## 处理范围

当前覆盖四类直接规则：

- `system_server` 被授予 `process execmem`。
- `untrusted_app*` 被授予调用 Magisk binder 类型的 `binder call`。
- `untrusted_app*` 被授予调用 KernelSU/KSU/SukiSU/ReSukiSU binder 类型的 `binder call`。
- `untrusted_app*` 被授予读取 `lsposed_file` 的 read/open/getattr/map/ioctl/lock 类权限。

模块会自动删除可安全识别的单行规则和补丁新增行。多行或无法安全改写的规则不会被盲改；严格模式下会直接让构建失败，并在日志里给出文件和行号。

## ABK 使用方式

在 ABK App 或 GitHub Actions 中启用“自定义外部模块”，并配置本仓库。

GitHub Actions 模块字符串：

```text
https://github.com/xingguangcuican6666/ABK_NO_ANYTHING_CAN_CHECK.git;after_patch
```

ABK App：

```text
https://github.com/xingguangcuican6666/ABK_NO_ANYTHING_CAN_CHECK.git
```

然后阶段选择 `after_patch`。

不要把本模块配置到 `before_build`。该阶段只会打印提示并退出，因为清理应发生在源码补丁完成之后、编译开始之前。

## 行为说明

- 扫描 `$KERNEL_ROOT`。
- 扫描 `$SUSFS4KSU`、`$KERNEL_PATCHES`、`$SUKISU_PATCHES`，如果这些目录存在。
- 在没有其他可用扫描根目录时，回退扫描 `$GITHUB_WORKSPACE`。
- 跳过 `.git`、`.repo`、常见构建输出目录、压缩包、镜像和二进制文件。
- 默认严格模式：发现残留目标规则就失败。

严格模式开关：

```bash
ABK_DIRTY_SEPOLICY_STRICT=1  # 默认，残留目标规则会失败
ABK_DIRTY_SEPOLICY_STRICT=0  # 只警告，不阻断构建
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
- 非目标规则保留。

## 主要文件

- `setup.sh`：ABK 执行入口。
- `scripts/dirty_sepolicy_guard.sh`：dirty SELinux 规则清理和残留扫描逻辑。
- `tests/dirty_sepolicy_guard_test.sh`：本地 shell fixture 测试。
- `docs/development.md`：开发细节和 ABK 外部模块上下文。

## 许可证

GPL-3.0。引入第三方代码或补丁时，请确认其许可证与目标内核和本仓库兼容。
