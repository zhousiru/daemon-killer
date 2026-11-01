# daemon-killer

[English](README.md) | 简体中文

[![CI](https://github.com/zhousiru/daemon-killer/actions/workflows/ci.yml/badge.svg)](https://github.com/zhousiru/daemon-killer/actions/workflows/ci.yml)

为 [Clash](https://github.com/MetaCubeX/mihomo) TUN 提供的故障即阻断（fail-closed）断网开关。Clash 一停，流量就停。

应用只能通过 Clash TUN 访问网络。如果 Clash 退出、崩溃或 TUN 消失，内核防火墙会阻断物理网卡上的直连流量，而不是让它绕过代理泄漏出去。Clash 核心本身不受限制，因此代理上游、DNS 和 `DIRECT` 规则照常工作。

- **双平台原生实现**：macOS 使用 PF，Windows 使用 Windows Filtering Platform
- **故障即阻断**：规则位于内核中，即使守护进程或 Clash 已退出也会继续阻断
- **自我修复**：如果其他进程修改或删除了规则，守护进程会自动恢复
- **安全启用**：除非你确认网络仍然正常，否则 `up` 会自动回滚

## 安装

从 [Releases](https://github.com/zhousiru/daemon-killer/releases) 下载（`dev` 跟随 `main` 分支）。

**macOS**

```sh
xattr -d com.apple.quarantine daemon-killer    # 二进制文件未签名
sudo ./daemon-killer install    # 安装到 /usr/local/bin 并写入示例配置
sudo vi /etc/daemon-killer/config.toml
sudo daemon-killer up           # 在 60 秒内输入 `yes` 以保持开启
```

**Windows**（管理员终端）

```powershell
.\daemon-killer.exe install     # 安装到 Program Files 并加入 PATH
notepad $env:ProgramData\daemon-killer\config.toml
daemon-killer up                # 在新终端中运行
```

在 Windows 上，`core_program` 必须设置为 `mihomo.exe` 的完整路径。可用 `(Get-Process mihomo).Path` 查找。

## 用法

| 命令           | 说明                                                       |
| -------------- | ---------------------------------------------------------- |
| `status`       | 显示保护、Clash、防火墙和服务的状态，以及下一步该做什么    |
| `up`           | 开启保护，或应用修改后的配置；需要确认                     |
| `down`         | 关闭保护                                                   |
| `pause -m <N>` | 暂停保护 N 分钟（默认 5），例如用于登录强制门户（captive portal） |
| `install`      | 安装或更新二进制文件及其服务；不改动网络                   |
| `uninstall`    | 关闭保护并移除二进制文件和服务；保留配置                   |

除 `status` 外，所有命令都需要 root 或管理员终端。开关状态在重启和升级后保持不变。

配置文件从固定的、仅管理员可写的位置读取：macOS 上为 `/etc/daemon-killer/config.toml`，Windows 上为 `%ProgramData%\daemon-killer\config.toml`。修改后请运行 `up`。

## 故障排查

**网络被阻断，而我暂时修不好 Clash。** 以 root 或管理员身份运行 `daemon-killer down`。即使程序未安装，它也会移除规则。

**`down` 之后仍然断网。** daemon-killer 的规则已经移除，问题出在 Clash。在 Clash Party 中重启核心，或退出后重新打开。在 Windows 上，禁用再启用 `Mihomo` 网卡并不能恢复 TUN。

当网卡、核心进程和控制器都正常时，`status` 会报告 Clash 健康；但这并不代表网站能打开，所以确认 `up` 之前请先访问一个网站检查。

**日志**位于 macOS 的 `/var/log/daemon-killer.log` 和 Windows 的 `%ProgramData%\daemon-killer\daemon-killer.log`。

## 局限

- 它保护的是本机上的应用。来自 WSL、虚拟机或网络共享的流量不在范围内。
- 不保证流量一定经过远程代理：Clash 的 `DIRECT` 规则依然生效，本地代理也可能为其他应用转发流量。
- macOS 按 UID 放行 Clash 核心。Clash Party 以 root 运行 mihomo，因此所有 root 进程都可能直连。Windows 按可执行文件路径放行核心。
- 篡改是通过轮询修复的，因此无法阻止一个持续修改规则的管理员进程。
- 在 macOS 上，开机后到守护进程启动之前，网络不受保护。

## 构建

```sh
cargo build --release
```

发布时，修改 `Cargo.toml` 中的 `version` 并推送对应的 `v*` 标签。

## 许可证

[MIT](LICENSE)
