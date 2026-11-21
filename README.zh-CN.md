# BMC DHCP

在 Mac 上为直连服务器的 BMC 分配临时 DHCP 地址，并找到管理页面。

[English](README.md) · [快速上手](docs/QUICKSTART.md) · [架构](docs/ARCHITECTURE.md) · [验证记录](docs/VALIDATION.md)

适合新机器上架、机房调试：Mac 的以太网卡接到 BMC 专用管理口，启动临时 DHCP，获得地址后打开 iDRAC、iLO、XCC、iBMC 等管理界面。

![原生控制台：普通权限测试，未连接 BMC](docs/screenshot-macos.png)

## 下载与系统要求

从 [GitHub Releases](https://github.com/zyf18195378233/bmc-dhcp/releases) 下载并完整解压，不要只复制应用入口。

| 平台 | 包名 | 入口 |
| --- | --- | --- |
| macOS 15+ / Apple Silicon | `BMC-DHCP-<版本>-macOS-arm64.zip` | `BMC DHCP.app` |
| macOS 15+ / Intel | `BMC-DHCP-<版本>-macOS-x86_64.zip` | `BMC DHCP.app` |
| Windows 10/11 / x64 | `BMC-DHCP-<版本>-Windows-x64.zip` | `BMC DHCP.exe` / `bmcd.exe` |

二进制包自带 Python、Scapy；Windows 二层抓包所需 Npcap 另行安装。签名、实际验证的平台和物理硬件限制见 [验证记录](docs/VALIDATION.md)。

## 主要能力

- 原生 macOS 窗口，随包携带 Python 和 scapy，不要求安装 Homebrew、Python 或 Chrome。
- 指定单个网口、子网、地址池和租期，实时显示租约、主机名及厂商识别证据。
- 同一 MAC 尽量保持相同 IP；可以打开管理页、复制地址、查看实时日志和诊断。
- BMC 已设静态 IP 时，可使用「IP 探测」的被动侦听、IPv6 邻居与限定网段 ARP 扫描。
- 改网口前先持久化原配置；备份失败就不修改。停止时恢复；恢复失败保留记录并允许重试。
- 本地控制台仅监听环回地址，校验访问令牌、Host 和 Origin。

当前为 **Beta**：本地协议、环回 UDP、打包和原生窗口验证通过，GitHub 托管的 macOS 15/Windows x64 构建与包内验证也已通过；尚未接真实 BMC 验证 DHCP、管理员网口改配及恢复。详见 [验证边界](docs/VALIDATION.md)。

## 使用

当前二进制版本需要 macOS 15+（由随包 Python 的构建目标决定），下载与 Mac 架构匹配的 ZIP 后解压。Apple Silicon 与 Intel 包均已通过 GitHub 托管构建和包内验证；实际运行仍以目标机器测试为准。

1. 用网线连接 Mac 网卡与 BMC 专用管理口，或接入隔离管理交换机。确认 BMC 已启用 DHCP。
2. 打开 **BMC DHCP.app**，通过 macOS 管理员授权。
3. 选择实际接线的网口，点击「启动服务」。
4. 租约出现后打开管理页。用完停止服务，或退出 App。

默认 Mac 地址为 `10.99.0.1/24`，地址池 `.100–.200`，租期 300 秒；如与现有网络冲突应先修改。工具不提供 NAT、互联网共享、DNS 转发、PXE 或 TFTP，不要在已有 DHCP 的办公网启动第二个 DHCP 服务。

当前应用使用本地 ad-hoc 签名，未做 Developer ID 签名和公证。跨机器首次运行可能需要在 macOS「隐私与安全性」允许打开；应用不会绕过系统检查。

## 源码使用

Python 3.11+，在仓库目录执行：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[raw]'
.venv/bin/bmcd ifaces
.venv/bin/bmcd selftest
```

实际发地址用 `./bmcd --iface en7`，将 `en7` 换成真实网口，启动器会请求 sudo。源码模式的提权进程应从 Documents/Desktop/Downloads 以外的目录运行；原生 App 会自动处理运行时副本。

[CLI 与静态 IP 探测说明](docs/CLI_REFERENCE.zh-CN.md) 包含更多参数。[Windows x64 便携版](WIN-README.md) 提供图形 EXE 与 CLI，自带 Python/Scapy；源码入口仍保留。Windows CI 验证打包和环回行为，真实 BMC、Npcap、防火墙与 UAC 交互仍待实机验证。

## 开发与开源

- [参与贡献](CONTRIBUTING.md)：开发环境、测试与提交要求。
- [发布指南](docs/RELEASING.md)：构建、许可证、对应源码、签名与校验。
- [更新记录](CHANGELOG.md) · [安全政策](SECURITY.md) · [社区规范](CODE_OF_CONDUCT.md)。

GitHub CI 覆盖静态检查、前端冒烟、wheel 安装及 Python 3.11、3.13、3.15 的 macOS 测试。手动发布工作流会先构建并验证 Apple Silicon、Intel 与 Windows x64 候选包，再由维护者审阅产物；工作流不会自动公开发布 Release。

## 许可证

项目采用 [GPL-2.0-only](LICENSE)。Scapy 同样采用 GPL-2.0-only；其他组件保留其原许可。Mac 分发包携带本项目及 Scapy 对应源码、许可证和依赖清单，见 [第三方声明](THIRD_PARTY_NOTICES.md)。

Repository: https://github.com/zyf18195378233/bmc-dhcp · Downloads: https://github.com/zyf18195378233/bmc-dhcp/releases
