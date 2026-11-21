# BMC DHCP for Windows x64

临时为直连 BMC 分配 DHCP 地址。当前为 Beta，真实 BMC、Npcap、防火墙和 UAC 交互仍需实机验证。

## 下载安装包

[GitHub Releases](https://github.com/wiswawa/bmc-dhcp/releases)

下载 `BMC-DHCP-<version>-Windows-x64.zip`，完整解压后：

- 双击 **BMC DHCP.exe** 打开图形界面。
- 使用 **bmcd.exe** 运行命令行。
- 保留 `_internal` 和 `Resources`，不要只复制 EXE。

EXE 包内置 Python 和 Scapy，不依赖本机 Python。Npcap 没有随包分发；需要二层 raw 抓包、被动侦听或跨网段 ARP 时，从 [Npcap 官方网站](https://npcap.com/) 安装。未装时使用 UDP，服务约束到所选接口。

当前程序没有代码签名；Windows 的安全提示须由用户处理。

## 使用

1. Mac/PC 的网口直连 BMC 专用管理口，或使用隔离管理交换机。
2. 确认 BMC 已开启 DHCP，完整解压程序并双击图形入口。
3. 通过后台的 UAC 授权，选择接线的以太网卡，点击「启动服务」。
4. 租约出现后打开管理页；用完停止服务或从页面退出。

默认地址为 `10.99.0.1/24`、池 `.100–.200`、租期 300 秒。与现有网络重叠时先修改。不要在已有 DHCP 的共享办公网启动此服务。

## 命令行

```powershell
.\bmcd.exe --version
.\bmcd.exe ifaces
.\bmcd.exe selftest
.\bmcd.exe run --iface "Ethernet"
```

实际修改网口时需在管理员终端运行。源码 ZIP 的 `BMC DHCP.cmd` / `bmcd.cmd` 是备用入口，仅源码模式需要 Python 3.11+。

## 诊断与限制

- 数据和日志：`%LOCALAPPDATA%\bmcd`，主会话记录可能位于 `%USERPROFILE%\.bmcd`。
- 日志分享前移除访问令牌、主机名、真实 MAC 和个人路径。
- 网卡列表由 GetAdaptersAddresses、PowerShell、ipconfig 依次降级；可刷新或手填名称。
- UDP/67 占用、网口不通、静态 BMC 或固件未启动，都可能导致没有租约。
- 没有 Npcap 时，UDP 对不广播的初始 DHCP 客户端兼容性有限；静态地址发现也受系统能力限制。
- 恢复失败会保留记录；不要把软件自检通过理解为真实网口恢复或所有 BMC 型号已验证。

[验证记录](docs/VALIDATION.md) · [完整 CLI 参数](docs/CLI_REFERENCE.zh-CN.md) · [许可证](LICENSE)
