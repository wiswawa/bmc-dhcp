# CLI 与静态 IP 探测

CLI 与原生 App 共用 Session 和 DHCP 状态机。以下网口名和地址均为示例，不会自动执行。

## 常用命令

```bash
./bmcd ifaces
./bmcd selftest
./bmcd --iface en7 --open
./bmcd --iface en7 --subnet 192.168.50.0/24 --pool .20-.60 --lease 600
./bmcd probe 10.99.0.100
./bmcd leases
```

`ifaces / leases / selftest / probe` 不需要修改网口。实际 DHCP、二层抓包和临时地址配置需要管理员权限；`bmcd` 启动器按命令请求 sudo。源码放在 macOS 受保护的 Documents/Desktop/Downloads 中时，提权后的访问可能受 TCC 限制；建议用普通开发目录，或使用原生 App。

| 参数 | 作用 |
| --- | --- |
| `--iface en7` | 明确选择连接 BMC 的网口 |
| `--subnet 10.99.0.0/24` | 临时子网 |
| `--pool .100-.200` | 地址池；也支持完整 IP 范围 |
| `--lease 300` | 租期秒数 |
| `--no-configure` | 保留已手工设置的网口地址 |
| `--no-restore` | 选择在停止后保留配置；仅在明确需要时使用 |
| `--no-router` | 不向 BMC 下发默认网关 |
| `--dns 192.168.50.1` | 明确需要时下发 DNS；默认不发 |
| `--engine raw` | 使用 Scapy/BPF 二层收发 |
| `--engine udp` | 标准库 UDP，兼容性受客户端广播行为限制 |
| `--duration 600` | 到时自动结束 |
| `--json-log run.jsonl` | 保存本地日志，分享前需脱敏 |

用 `./bmcd run --help` 查看完整参数。

## BMC 已有静态 IP

静态地址的 BMC 不会因为存在 DHCP 服务就改变地址。可以先用本地链路探测：

```bash
./bmcd scan --iface en7 --cidr 192.168.50.0/24 --cleanup
./bmcd scan --iface en7 --listen 20 --no-active
./bmcd scan --iface en7 --cidr 10.20.0.0/16 --cleanup
```

被动侦听从 ARP/mDNS/LLDP 等报文提取地址线索；IPv6 邻居和广播探测取决于对端是否回应；ARP 扫描只覆盖同一二层网络及用户指定的网段。工具不能保证发现所有静默的静态设备。必要时从服务器 BIOS、前面板或已知配置查询 BMC 地址。

大网段按批次扫描，单段最大 `/16`，总量有上限，可随时停止。扫描可能为发现的网段添加临时本机地址；GUI 退出会清理，CLI 使用 `--cleanup` 在结束时清理。

## 排障

- 租约为空：检查网口链路、管理口/共享口选择、BMC DHCP 开关与启动时间。
- UDP/67 已占用：查看诊断中的占用者，检查 macOS「互联网共享」和其他 DHCP 服务；不要直接强杀不明服务。
- 管理页打不开：确认租约、服务端口与 BMC 启动完成情况。自签证书的浏览器决定由用户处理。
- 恢复失败：保留 `~/.bmcd/iface-backup.json`，查看日志并重新停止或重开 App。不要把失败的恢复记录当作已恢复后删除。
- 厂商识别：页面标题/TLS 证书是较强证据，DHCP 主机名次之，单靠 MAC 前缀置信度较低。

本工具不登录 BMC、不重置凭据、不改变 BMC 固件配置。
