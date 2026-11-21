# Windows x64 便携版

自带 Python 与 Scapy 的候选包由 Windows runner 构建：`BMC-DHCP-1.9.0-Windows-x64.zip`。
完整解压后双击 **BMC DHCP.exe**；命令行使用 **bmcd.exe**。无需另装 Python，不要只拷贝 EXE，需保留 `_internal` 与 `Resources`。后台通过 UAC 请求管理员授权。

Npcap 没有随包分发：使用二层 raw 抓包与跨网段发现时需自行从官方安装。未装 Npcap 时可用 UDP；UDP 使用 Winsock 接口列表与出接口选项限定所选网卡。应用暂未做代码签名，Windows 的安全提示由用户决定。

本包仍为 Beta。Windows runner 的可执行文件/环回/API 检查与真实 BMC、网口改配/UAC 交互分别记录；不能用前者冒充实机通过。源码 ZIP 保留 `BMC DHCP.cmd` / `bmcd.cmd` 入口，源码模式才需要本机 Python。

[GitHub 仓库](https://github.com/zyf18195378233/bmc-dhcp) · [发布下载](https://github.com/zyf18195378233/bmc-dhcp/releases)

---

> Experimental Windows source tooling: simulated tests only; no native Windows/BMC hardware validation. The primary supported target is macOS. See [the project README](README.md).

# bmcd for Windows — 给新机器的 BMC 发临时 DHCP 地址

跟 mac 版是同一套后端（`src/bmcdhcp/`），Windows 上多了一个平台层 `winnet.py`：
`ifconfig/networksetup` 换成 `netsh`，`/dev/bpf` 换成 Npcap，`sudo` 换成 UAC。
界面、CLI、API、IP 探测，用的都是同一份代码。

```
   Windows PC                                    新机器
 ┌────────────────────┐      网线（USB 网卡）   ┌──────────────────────┐
 │ bmcd 10.99.0.1     │ ─────────────────────► │ BMC 口（专用管理口）  │
 │ 发 OFFER/ACK       │ ◄───────────────────── │ DISCOVER / REQUEST   │
 └────────────────────┘                        └──────────────────────┘
```

---

## 一、准备（只做一次）

1. **Python 3.11+**：<https://www.python.org/downloads/windows/> 下载安装，
   安装第一屏**务必勾上 `Add python.exe to PATH`**。
2. **（可选）Npcap**：<https://npcap.com/#download>，安装时勾 **WinPcap API-compatible Mode**。
   - 装了：能用 `raw` 引擎（最可靠）、能**被动侦听**（听 BMC 自己喊的 ARP/mDNS/LLDP）、能扫**跨网段**的 ARP。
   - 不装：照样发 DHCP（用 `udp` 引擎）、照样能扫**本网段**（用系统自带 SendARP）、照样能加临时地址。

## 一点安全保障（两个平台一样）

改网卡之前，原配置（DHCP / 手工 IP / 掩码 / 网关）会先落到
`%LOCALAPPDATA%\bmcd\iface-backup.json`（mac 上是 `~/.bmcd/iface-backup.json`），
正常停止并还原成功后删掉。所以哪怕后端被强杀、UAC 窗口被关掉、机器直接断电，
下次启动都会读这份备份：

* 那块网卡上**还是我们设的地址** → 自动改回原来的 DHCP/静态配置，日志里告诉你；
* 地址已经被别人/你自己改过 → 不动它，只清掉过期备份。

## 二、跑起来

### 图形界面（推荐）

双击 **`BMC DHCP.cmd`** →

1. 第一次会花几十秒建运行环境（`%LOCALAPPDATA%\bmcd\venv`，装 scapy）；
2. 弹一次 **UAC**，点「是」（后端要改网卡地址、抓 DHCP 包，必须管理员）；
3. 自动开一个 Edge/Chrome 的独立窗口（没有地址栏，就是一个 App 窗口）。

窗口里左边选网卡（插着 BMC 网线的那个）、点「启动」；右上「租约」看谁要到了地址，
「IP 探测」找那些**已经配好静态 IP、不会来要 DHCP** 的机器。

> 想改配置/重开：关掉浏览器窗口之后，如果服务还在跑，界面 2 分钟没心跳会自动停止并还原网卡；
> 也可以点右上角「退出」立即停。

### 命令行

```bat
bmcd.cmd                        :: 自动挑网卡、自动 UAC、发 DHCP
bmcd.cmd ifaces                 :: 看网卡（含没有地址的）
bmcd.cmd probe 192.168.0.120    :: 已知 IP，只想识别它是什么机器
bmcd.cmd scan                   :: 找已经配好静态 IP 的机器（侦听 + 扫网段 + 识别）
bmcd.cmd scan --listen 0 --cidr 192.168.0.0/24   :: 只扫网段
bmcd.cmd selftest               :: 不需要管理员的自检
bmcd.cmd simulate               :: 假 BMC：真发 DHCP 报文，跑完整链路
bmcd.cmd leases                 :: 看上次保存的租约
bmcd.cmd leases --state "%LOCALAPPDATA%\bmcd\state.json"
bmcd.cmd repair                 :: 重新建运行环境（%LOCALAPPDATA%\bmcd\venv）
bmcd.cmd verify                 :: 只查程序文件全不全（不需要 Python、不要管理员）
```

`run / scan / find-static / simulate` 会自动请求管理员权限（用 PowerShell 的
`Start-Process -Verb RunAs` 拉起一个新的管理员窗口，等价于 mac 的 `sudo`）。
不想弹 UAC 就跑 `set BMCD_NO_ADMIN=1`（只有 `ifaces/selftest/leases` 有意义）。

## 三、验证（不用 BMC 也能验）

```bat
bmcd.cmd selftest
```
编解码 → DORA 状态机 → 本机 UDP 往返 → Session 生命周期，全 PASS 说明软件本身没问题。

```bat
bmcd.cmd simulate
```
它自己起服务、用假 MAC 发 DISCOVER/REQUEST、核对租约；有真网卡时还会把地址挂上网卡、
起一个自签证书的 HTTPS「iDRAC 管理页」，验证厂商识别和「打开管理页」。

```bat
bmcd.cmd scan --listen 0 --cidr 192.168.x.0/24 --cleanup
```
把网段换成你家/机房的：应该能列出路由器、手机、电视之类的 IP + MAC + 厂商。
**能列出来就说明 ARP 扫描、识别、临时地址这三段都是通的**，换成 BMC 只是多个 623 端口和 iDRAC/iLO 标题。

## 四、Windows 上要注意的几件事

| 现象 | 原因 / 处理 |
|---|---|
| 起来就报「UDP/67 已被占用」 | Hyper-V / VMware / Docker / 另一个 DHCP 服务占着 67。`bmcd.cmd ifaces` 之后看 `leases` 页的「诊断」，它会列出占用进程名和 PID |
| 提示「Npcap 抓包 不可用」 | 没装 Npcap（或没勾 WinPcap 兼容模式）。DHCP 用 `udp` 引擎照样工作，只是不能被动侦听 |
| 「IP 探测」只扫到本网段 | 没有 Npcap 时，跨网段的 ARP 扫不了（`SendARP` 的系统限制）；装了 Npcap 就能跨网段。另外地址可能是**任何值**（上一家单位留下的），把网段改成 `192.168.0.0/16`，或者断电重启 BMC 让它自己喊（`-l 30 --no-active`） |
| 「IP 探测」找不到，但机器明明开着 | 依次试：① 勾「先试常见出厂地址」；② 勾「IPv6/广播探测」（跟 IPv4 配成什么无关）；③ 断电重启 BMC + 只侦听 30 秒；④ 换成 `192.168.0.0/16` / `10.0.0.0/16` 扫 |
| 加了临时地址之后连不上管理页 | Windows 防火墙/杀软拦截出站 443 到新网段；或者对端 BMC 只允许特定源地址 |
| 界面提示「当前不是管理员权限」 | 关掉窗口，右键 `bmcd.cmd` →「以管理员身份运行」 |
| 中文网卡名（「以太网 2」） | 全流程都支持，netsh 和 PowerShell 都是按名字走的，不用改成英文 |
| 打开界面是一页**白屏 + 一行 JSON**（`"error": "服务端异常: [Errno 2] … ui\\index.html"`） | 包里少文件（`ui\index.html` 没解压出来，多半是只复制了一部分）。跑 `bmcd.cmd verify` 会列出缺哪些；把 zip **重新完整解压**到空目录（如 `C:\bmcd`）。1.5.1 起启动前就会查包，缺文件直接告诉你，不会再白屏 |
| 弹框说**「后端启动超时」**，但 `backend.log` 里已经有 `BMCD_LISTEN http://127.0.0.1:…` | 后端其实起来了，是「把地址交给启动器」这一步没成功（会话文件写在 `%USERPROFILE%\.bmcd\web.json`）。1.5.3 起：主路径写不进去会自动写 `%LOCALAPPDATA%\bmcd\web.json`，启动器两个位置都读，实在读不到还会直接解析 `backend.log` 里的 `BMCD_LISTEN`，所以窗口照样会开；`backend.log` 里以 `BMCD_SESSION` / `BMCD_SESSION_ERR` 开头的行会说明到底写没写成 |
| 双击只弹一个 **`Python venv launcher … failed to locate pyvenv.cfg`** 的框，然后就没了 | `%LOCALAPPDATA%\bmcd\venv` 是个坏掉的运行环境（上次装到一半被关掉／被杀软清过／从别的机器拷过来的）。1.4.2 起双击会**自动发现并重建**它；也可以手动 `bmcd.cmd repair` |
| **网卡下拉框是空的** | 1.7.0 起不会了。枚举改成 **ctypes(GetAdaptersAddresses) → PowerShell → ipconfig** 三级降级：第一级在进程内直接向 Windows 要网卡，**完全不依赖 PowerShell**（Store 版 Python、被策略拦住的 PowerShell、杀软都可能让旧的两级源同时失效）。真读不到时，下拉框里会写出**每一级的原因**（`ctypes：…；powershell：…；ipconfig：…`），不会再是一排空白。逐步排查见下面「网卡选择：下拉为空 / 没有我要的口」 |
| 双击后没反应 | 看 `%LOCALAPPDATA%\bmcd\launcher.log` 和 `backend.log`，里面是最新的失败原因（启动器崩了会把 traceback 弹出来） |

### 网卡选择：下拉为空 / 没有我要的口

枚举是**三级降级**，任一级拿到网卡就停（`/api/ifaces` 返回的 `source` 就是真正生效的那一级）：

1. **`ctypes`** → `iphlpapi!GetAdaptersAddresses`，进程内调用，**0 个子进程、不需要 PowerShell**；
2. **`powershell`** → `Get-NetAdapter`（第一级失败或跳过时才用，一次请求最多 spawn 1 次 `powershell.exe`）；
3. **`ipconfig /all`** 解析（最后手段；名字可能只剩本地化区块标题，启动时按名字找可能对不上）。

按这个顺序排查，从便宜到贵：

1. **先看 error 文案**：下拉框为空时，下面会直接写系统给的原因，例如
   `ctypes：加载 iphlpapi.dll 失败；powershell：…；ipconfig：…`。这一行就是「为什么空」。
2. **点「刷新」重枚举**（带 `?refresh=1` 绕过 5 秒缓存）。列表里**有**条目、只是要的口排在后面，就勾
   「**显示所有网卡**」——虚拟网卡 / Wi-Fi 现在不隐藏，只排后并标「虚拟」「Wi-Fi」。
3. **手填网卡名**：列表为空或勾了「显示所有网卡」时会出现「**手动填网卡名**」输入框，填 `以太网 2`
   这种名字即可（填服务名也行，后端会按「设备名 → 服务名」反查）。
4. **命令行体检**：`bmcd.cmd ifaces --json`（不要管理员）逐源打印 `{source, ok, count, ms, error, skipped}`；
   `bmcd.cmd selftest` 里也有一项「网卡枚举」。两个命令都走 **`:sysdiag`** 分支：先试 venv 里的 Python，
   不行依次退 `py -3`、`python`，所以 **venv 坏了也能跑诊断**。
5. **包完整性 / 运行环境**：`bmcd.cmd verify`（不要 Python、不要管理员）查文件缺不缺；缺了就重新完整解压 zip。
   环境问题用 `bmcd.cmd repair` 重建 `%LOCALAPPDATA%\bmcd\venv`。
6. **换 python.org 版 Python 重建 venv**：三级都卡在 `ctypes：加载 iphlpapi.dll 失败`、或 Python 本身起不来
   （Microsoft Store 版常见：`python -m venv` 建不出可用环境、`pythonw` 下 `WinError 6`）时，卸掉 Store 版，
   装 **python.org 官方安装包**（勾 *Add python.exe to PATH*），再 `bmcd.cmd repair`。

> 界面请求层面也做了兜底：`GET` 8 秒 / `POST` 30 秒超时（`AbortController`），失败自动重试一次并带
> `?refresh=1`；0 网卡时下拉框必有占位项且露出「手动填网卡名」，不会给一个无提示的空框。

## 五、这个包里有什么

```
bmcd-win/
├── BMC DHCP.cmd          ← 双击这个（图形界面）
├── bmcd.cmd              ← 命令行入口
├── app_win.py            ← 界面启动器：UAC 提权 + 开 Edge/Chrome App 窗口
├── WIN-README.md         ← 本文件
├── README.md             ← 完整功能说明（原理、参数、各厂商的坑）
├── src/bmcdhcp/          ← 后端（和 mac 版共用）
│   ├── winnet.py         ← Windows 平台层（netsh / PowerShell / SendARP / Npcap）
│   ├── iface.py          ← 网卡抽象（平台分支在这里）
│   ├── dhcp.py core.py leases.py session.py engines.py scan.py discover.py webapp.py
│   └── ui/index.html     ← 单页界面
├── tests/                ← 跨平台与模拟单测（不需要 Windows，也不需要管理员）
└── tools/                ← 图标/打包脚本
```

自检命令（在这个目录下、装了 Python 的任意机器上都能跑）：

```bat
set PYTHONPATH=src
python -m unittest discover -s tests
```

## 六、和 mac 版的差异（说清楚，别踩坑）

| 能力 | macOS | Windows |
|---|---|---|
| DHCP 发包 | `raw`（BPF）首选，`udp` 兜底 | 装了 Npcap 才用 `raw`；否则 `udp` |
| 改网卡地址 | `networksetup` | `netsh interface ipv4 set address` |
| 临时地址（IP 探测用） | `ifconfig alias` | `netsh interface ipv4 add address` |
| 被动侦听 ARP/mDNS/LLDP | 只要 root | 要 Npcap |
| 扫跨网段 ARP | scapy `srp` | 有 Npcap 时同左；没有就只能扫本网段（SendARP） |
| 提权 | `sudo` / osascript 授权框 | UAC（`ShellExecuteW(runas)`） |
| 界面窗口 | 原生 AppKit / WKWebView | Edge/Chrome `--app`，兜底默认浏览器 |

权限模型完全一样：**界面进程是普通用户，后端是管理员**，两边靠
`%USERPROFILE%\.bmcd\web.json` 里的一次性令牌接头，令牌不进命令行。
