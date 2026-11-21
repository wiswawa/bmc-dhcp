"""网卡层：枚举接口、配置静态地址、运行后还原、查端口冲突。

macOS 走 `ifconfig` / `networksetup` / `route`；
Windows 走 `netsh` / PowerShell / SendARP（见 winnet.py）。
两边对外暴露同一套函数，上层（session/scan/cli/webapp）不用关心平台。
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import winnet  # noqa: E402  （平台判定在里面，非 Windows 不会碰 ctypes）

IS_WINDOWS = winnet.IS_WIN

IFCONFIG = "/sbin/ifconfig"
NETWORKSETUP = "/usr/sbin/networksetup"
ROUTE = "/sbin/route"
NETSTAT = "/usr/sbin/netstat"


def mask_to_dotted(mask: str) -> str:
    """ifconfig 在 macOS 上给的是 0xffffff00，统一转成点分十进制。"""
    if not mask:
        return "255.255.255.0"
    if mask.lower().startswith("0x"):
        try:
            return str(ipaddress.IPv4Address(int(mask, 16)))
        except ValueError:
            return "255.255.255.0"
    return mask


def run(cmd: List[str], check: bool = False) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)
    if check and proc.returncode != 0:
        raise RuntimeError("%s 失败: %s" % (" ".join(cmd), proc.stderr.strip()))
    return proc.returncode, proc.stdout, proc.stderr


@dataclass
class Interface:
    name: str
    mac: str = ""
    ipv4: str = ""
    netmask: str = ""
    flags: str = ""
    up: bool = False
    running: bool = False
    link: str = ""            # "active" / "inactive" / ""
    media: str = ""
    service: str = ""         # networksetup 里的服务名
    ipv6_linklocal: str = ""
    is_default_route: bool = False
    loopback: bool = False       # 环回口（Windows 上是 "Loopback Pseudo-Interface 1"）
    virtual: bool = False        # Hyper-V / VMware / VPN 之类的虚拟口，不当物理网卡用
    device: str = ""             # scapy/Npcap 用的设备名，Windows 上不同于显示名
    # 下面这些是 Windows 侧新增的「已判定」字段：判定一次就存下来，
    # 避免 is_wifi 这类 property 在渲染时又去枚举一遍网卡（那是 20 秒卡顿的来源）。
    wifi: bool = False
    wifi_known: bool = False
    tunnel: bool = False         # isatap/teredo/隧道口：不参与候选排序
    source: str = ""             # ctypes / powershell / ipconfig
    friendly: str = ""           # ipconfig 区块标题里剥出来的真实接口名
    if_index: int = 0             # Windows UDP 收发接口约束使用的系统索引

    @property
    def has_link(self) -> bool:
        if self.link:
            return self.link == "active"
        # 老系统没有 status 行，退回 media 判断
        return bool(self.running and self.media and "none" not in self.media)

    @property
    def is_wifi(self) -> bool:
        """是不是无线口。

        `wifi_known=True` 表示调用方（Windows 的 `_windows_interfaces`）已经
        判定过并存好了结论 —— 这时**不再**回落到 `wifi_devices()`：
        那个函数会去枚举网卡，而 `/api/ifaces` 里每张卡都要问一次 is_wifi，
        等于把一次请求放大成十几次 PowerShell 启动（1.6.0 首屏空白的主因之一）。
        """
        if self.wifi:
            return True
        if self.wifi_known:
            return False
        service = (self.service or "").lower()
        if "wi-fi" in service or "airport" in service or "wireless" in service:
            return True
        if "wlan" in (self.name or "").lower():
            return True
        return self.name in wifi_devices()

    @property
    def prefixlen(self) -> int:
        if not self.netmask:
            return 24
        try:
            return ipaddress.IPv4Network("0.0.0.0/%s" % mask_to_dotted(self.netmask)).prefixlen
        except ValueError:
            return 24

    @property
    def is_link_local(self) -> bool:
        return self.ipv4.startswith("169.254.")

    def label(self) -> str:
        bits = [self.name]
        if self.service:
            bits.append(self.service)
        addr = self.ipv4 or "无 IPv4"
        bits.append(addr)
        if not self.has_link:
            bits.append("无链路")
        return " | ".join(bits)


# mac 上的「假网口」：隧道/点对点/无线 P2P/虚拟机网口。
# 不标出来它们在界面里就是一堆「无链路的 en4/en5/vmenet0」，用户根本不知道选哪个。
_VIRTUAL_MAC_PREFIXES = (
    "utun", "ipsec", "ppp", "tap", "tun", "gif", "stf", "awdl", "llw",
    "anpi", "ap", "bridge", "vmenet", "vmnet", "feth", "pktap", "vlan",
)


def _mac_is_virtual(name: str, media: str) -> bool:
    """mac 上这个接口是不是「虚拟/不独立」的。"""
    low = (name or "").lower()
    if any(low.startswith(p) for p in _VIRTUAL_MAC_PREFIXES):
        return True
    # 注意：**不要**因为「是 bridge 成员」就判虚拟 —— 开了「互联网共享」时
    # 真正的 en0（Wi-Fi）自己也是桥成员，那样会把唯一能用的网口藏起来。
    # 桥成员身份只用来给下拉框加标签（service 里已经写了「（桥成员）」）。
    text = (media or "").lower()
    return any(hint in text for hint in ("vmware", "virtual", "vmenet", "vmnet"))


_VIRTUAL_HINTS = (
    "hyper-v", "virtual", "vmware", "virtualbox", "tap-", "tap adapter",
    "loopback", "bluetooth", "蓝牙", "wsl", "vethernet", "npcap loopback",
)


def _windows_interfaces() -> List[Interface]:
    ifaces: List[Interface] = []
    for rec in winnet.adapter_records():
        name = rec.best_name                 # ipconfig 来源时是剥掉区块标题的名字
        desc = rec.desc or ""
        low = (desc + " " + name).lower()
        # 链路：只有「媒体状态 / 状态词 / 有地址」三者全都没有时，才不敢说它通着。
        # （ipconfig 兜底没有媒体状态，以前会把断开的口和 isatap 隧道全判成 up）
        up = bool(rec.is_up and rec.link_known)
        wifi = (rec.if_type == winnet.IF_TYPE_IEEE80211
                or any(hint in desc.lower()
                       for hint in ("wi-fi", "wifi", "wireless", "802.11"))
                or "wlan" in name.lower())
        ifaces.append(Interface(
            name=name,
            mac=rec.mac,
            ipv4=rec.ip,
            netmask=rec.mask,
            flags="UP" if up else "",
            up=up,
            running=up,
            link="active" if up else "inactive",
            media=desc,
            service=name,                     # netsh 用的就是这个名字
            is_default_route=False,
            loopback=rec.is_loopback,
            virtual=any(hint in low for hint in _VIRTUAL_HINTS),
            device=name,
            wifi=wifi,
            wifi_known=True,
            tunnel=rec.tunnel,
            source=rec.source,
            friendly=rec.friendly,
            if_index=rec.index,
        ))
    return ifaces


def list_interfaces() -> List[Interface]:
    if IS_WINDOWS:
        return _windows_interfaces()
    _, out, _ = run([IFCONFIG, "-a"])
    ifaces: List[Interface] = []
    cur: Optional[Interface] = None
    for line in out.splitlines():
        if line and not line[0].isspace():
            m = re.match(r"^([a-z0-9]+):", line)
            if not m:
                cur = None
                continue
            name = m.group(1)
            cur = Interface(name=name, flags=line, up="UP" in line,
                            loopback=name.startswith("lo"))
            for flag in ("RUNNING", "BROADCAST", "MULTICAST"):
                if flag in line:
                    cur.running = cur.running or flag == "RUNNING"
            ifaces.append(cur)
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("ether "):
            cur.mac = s.split()[1].lower()
        elif s.startswith("inet "):
            parts = s.split()
            cur.ipv4 = parts[1]
            for i, p in enumerate(parts):
                if p == "netmask" and i + 1 < len(parts):
                    cur.netmask = mask_to_dotted(parts[i + 1])
        elif s.startswith("status:"):
            cur.link = s.split(":", 1)[1].strip()
        elif s.startswith("media:"):
            cur.media = s.split(":", 1)[1].strip()
        elif s.startswith("inet6 fe80"):
            cur.ipv6_linklocal = s.split()[1].split("%")[0]
    for item in ifaces:
        item.virtual = _mac_is_virtual(item.name, item.media)
    return ifaces


_WIFI_CACHE: Dict[str, object] = {}


def wifi_devices() -> set:
    """从 networksetup 的硬件端口表里认出 Wi-Fi 设备名（不同 Mac 不一样）。"""
    if IS_WINDOWS:
        names = set()
        for rec in winnet.adapter_records():
            low = (rec.desc or "").lower()
            if (rec.if_type == winnet.IF_TYPE_IEEE80211
                    or any(hint in low for hint in ("wi-fi", "wifi", "wireless", "802.11"))):
                names.add(rec.best_name)
        return names
    cached = _WIFI_CACHE.get("devices")
    if isinstance(cached, set):
        return cached
    _, out, _ = run([NETWORKSETUP, "-listallhardwareports"])
    devices = set()
    is_wifi = False
    for line in out.splitlines():
        low = line.strip().lower()
        if low.startswith("hardware port:"):
            is_wifi = ("wi-fi" in low) or ("airport" in low)
        elif low.startswith("device:") and is_wifi:
            devices.add(line.split(":", 1)[1].strip())
    _WIFI_CACHE["devices"] = devices
    return devices


def service_map() -> Dict[str, str]:
    """设备名 -> 网络服务名，例如 en7 -> 'AX88179A'。"""
    if IS_WINDOWS:
        return {rec.name: rec.name for rec in winnet.adapter_records()}
    _, out, _ = run([NETWORKSETUP, "-listnetworkserviceorder"])
    mapping: Dict[str, str] = {}
    pending: Optional[str] = None
    for line in out.splitlines():
        m = re.match(r"^\(\d+\)\s+(.*)$", line.strip())
        if m:
            pending = m.group(1).strip().rstrip("*").strip()
            continue
        m = re.search(r"Device:\s*([a-z0-9]+)", line)
        if m and pending:
            mapping[m.group(1)] = pending
            pending = None
    return mapping


def bridge_members() -> set:
    """bridge0 的成员口（Thunderbolt Bridge 之类），不该被当成独立网卡。"""
    if IS_WINDOWS:
        return set()
    _, out, _ = run([IFCONFIG, "-a"])
    members = set()
    for line in out.splitlines():
        m = re.search(r"member:\s+([a-z0-9]+)\s", line)
        if m:
            members.add(m.group(1))
    return members


def default_route_iface() -> str:
    if IS_WINDOWS:
        return winnet.default_route_iface()
    _, out, _ = run([ROUTE, "-n", "get", "default"])
    m = re.search(r"interface:\s*(\S+)", out)
    return m.group(1) if m else ""


def enumerate_all() -> List[Interface]:
    if IS_WINDOWS:
        ifaces = _windows_interfaces()
        default = winnet.default_route_iface()
        for iface in ifaces:
            iface.is_default_route = bool(default) and iface.name == default
        return ifaces
    ifaces = list_interfaces()
    services = service_map()
    default_if = default_route_iface()
    members = bridge_members()
    for iface in ifaces:
        iface.service = services.get(iface.name, "")
        iface.is_default_route = iface.name == default_if
        if iface.name in members:
            iface.link = iface.link or "inactive"
            iface.service = iface.service or "（桥成员）"
    return ifaces


def ethernet_candidates(ifaces: Optional[List[Interface]] = None) -> List[Interface]:
    """可能插着 BMC 网线的口，按可能性排序。

    `ifaces` 可以传进来复用（`/api/ifaces` 会传，避免一次请求枚举两遍 ——
    1.6.0 的「首屏空白 20 秒」有一半来自这里）。
    隧道口（isatap/teredo）和 Wi-Fi、虚拟口一律不进候选。
    """
    skip_prefix = ("lo", "gif", "stf", "utun", "awdl", "llw", "ap1", "anpi", "bridge")
    members = bridge_members()
    items = list(ifaces) if ifaces is not None else enumerate_all()
    scored: List[Tuple[int, Interface]] = []
    for iface in items:
        if iface.loopback or iface.virtual or iface.tunnel:
            continue
        # BSD 设备名前缀只在 mac 上有意义；Windows 的显示名（"以太网 2"、
        # "本地连接"）不该因为前缀规则被误杀
        if not IS_WINDOWS and iface.name.startswith(skip_prefix):
            continue
        if iface.name in members:
            continue
        if iface.is_wifi:
            continue
        if not iface.has_link:
            continue
        score = 0
        if iface.is_default_route:
            score -= 50
        if iface.ipv4 and not iface.is_link_local:
            score += 5
        if iface.is_link_local or not iface.ipv4:
            score += 10          # 刚插上的 BMC 口通常没地址 / 只有 169.254
        # Windows 上 service 就是网卡显示名（"以太网 2"），看不出是 USB 网卡
        # 还是板载，所以把设备描述（media）也拿来当提示
        service = (iface.service or "").lower()
        desc = (iface.media or "").lower()
        hint_text = service + " " + desc
        if "usb" in service:
            score += 8
        # AX88179 / RTL8153 / USB-C 扩展坞之类，名字里不一定有 usb
        for hint in ("ax88", "rtl81", "lan", "ethernet", "usb-c", "dock", "usb"):
            if hint in hint_text:
                score += 6
                break
        if "thunderbolt" in iface.service.lower():
            score += 4
        scored.append((score, iface))
    scored.sort(key=lambda x: (-x[0], x[1].name))
    return [i for _, i in scored]


def service_device(name: str) -> str:
    """服务名 -> 设备名（比如 AX88179A -> en7），设备没插也照样能查到。"""
    target = (name or "").strip().lower()
    if not target:
        return ""
    if IS_WINDOWS:
        return name if winnet.find_record(name) else ""
    for device, service in service_map().items():
        low = (service or "").lower()
        if low and (low == target or target in low):
            return device
    return ""


def find_by_service(name: str) -> Optional[Interface]:
    """按「网络服务名」找网卡，比如 AX88179A。

    扩展坞/网卡重插后 BSD 名字（en7/en9）会变，但服务名通常不变，
    所以记住服务名比记住 en 号靠谱。
    """
    target = (name or "").strip().lower()
    if not target:
        return None
    for iface in enumerate_all():
        service = (iface.service or "").lower()
        if service and (service == target or target in service):
            return iface
    return None


def find_by_name(name: str) -> Optional[Interface]:
    for iface in enumerate_all():
        if iface.name == name:
            return iface
    return None


# ----------------------------------------------------------------------
# 地址配置 / 还原
# ----------------------------------------------------------------------

@dataclass
class SavedConfig:
    iface: str
    mode: str = "unknown"       # dhcp / manual / none / unknown
    ip: str = ""
    mask: str = ""
    router: str = ""
    service: str = ""


def describe_config(service: str) -> SavedConfig:
    cfg = SavedConfig(iface="", service=service)
    if not service:
        return cfg
    if IS_WINDOWS:
        info = winnet.describe_config(service)
        cfg.mode = str(info.get("mode") or "none")
        cfg.ip = str(info.get("ip") or "")
        cfg.mask = str(info.get("mask") or "")
        cfg.router = str(info.get("router") or "")
        return cfg
    _, out, _ = run([NETWORKSETUP, "-getinfo", service])
    if "DHCP Configuration" in out:
        cfg.mode = "dhcp"
    elif "Manual Configuration" in out:
        cfg.mode = "manual"
    elif "service is not" in out or "not connected" in out:
        cfg.mode = "none"
    m = re.search(r"IP address:\s*(\S+)", out)
    if m:
        cfg.ip = m.group(1)
    m = re.search(r"Subnet mask:\s*(\S+)", out)
    if m:
        cfg.mask = m.group(1)
    m = re.search(r"Router:\s*(\S+)", out)
    if m:
        cfg.router = "" if m.group(1) == "(null)" else m.group(1)
    return cfg


def set_static(iface: Interface, ip: str, mask: str = "255.255.255.0") -> bool:
    """把网卡设成静态地址（同时会停掉系统的 DHCP 客户端）。"""
    if IS_WINDOWS:
        name = iface.service or iface.name
        return winnet.set_static(name, ip, mask_to_dotted(mask))
    if iface.service:
        # -setmanual 要求 router 参数；0.0.0.0 表示这个直连口没有默认网关。
        rc, _, err = run([NETWORKSETUP, "-setmanual", iface.service, ip, mask, "0.0.0.0"])
        if rc == 0:
            return True
        err = err.strip()
        if err:
            print("networksetup 配置失败: %s" % err)
        return False  # 服务存在却设置失败时，不用 ifconfig 掩盖失败并留下 DHCP 客户端
    # 退化方案：直接 ifconfig（对没有「网络服务」的 BSD 接口）
    rc, _, _ = run([IFCONFIG, iface.name, "inet", ip, mask, "up"])
    return rc == 0


def set_dhcp(iface: Interface) -> bool:
    if IS_WINDOWS:
        name = iface.service or iface.name
        return bool(name) and winnet.set_dhcp(name)
    if not iface.service:
        return False
    rc, _, _ = run([NETWORKSETUP, "-setdhcp", iface.service])
    return rc == 0


def restore_config(saved: SavedConfig) -> bool:
    if not saved.service or saved.mode in ("unknown", "none"):
        return False
    if IS_WINDOWS:
        if saved.mode == "dhcp":
            return winnet.set_dhcp(saved.service)
        if saved.mode == "manual" and saved.ip:
            return winnet.set_static(saved.service, saved.ip,
                                     saved.mask or "255.255.255.0", saved.router)
        # 原来就没有地址：让它自己去 DHCP，比留着一个 BMC 网段地址干净
        return winnet.set_dhcp(saved.service)
    if saved.mode == "dhcp":
        rc, _, _ = run([NETWORKSETUP, "-setdhcp", saved.service])
        return rc == 0
    if saved.mode == "manual" and saved.ip:
        args = [NETWORKSETUP, "-setmanual", saved.service, saved.ip,
                saved.mask or "255.255.255.0", saved.router or "0.0.0.0"]
        rc, _, _ = run(args)
        return rc == 0
    return False


# ----------------------------------------------------------------------
# 环境检查
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# 临时地址别名（扫到别的网段的机器以后，要靠它才连得上去）
# ----------------------------------------------------------------------

def addresses(name: str) -> List[str]:
    """网卡上所有 IPv4 地址（含 alias 加的那些）。"""
    if not name:
        return []
    if IS_WINDOWS:
        return winnet.addresses(name)
    rc, out, _ = run([IFCONFIG, name])
    if rc != 0:
        return []
    found: List[str] = []
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("inet "):
            parts = s.split()
            if len(parts) >= 2:
                found.append(parts[1])
    return found


def add_alias(name: str, ip: str, mask: str = "255.255.255.0") -> bool:
    """临时给网卡加一个同网段地址，这样扫到的机器 TCP 才连得上去。

    只改内核态地址，不动 networksetup 里的配置：拔网线/重启就没了，
    也可以用 remove_alias 立刻摘掉。

    ifconfig 的 `alias` 参数位置在不同 macOS 版本上略有出入，所以三种写法
    依次试；**最后一定要回读地址表确认真的加上了**，不能只信返回码。
    """
    if not name or not ip:
        return False
    if IS_WINDOWS:
        return winnet.add_alias(name, ip, mask_to_dotted(mask))
    mask = mask_to_dotted(mask)
    attempts = (
        [IFCONFIG, name, "inet", ip, "netmask", mask, "alias"],
        [IFCONFIG, name, "alias", ip, "netmask", mask],
        [IFCONFIG, name, "alias", ip, mask],
    )
    for args in attempts:
        rc, _, _ = run(args)
        if rc == 0 and ip in addresses(name):
            return True
    return False


def remove_alias(name: str, ip: str) -> bool:
    if not name or not ip:
        return False
    if IS_WINDOWS:
        return winnet.remove_alias(name, ip)
    rc, _, _ = run([IFCONFIG, name, "-alias", ip])
    if rc != 0:
        return False
    return ip not in addresses(name)


def dhcp_port_owner(exclude_pid: int = 0) -> List[str]:
    """谁占着 UDP 67（Windows 上是别的 DHCP 服务/虚拟机网络）。

    exclude_pid 用来把自己排掉：引擎跑起来以后，占着 67 的就是我们自己。
    """
    if IS_WINDOWS:
        owners: List[str] = []
        for pid in winnet.udp_port_owners(67):
            if exclude_pid and pid == exclude_pid:
                continue
            name = winnet.process_name(pid) or "未知进程"
            owners.append("%s(pid %d)" % (name, pid))
        return owners
    owners: List[str] = []
    # lsof 能报出进程名和 PID，比 netstat 有用
    rc, out, _ = run(["/usr/sbin/lsof", "-nP", "-iUDP:67"])
    if rc == 0:
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    pid = int(parts[1])
                except ValueError:
                    pid = 0
                if exclude_pid and pid == exclude_pid:
                    continue
                owners.append("%s(pid %s)" % (parts[0], parts[1]))
    if owners:
        return sorted(set(owners))

    _, out, _ = run([NETSTAT, "-an", "-p", "udp"])
    busy = [l for l in out.splitlines() if re.search(r"\.67\s*$", l.rstrip())]
    if busy:
        rc, pids, _ = run(["/bin/sh", "-c", "pgrep -fl 'bootpd|dnsmasq|dhcpd' || true"])
        if rc == 0 and pids.strip():
            owners.extend([x.strip() for x in pids.strip().splitlines()])
        else:
            owners.append("UDP/67 已被占用")
    return owners


def is_root() -> bool:
    """管理员权限：mac 看 uid，Windows 看 UAC 令牌。"""
    if IS_WINDOWS:
        return winnet.is_admin()
    import os
    return os.geteuid() == 0


def scapy_iface(name: str) -> str:
    """把网卡显示名换成 scapy/Npcap 认的设备名（mac 上原样返回）。"""
    if not name:
        return name
    if IS_WINDOWS:
        return winnet.scapy_iface(name)
    return name


def broadcast_of(ip: str, mask: str = "255.255.255.0") -> str:
    try:
        net = ipaddress.IPv4Network("%s/%s" % (ip, mask_to_dotted(mask)), strict=False)
    except ValueError:
        return "255.255.255.255"
    return str(net.broadcast_address)


def subnet_of(ip: str, mask: str = "255.255.255.0") -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network("%s/%s" % (ip, mask_to_dotted(mask)), strict=False)
