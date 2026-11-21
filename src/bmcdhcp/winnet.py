"""Windows 网络层：把 mac 版 `iface.py` 里那些 `ifconfig/networksetup/route` 换成
`netsh` / PowerShell / SendARP，并保持同一套返回语义。

设计原则（因为这份代码是在 mac 上写的、只能在 Windows 上验）：

* **只用系统自带的东西**：netsh、PowerShell 5.1（Win10/11 自带）、iphlpapi。
  不装 Npcap 也能跑 DHCP、能扫本网段、能加临时地址。
* **不解析本地化文本**：PowerShell 用 `ConvertTo-Json` 输出，属性名是英文；
  netsh 只用来「执行」，不用来「读取」（读取一律走结构化数据）。
  唯一需要解析的 `arp -a` 只做兜底，且只按 IP/MAC 的形状匹配，不看表头。
* **每个函数都能在非 Windows 上导入**（ctypes.windll 只在调用时才碰），
  这样测试和 mac 端 CI 都不受影响。
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

IS_WIN = os.name == "nt"
NETSH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "netsh.exe") \
    if IS_WIN else "netsh"
POWERSHELL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32",
                          "WindowsPowerShell", "v1.0", "powershell.exe") \
    if IS_WIN else "powershell"

CREATE_NO_WINDOW = 0x08000000
MAC_RE = re.compile(r"\b([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\b", re.I)
IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# 历史名字保留一个别名（外部/测试可能 import 过）；实际使用统一的 IF_TYPE_* 常量

# ----------------------------------------------------------------------
# iphlpapi!GetAdaptersAddresses（Windows 第一枚举源）
#
# 为什么它排第一：进程内调用，不 spawn 子进程 —— 不受 PowerShell 策略/杀软、
# 控制台代码页、pythonw 无控制台句柄（[WinError 6]）、20 秒超时的影响；
# FriendlyName / Description 直接是 UTF-16，中文网卡名不会乱码。
#
# 结构体一律用**定长类型**（c_uint32 / c_void_p），不要用 ctypes.wintypes.ULONG：
# 后者在 macOS/Linux 上是 c_ulong（8 字节），结构体会整体错位，mac 上的单测
# 也就没法校验 x64 偏移了。Windows x64 与 mac x64 的指针宽度都是 8，
# 所以同一份定义在两边偏移一致，可以直接断言。
# ----------------------------------------------------------------------

AF_UNSPEC = 0
AF_INET = 2
GAA_SKIP_ANYCAST = 0x0002
GAA_SKIP_MULTICAST = 0x0004
GAA_SKIP_DNS_SERVER = 0x0008
GAA_INCLUDE_PREFIX = 0x0010
GAA_FLAGS = GAA_SKIP_ANYCAST | GAA_SKIP_MULTICAST | GAA_SKIP_DNS_SERVER | GAA_INCLUDE_PREFIX

ERROR_BUFFER_OVERFLOW = 111
ERROR_NO_DATA = 232
ERROR_NOT_SUPPORTED = 50
ERROR_INVALID_PARAMETER = 87

IF_TYPE_ETHERNET_CSMACD = 6
IF_TYPE_IEEE80211 = 71
IF_TYPE_SOFTWARE_LOOPBACK = 24
IF_TYPE_TUNNEL = 131
_IF_TYPE_SOFTWARE_LOOPBACK = IF_TYPE_SOFTWARE_LOOPBACK    # 兼容旧名字

OPER_STATUS_UP = 1
OPER_STATUS_DOWN = 2

GAA_BUFFER_INITIAL = 16 * 1024        # 15~32KB 都行；16KB 够 8~20 张网卡
GAA_BUFFER_MAX = 256 * 1024
GAA_MAX_ROUNDS = 3
# IP_ADAPTER_ADDRESSES.Flags 里的 IP_ADAPTER_DHCP_ENABLED
_ADAPTER_FLAG_DHCP_ENABLED = 0x0004


class _SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p),
                ("iSockaddrLength", ctypes.c_int)]


class _IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    """x64: sizeof=64，Address@16，OnLinkPrefixLength@56。"""


_IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", ctypes.c_uint32),
    ("Flags", ctypes.c_uint32),
    ("Next", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", _SOCKET_ADDRESS),
    ("PrefixOrigin", ctypes.c_int),
    ("SuffixOrigin", ctypes.c_int),
    ("DadState", ctypes.c_int),
    ("ValidLifetime", ctypes.c_uint32),
    ("PreferredLifetime", ctypes.c_uint32),
    ("LeaseLifetime", ctypes.c_uint32),
    ("OnLinkPrefixLength", ctypes.c_ubyte),
]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    """只声明到 OperStatus（x64 偏移 104），后面的字段用不到。

    注意 Length 是**输出**字段（API 回填自己的 sizeof），不要拿我们的
    `ctypes.sizeof(IP_ADAPTER_ADDRESSES)` 去预填它 —— 我们这份是截断结构体。
    """


IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", ctypes.c_uint32),
    ("IfIndex", ctypes.c_uint32),
    ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", ctypes.c_uint32),
    ("Flags", ctypes.c_uint32),
    ("Mtu", ctypes.c_uint32),
    ("IfType", ctypes.c_uint32),
    ("OperStatus", ctypes.c_int),
]

_IPHLPAPI: Dict[str, Any] = {}


# ----------------------------------------------------------------------
# 进程
# ----------------------------------------------------------------------

def _flags() -> int:
    return CREATE_NO_WINDOW if IS_WIN else 0


def _decode_text(raw: bytes, native: bool = False) -> str:
    """按「命令族」解码子进程输出（中文 Windows 上这一步决定错误文本能不能读）。

    * PowerShell：脚本里强制了 `[Console]::OutputEncoding=UTF8`，所以先按 UTF-8
      严格解；万一那句被吞了，PowerShell 会用控制台代码页（中文系统 cp936），
      严格 UTF-8 会失败 → 退 mbcs/OEM。
    * 原生命令（ipconfig/arp/netstat/tasklist/ping）：输出是控制台代码页；
      但 `bmcd.cmd` 里有 `chcp 65001`，那种环境下是 UTF-8。先严格 UTF-8
      （cp936 中文几乎不可能凑成合法 UTF-8），失败再退 mbcs/OEM。

    两条路都失败才 `errors="replace"` —— 保证永远不抛，也永远不静默丢字节。
    """
    data = raw or b""
    if not data:
        return ""
    # 严格 UTF-8 优先：cp936 的汉字字节序列几乎不可能通过 UTF-8 校验，
    # 所以「能解出来」基本就等于「本来就是 UTF-8」。
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    for enc in ("mbcs", "gbk", "cp936"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    # 最后的兜底：native 用 mbcs（Windows）/ utf-8（其它平台）做替换解码
    fallback = "mbcs" if native else "utf-8"
    try:
        return data.decode(fallback, "replace")
    except LookupError:
        return data.decode("utf-8", "replace")


def run(cmd: Sequence[str], timeout: float = 25.0,
        native: bool = True) -> Tuple[int, str, str]:
    """跑一个子进程，永远不弹黑框，永远不因为编码炸掉。

    `stdin=subprocess.DEVNULL` 是**必须**的：GUI 后端跑在 `pythonw.exe` 里，
    没有标准输入句柄，不显式给 DEVNULL 时 CPython 会把无效句柄传给子进程，
    直接抛 `OSError: [WinError 6] 句柄无效` —— 那一下会把网卡枚举的两条源
    一起打死（app_win._capture 早就这么干了，这里对齐）。
    """
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            creationflags=_flags() if IS_WIN else 0,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)
    return (proc.returncode,
            _decode_text(proc.stdout, native=native),
            _decode_text(proc.stderr, native=native))


def ps_quote(text: str) -> str:
    """PowerShell 单引号字符串转义。"""
    return "'" + str(text).replace("'", "''") + "'"


_PS_EXE_CACHE: Dict[str, str] = {}


def powershell_path() -> str:
    """powershell.exe 的真实路径。

    固定拼 `%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe` 在
    32 位 Python 上会被 WOW64 重定向到 `SysWOW64`（那里**没有**这个文件），
    所以固定路径不存在时退到 PATH 里的 `powershell`/`powershell.exe`，
    至少让错误信息是「找不到」而不是一个假的「没有输出」。
    """
    cached = _PS_EXE_CACHE.get("exe")
    if cached:
        return cached
    candidates = [POWERSHELL]
    if IS_WIN:
        candidates.extend(["powershell.exe", "powershell"])
    for cand in candidates:
        if os.path.isabs(cand):
            if os.path.isfile(cand):
                _PS_EXE_CACHE["exe"] = cand
                return cand
            continue
        _PS_EXE_CACHE["exe"] = cand
        return cand
    return POWERSHELL


def powershell(script: str, timeout: float = 20.0) -> Tuple[int, str, str]:
    """跑一段 PowerShell，输出强制 UTF-8（否则中文网卡名会乱码）。

    注意：`[Console]::OutputEncoding` 在没有控制台句柄时（比如被 pythonw
    这种无窗口进程拉起来）会抛 IOException，所以必须包在 try 里 ——
    否则整个脚本一行都不输出，网卡列表就空了。
    """
    body = ("try{[Console]::OutputEncoding=[System.Text.Encoding]::UTF8}"
            "catch{};" + script)
    return run([powershell_path(), "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", body],
               timeout=timeout, native=False)


def powershell_json_ex(script: str, timeout: float = 20.0) -> Tuple[Optional[object], str]:
    """跑 PowerShell 并返回 JSON；失败时把原因带回来（不要静默 None）。"""
    import json

    rc, out, err = powershell(script, timeout=timeout)
    text = (out or "").strip()
    detail = (err or "").strip()[:300]
    if rc != 0:
        return None, ("PowerShell 退出码 %d：%s" % (rc, (detail or text or "无输出")[:200]))
    if not text:
        # rc=0 但没有 stdout 并不等于正常：组策略/杀软/模块缺失时
        # $ErrorActionPreference 会把它变成「静默失败」，真正的线索在 stderr。
        if detail:
            return None, "PowerShell 没有输出（stderr：%s）" % detail
        return None, "PowerShell 没有输出（脚本没报错但也没打印，可能被策略/杀软拦了）"
    start = min([i for i in (text.find("{"), text.find("[")) if i >= 0], default=-1)
    if start > 0:
        text = text[start:]
    try:
        return json.loads(text), ""
    except ValueError:
        return None, "PowerShell 输出不是 JSON：%s%s" % (
            text[:120], ("（stderr：%s）" % detail) if detail else "")


def powershell_json(script: str, timeout: float = 20.0) -> Optional[object]:
    data, _ = powershell_json_ex(script, timeout=timeout)
    return data


# ----------------------------------------------------------------------
# 管理员权限
# ----------------------------------------------------------------------

def is_admin() -> bool:
    if not IS_WIN:
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:                     # noqa: BLE001
        return False


def message_box(text: str, title: str = "BMC DHCP", error: bool = True) -> None:
    if not IS_WIN:
        return
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, str(text), str(title), 0x10 if error else 0x40)
    except Exception:                     # noqa: BLE001
        pass


# ----------------------------------------------------------------------
# 小工具
# ----------------------------------------------------------------------

def mask_from_prefix(prefix: object, default: str = "255.255.255.0") -> str:
    try:
        value = int(prefix)            # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    if value < 0 or value > 32:
        return default
    return str(ipaddress.IPv4Network("0.0.0.0/%d" % value).netmask)


def prefix_from_mask(mask: str, default: int = 24) -> int:
    try:
        return ipaddress.IPv4Network("0.0.0.0/%s" % mask).prefixlen
    except ValueError:
        return default


def norm_mac(mac: str) -> str:
    m = MAC_RE.search(mac or "")
    if not m:
        return ""
    return m.group(1).replace("-", ":").lower()


def _pick_ip(pairs: Sequence[Tuple[str, int]]) -> Tuple[str, int]:
    """从 (ip, prefix) 里挑一个：优先非 link-local / 非环回，否则退第一个。

    纯函数，PowerShell 源和 GetAdaptersAddresses 源共用同一套优先级
    （插着 BMC 网线、只有 169.254 的自配地址时，不能因为它是 link-local
    就把这张网卡整个丢掉）。
    """
    for ip, prefix in pairs:
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if addr.is_link_local or addr.is_loopback:
            continue
        return ip, prefix if 0 < prefix <= 32 else 24
    for ip, prefix in pairs:
        if not ip:
            continue
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        return ip, prefix if 0 < prefix <= 32 else 24
    return "", 0


def _first_ip(rec: Dict[str, object]) -> Tuple[str, int]:
    ips = rec.get("ips")
    if isinstance(ips, dict):
        ips = [ips]
    if not isinstance(ips, list):
        return "", 0
    pairs: List[Tuple[str, int]] = []
    for item in ips:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("ip") or "").strip()
        if not ip:
            continue
        try:
            prefix = int(item.get("p") or 0)
        except (TypeError, ValueError):
            prefix = 0
        pairs.append((ip, prefix))
    return _pick_ip(pairs)


# IF_MEDIA_CONNECT_STATE：数字枚举，不受系统语言影响，比 Status 字符串可靠
_MEDIA_CONNECTED = 1
_MEDIA_DISCONNECTED = 2

_UP_WORDS = {"up", "connected", "已连接", "已連線"}
_DOWN_WORDS = {"disconnected", "down", "disabled", "not present", "notpresent",
               "media disconnected", "媒体已断开连接", "已断开连接", "已禁用",
               "未连接", "此设备当前不可用"}


@dataclass
class AdapterRecord:
    name: str
    desc: str = ""
    mac: str = ""
    status: str = ""
    index: int = 0
    dhcp: bool = False
    ip: str = ""
    prefix: int = 0
    media_state: int = 0
    # 真实接口名（netsh 认的那个）。ipconfig 兜底的 name 是区块标题
    # （"以太网适配器 以太网 2"），friendly 才是 "以太网 2"。
    friendly: str = ""
    if_type: int = 0
    guid: str = ""
    source: str = ""            # ctypes / powershell / ipconfig
    tunnel: bool = False        # isatap/teredo/隧道口：不参与候选排序

    @property
    def mask(self) -> str:
        return mask_from_prefix(self.prefix) if self.prefix else ""

    @property
    def best_name(self) -> str:
        """给 netsh / UI 用的名字：优先 friendly。"""
        return self.friendly or self.name

    @property
    def link_known(self) -> bool:
        """链路的判断依据是否真的存在（媒体状态 / 状态词 / 有地址）。"""
        return bool(self.media_state or (self.status or "").strip() or self.ip)

    @property
    def is_up(self) -> bool:
        """有没有链路。

        三层判断，越靠前越可靠：
          1. MediaConnectState（数字：1 连上 / 2 断开），不看语言；
          2. Status 字符串里的已知词（英文、中文都认）；
          3. 认不出来就当通着 —— 宁可多列一个口，也不要因为读不懂
             本地化字符串把一张能用的网卡挡住（之前就是这么被挡的）。
        """
        if self.media_state == _MEDIA_CONNECTED:
            return True
        if self.media_state == _MEDIA_DISCONNECTED:
            return False
        text = (self.status or "").strip().lower()
        if text in _DOWN_WORDS:
            return False
        if text in _UP_WORDS:
            return True
        return True

    @property
    def is_loopback(self) -> bool:
        low = (self.best_name or "").lower()
        return self.ip.startswith("127.") or "loopback" in low or "环回" in self.best_name


def records_from_json(data: object) -> List[AdapterRecord]:
    """把 Get-NetAdapter 的 JSON 变成记录列表（纯函数，方便单测）。"""
    items: List[object]
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = list(data)
    else:
        return []
    out: List[AdapterRecord] = []
    for raw in items:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("n") or raw.get("Name") or "").strip()
        if not name:
            continue
        ip, prefix = _first_ip(raw)
        try:
            index = int(raw.get("i") or raw.get("ifIndex") or 0)
        except (TypeError, ValueError):
            index = 0
        try:
            media_state = int(raw.get("mcs", raw.get("MediaConnectState")) or 0)
        except (TypeError, ValueError):
            media_state = 0
        dhcp_raw = raw.get("dhcp", raw.get("Dhcp"))
        dhcp = bool(dhcp_raw) if not isinstance(dhcp_raw, str) else \
            dhcp_raw.strip().lower() in ("true", "1", "yes")
        desc = str(raw.get("d") or raw.get("InterfaceDescription") or "").strip()
        out.append(AdapterRecord(
            name=name,
            desc=desc,
            mac=norm_mac(str(raw.get("m") or raw.get("MacAddress") or "")),
            status=str(raw.get("s") or raw.get("Status") or "").strip(),
            index=index,
            dhcp=dhcp,
            ip=ip,
            prefix=prefix,
            media_state=media_state,
            friendly=name,
            if_type=_if_type_from_hint(name, desc),
            source="powershell",
            tunnel=_looks_like_tunnel(name, desc),
        ))
    return out


def _looks_like_tunnel(name: str, desc: str) -> bool:
    """isatap / teredo / 各种隧道口：不该出现在「插 BMC 网线的口」候选里。"""
    text = ((name or "") + " " + (desc or "")).lower()
    return any(hint in text for hint in ("isatap", "teredo", "tunnel", "隧道"))


def _if_type_from_hint(name: str, desc: str) -> int:
    """没有 IfType 时的保守推断（只为让 is_wifi/loopback 判定更稳）。"""
    text = ((name or "") + " " + (desc or "")).lower()
    if any(hint in text for hint in ("wi-fi", "wifi", "wireless", "802.11", "wlan")):
        return IF_TYPE_IEEE80211
    if "loopback" in text or "环回" in text:
        return IF_TYPE_SOFTWARE_LOOPBACK
    return 0


def is_netmask(text: str) -> bool:
    """是不是一个合法的连续掩码（255.255.255.0 这种）。"""
    try:
        net = ipaddress.IPv4Network("0.0.0.0/%s" % text)
    except (ValueError, TypeError):
        return False
    return net.prefixlen > 0 and str(net.netmask) == text


_SECTION_PREFIXES = (
    "以太网适配器", "乙太網路適配器", "无线局域网适配器", "無線區域網路適配器",
    "无线网络连接", "無線網路連線", "隧道适配器", "通道適配器", "未知适配器",
    "蓝牙网络连接", "藍牙網路連線",
    "Ethernet adapter", "Wireless LAN adapter", "Tunnel adapter",
    "Unknown adapter", "PPP adapter", "Mobile Broadband adapter",
)

_SECTION_RE = re.compile(r"^(?P<kind>[^\s]{0,12}?(?:适配器|適配器))\s+(?P<name>.+)$")
_SECTION_EN_RE = re.compile(r"^(?P<kind>.{0,60}?adapter)\s+(?P<name>.+)$", re.I)

_MEDIA_LABELS = ("媒体状态", "媒體狀態", "media state")


def _split_ipconfig_section(title: str) -> str:
    """区块标题 → 真实适配器名。

    中文/英文的 ipconfig 只用区块标题分节：`以太网适配器 以太网 2:` /
    `Ethernet adapter Ethernet 2:`。标题**不是** netsh 认的接口名
    （netsh 要的是 `以太网 2`），所以这里按本地化的「类型前缀」剥一层。
    剥不出来（不认识的本地化）就返回空串，调用方保留原标题。
    """
    text = (title or "").strip()
    if not text:
        return ""
    low = text.lower()
    for prefix in _SECTION_PREFIXES:
        if low.startswith(prefix.lower()):
            rest = text[len(prefix):].strip()
            return rest if rest and rest != text else ""
    for pattern in (_SECTION_RE, _SECTION_EN_RE):
        match = pattern.match(text)
        if match:
            rest = (match.group("name") or "").strip()
            if rest and rest != text:
                return rest
    return ""


def _ipconfig_value(line: str) -> str:
    if ":" not in line:
        return ""
    return line.split(":", 1)[1].strip()


def _ipconfig_desc(lines: Sequence[str]) -> str:
    for line in lines:
        low = line.lower()
        if ("描述" in line) or ("description" in low):
            value = _ipconfig_value(line)
            if value:
                return value
    return ""


def _ipconfig_media_state(lines: Sequence[str]) -> int:
    """从「媒体状态 / Media State」行读链路状态（本地化也认）。"""
    for line in lines:
        low = line.lower()
        if not any(label in low for label in _MEDIA_LABELS):
            continue
        value = _ipconfig_value(line).lower()
        if not value:
            continue
        if ("断开" in value or "中斷" in value or "disconnected" in value
                or "已禁用" in value or "disabled" in value or "停用" in value):
            return _MEDIA_DISCONNECTED
        if "已连接" in value or "已連線" in value or "connected" in value:
            return _MEDIA_CONNECTED
    return 0


def records_from_ipconfig(text: str, mac_names: Optional[Dict[str, str]] = None
                          ) -> List[AdapterRecord]:
    """`ipconfig /all` 兜底解析（最后一级，名字最不可靠，所以只做兜底）。

    Windows 的输出是本地化的，所以这里**不看表头文字**，只按形状抓：
    先按「顶格、以冒号结尾」的行切分隔块，块里出现 6 组 xx-xx 就是 MAC，
    出现点分四段就是地址；`255.x.x.x` 这类连续掩码按掩码算。

    两个补强（都是「能选到网卡」的关键）：
      * `name` 保留区块标题（调用方/老测试依赖这个字段），新增 `friendly`
        存剥出来的真实接口名；给了 `mac_names`（MAC → FriendlyName）时
        优先用 MAC 反查 —— 这是唯一不依赖本地化文字的办法。
      * 抓「描述」和「媒体状态」：否则 virtual / is_wifi / 链路判断在这条
        兜底源上全部失效（隧道口会被当成正经以太口排到候选第一位）。
    """
    names = mac_names or {}
    blocks: List[Tuple[str, List[str]]] = []
    name = ""
    lines: List[str] = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if (not line[:1].isspace()) and stripped.endswith(":") and len(stripped) > 1:
            if name:
                blocks.append((name, lines))
            name = stripped[:-1].strip()
            lines = []
            continue
        if name:
            lines.append(stripped)
    if name:
        blocks.append((name, lines))

    out: List[AdapterRecord] = []
    for block_name, block_lines in blocks:
        if not block_name:
            continue
        mac = ""
        quads: List[str] = []
        for ln in block_lines:
            if not mac:
                found = MAC_RE.search(ln)
                if found:
                    mac = norm_mac(found.group(1))
                    continue
            quads.extend(IPV4_RE.findall(ln))
        ip = ""
        mask = ""
        for quad in quads:
            try:
                addr = ipaddress.IPv4Address(quad)
            except ValueError:
                continue
            if addr.is_multicast or addr.is_loopback:
                continue
            if is_netmask(quad):
                if ip and not mask:
                    mask = quad
                continue
            if not ip:
                ip = quad
        desc = _ipconfig_desc(block_lines)
        media_state = _ipconfig_media_state(block_lines)
        friendly = names.get(mac, "") if mac else ""
        if not friendly:
            friendly = _split_ipconfig_section(block_name)
        if media_state == _MEDIA_DISCONNECTED:
            status = "disconnected"
        elif ip:
            status = "up"
        else:
            status = ""
        out.append(AdapterRecord(
            name=block_name,
            desc=desc,
            mac=mac,
            status=status,
            dhcp=False,
            ip=ip,
            prefix=prefix_from_mask(mask) if mask else 0,
            media_state=media_state,
            friendly=friendly,
            if_type=_if_type_from_hint(friendly or block_name, desc),
            source="ipconfig",
            tunnel=_looks_like_tunnel(block_name + " " + friendly, desc),
        ))
    return out


# ----------------------------------------------------------------------
# 枚举
# ----------------------------------------------------------------------

PS_ADAPTERS = r"""
$ErrorActionPreference = 'Stop';
try {
  Get-NetAdapter -ErrorAction Stop | ForEach-Object {
    $a = $_;
    $ips = @();
    try {
      $ips = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction Stop |
               ForEach-Object { [pscustomobject]@{ ip=$_.IPAddress; p=$_.PrefixLength } });
    } catch {
      # 单个网卡查地址失败不该拖垮整张列表：记到 stderr，继续下一张
      [Console]::Error.WriteLine("BMCD_IP_ERROR ifIndex=$($a.ifIndex): $($_.Exception.Message)");
    }
    [pscustomobject]@{
      n=$a.Name; d=$a.InterfaceDescription; m=$a.MacAddress;
      s=$a.Status; i=$a.ifIndex; dhcp=[bool]$a.Dhcp; mcs=[int]$a.MediaConnectState;
      ips=$ips
    }
  } | ConvertTo-Json -Depth 5 -Compress
} catch {
  [Console]::Error.WriteLine("BMCD_PS_ERROR: $($_.Exception.Message)");
  exit 3
}
"""

PS_DEFAULT_ALIAS = r"""
$ErrorActionPreference='Continue';
try {
  (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
   Sort-Object -Property RouteMetric | Select-Object -First 1).InterfaceAlias
} catch {
  [Console]::Error.WriteLine("BMCD_ROUTE_ERROR: $($_.Exception.Message)");
  exit 3
}
"""

# FriendlyName 反查（MAC → 真实接口名）失败的原因。反查失败不影响「能出网卡」，
# 但 ipconfig 那一级的名字就退化成区块标题了 —— 这个降级必须能被看到。
LAST_NAME_ERROR = ""

_PS_CACHE: Dict[str, object] = {}
_PS_CACHE_TTL = 5.0            # 一次请求内复用；太短等于没缓存（PS 冷启就 1s+）
_ROUTE_CACHE: Dict[str, object] = {}
_ROUTE_CACHE_TTL = 30.0

# 请求级预算位：False = 这次枚举请求还没花掉那一个 powershell.exe，True = 已经花掉了。
# 以前是「ps_ts 距现在 < 2 秒」这种墙钟近似：PS 冷启动一旦超过 2 秒，窗口就过期，
# 默认路由那次查询又 spawn 一个 —— 一次 /api/ifaces 两个 PS，首屏白等一整轮。
# 现在是显式状态位，跟耗时无关：adapter_records() 真枚举时复位，spawn 一次就置起。
PS_BUDGET_KEY = "ps_budget"
# 窗口位：这次请求自己真枚举过（True）。窗口期内复用缓存只是内部再读，
# 不许把 cached 翻回 true；adapter_report() 被读走 = 本次请求结束，窗口关闭。
FRESH_WINDOW_KEY = "fresh_window"


def adapter_report() -> Dict[str, object]:
    """上一次枚举的逐源报告：每条源试没试、成功没、几条、多久、为什么失败。

    界面/诊断/CLI 都靠它把「为什么没有网卡」说清楚。
    """
    report = _PS_CACHE.get("report")
    info = {
        "source": str(_PS_CACHE.get("source") or ""),
        "error": str(_PS_CACHE.get("error") or ""),
        "sources": list(report) if isinstance(report, list) else [],
        "cached": bool(_PS_CACHE.get("cached")),
    }
    # 报告被读走 = 这次请求的枚举到此为止：关掉窗口。下一次请求如果还是复用
    # 同一批缓存（没有真枚举），adapter_records() 才会把 cached 置回 true。
    _PS_CACHE[FRESH_WINDOW_KEY] = False
    return info


def adapter_source() -> Dict[str, str]:
    """上一次枚举用的是哪条路、失败了为什么（给界面显示，别让用户对着空列表猜）。"""
    info = adapter_report()
    return {"source": str(info["source"]), "error": str(info["error"])}


# ----------------------------------------------------------------------
# GetAdaptersAddresses（ctypes）—— Windows 第一枚举源
# ----------------------------------------------------------------------

def _iphlpapi():
    """拿 iphlpapi 模块（只在 Windows 上有效）；不可用时返回 None。"""
    if not IS_WIN:
        return None
    cached = _IPHLPAPI.get("lib")
    if cached is not None:
        return cached
    windll = getattr(ctypes, "WinDLL", None)
    if windll is None:                    # 非 Windows 解释器
        return None
    try:
        lib = windll("iphlpapi.dll")
    except OSError:
        return None
    try:
        lib.GetAdaptersAddresses.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
        ]
        lib.GetAdaptersAddresses.restype = ctypes.c_uint32
        lib.GetBestInterface.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        lib.GetBestInterface.restype = ctypes.c_uint32
    except (AttributeError, TypeError):
        pass
    _IPHLPAPI["lib"] = lib
    return lib


def _gaa_error(rc: int) -> str:
    known = {
        ERROR_BUFFER_OVERFLOW: "ERROR_BUFFER_OVERFLOW(111) 缓冲区不够",
        ERROR_NO_DATA: "ERROR_NO_DATA(232) 没有此族地址（网卡全禁用/未连接时会出现）",
        ERROR_NOT_SUPPORTED: "ERROR_NOT_SUPPORTED(50) 系统不支持 IPv4 枚举",
        ERROR_INVALID_PARAMETER: "ERROR_INVALID_PARAMETER(87) 参数不合法",
    }
    if rc in known:
        return known[rc]
    try:
        return "Win32 错误 %d：%s" % (rc, ctypes.FormatError(rc))   # Windows 才有
    except (AttributeError, OSError, ValueError):
        return "Win32 错误 %d" % rc


def _decode_cstr(value: object) -> str:
    """PCHAR（AdapterName 那种）→ str；bytes 要按 ASCII 解，别留成 "b'...'"。"""
    if not value:
        return ""
    if isinstance(value, bytes):
        return value.decode("ascii", "replace")
    return str(value)


def _sockaddr_ipv4(raw: bytes) -> str:
    """从 sockaddr 原始字节里取 IPv4 点分地址（AF_INET 才算）。

    Windows 只有小端平台（x86/x64/ARM64），family 字段按小端读；
    `sockaddr_in.sin_addr` 固定在偏移 4。
    """
    if len(raw) < 8:
        return ""
    if int.from_bytes(raw[0:2], "little") != AF_INET:
        return ""
    return "%d.%d.%d.%d" % (raw[4], raw[5], raw[6], raw[7])


def _unicast_pairs(head) -> List[Tuple[str, int]]:
    """走 IP_ADAPTER_UNICAST_ADDRESS 链表，收集 (ip, prefix)。"""
    pairs: List[Tuple[str, int]] = []
    node = head
    seen = 0
    while node and seen < 64:
        seen += 1
        try:
            item = node.contents
            sock = item.Address
            length = int(sock.iSockaddrLength or 0)
            if not sock.lpSockaddr or length < 8:
                node = item.Next
                continue
            raw = ctypes.string_at(sock.lpSockaddr, length)
            ip = _sockaddr_ipv4(raw)
            if ip:
                pairs.append((ip, int(item.OnLinkPrefixLength or 0)))
            node = item.Next
        except (ValueError, OSError):
            break
    return pairs


def records_from_adapters_addresses(buf, source: str = "ctypes") -> List[AdapterRecord]:
    """把 GetAdaptersAddresses 填好的缓冲区解析成 AdapterRecord（纯函数，可单测）。

    读的字段：FriendlyName / Description / PhysicalAddress+Length /
    IfIndex / IfType / OperStatus / Flags(DHCP) / AdapterName(GUID) /
    FirstUnicastAddress 链表（IPv4 + OnLinkPrefixLength）。

    注意：缓冲区里是 API 按系统的真实结构体长度写进去的，我们只声明到
    OperStatus，所以**只能读前面这段**字段；`Length` 是输出字段，不参与判断。
    """
    if not buf:
        return []
    out: List[AdapterRecord] = []
    try:
        node = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    except (TypeError, ValueError):
        return []
    seen = 0
    while node and seen < 512:
        seen += 1
        try:
            entry = node.contents
            name = str(entry.FriendlyName or "").strip()
            desc = str(entry.Description or "").strip()
            if not name and not desc:
                node = entry.Next
                continue
            length = int(entry.PhysicalAddressLength or 0)
            mac = ""
            if length == 6:
                mac = ":".join("%02x" % entry.PhysicalAddress[i] for i in range(6))
            # 8 字节是 EUI-64（隧道口 / Teredo），不是以太网 MAC：不伪造
            if_type = int(entry.IfType or 0)
            oper = int(entry.OperStatus or 0)
            if oper == OPER_STATUS_UP:
                media_state = _MEDIA_CONNECTED
            elif oper == OPER_STATUS_DOWN:
                media_state = _MEDIA_DISCONNECTED
            else:
                media_state = 0
            ip, prefix = _pick_ip(_unicast_pairs(entry.FirstUnicastAddress))
            out.append(AdapterRecord(
                name=name or desc,
                desc=desc,
                mac=mac,
                status="Up" if oper == OPER_STATUS_UP else (
                    "Disconnected" if oper == OPER_STATUS_DOWN else ""),
                index=int(entry.IfIndex or 0),
                dhcp=bool(int(entry.Flags or 0) & _ADAPTER_FLAG_DHCP_ENABLED),
                ip=ip,
                prefix=prefix,
                media_state=media_state,
                friendly=name,
                if_type=if_type,
                guid=_decode_cstr(entry.AdapterName),
                source=source,
                tunnel=(if_type == IF_TYPE_TUNNEL) or _looks_like_tunnel(name, desc),
            ))
            node = entry.Next
        except (ValueError, OSError):
            break
    return out


def _gaa_call(size: int) -> Tuple[int, int, Optional[object]]:
    """调一次 GetAdaptersAddresses，返回 (rc, 需要的字节数, 缓冲区)。"""
    lib = _iphlpapi()
    if lib is None:
        return -1, 0, None
    buf = ctypes.create_string_buffer(max(int(size), 1024))
    length = ctypes.c_uint32(len(buf))
    # 用 AF_UNSPEC 而不是 AF_INET：带 family 过滤时，**没有任何 IPv4 的网卡
    # 会整张被漏掉** —— 而「刚插上 BMC 网线、还没拿到地址」恰恰是这种状态，
    # 那正是这个工具最需要看到的口。解析时只取 AF_INET 的 unicast 地址。
    rc = int(lib.GetAdaptersAddresses(
        ctypes.c_uint32(AF_UNSPEC), ctypes.c_uint32(GAA_FLAGS), None,
        ctypes.cast(buf, ctypes.c_void_p), ctypes.byref(length)))
    return rc, int(length.value), buf


def adapters_ctypes() -> Tuple[List[AdapterRecord], str]:
    """GetAdaptersAddresses 枚举源。返回 (records, error)，永远不抛。

    非 Windows 直接返回空 + 原因（调用方据此降级到下一源）。
    """
    if not IS_WIN:
        return [], "跳过 GetAdaptersAddresses：非 Windows 平台"
    if _iphlpapi() is None:
        return [], "GetAdaptersAddresses 不可用：加载 iphlpapi.dll 失败"
    size = GAA_BUFFER_INITIAL
    last = ""
    for _round in range(GAA_MAX_ROUNDS):
        rc, need, buf = _gaa_call(size)
        if rc == 0:
            return records_from_adapters_addresses(buf), ""
        if rc == ERROR_BUFFER_OVERFLOW:
            last = _gaa_error(rc)
            size = max(int(need), size * 2)
            if size > GAA_BUFFER_MAX:
                return [], "GetAdaptersAddresses 需要 %d 字节缓冲区（超过上限 %d）" % (
                    int(need), GAA_BUFFER_MAX)
            continue
        if rc == ERROR_NO_DATA:
            # 空，但**不是失败**：系统里没有 IPv4 地址时就是这种返回。
            return [], "GetAdaptersAddresses 返回 %s（空但不算失败）" % _gaa_error(rc)
        return [], "GetAdaptersAddresses 失败：%s" % _gaa_error(rc)
    return [], "GetAdaptersAddresses 连续 %d 次失败：%s" % (GAA_MAX_ROUNDS, last)


def _names_by_mac() -> Dict[str, str]:
    """MAC → FriendlyName（用 ctypes 源；失败就返回空表，但把原因留给调用方）。

    以前这里是 `except Exception: return {}` —— 反查失败与「ctypes 源本来就不可用」
    看起来一模一样，ipconfig 兜底出来的名字悄悄退化成区块标题，没人知道为什么。
    """
    global LAST_NAME_ERROR
    try:
        records, _ = adapters_ctypes()
    except Exception as exc:              # noqa: BLE001  兜底源里绝不能再炸
        LAST_NAME_ERROR = "FriendlyName 反查失败：%s" % exc
        return {}
    LAST_NAME_ERROR = ""
    return {rec.mac: rec.best_name for rec in records if rec.mac and rec.best_name}


# ----------------------------------------------------------------------
# 三源降级
# ----------------------------------------------------------------------

_SOURCES = ("ctypes", "powershell", "ipconfig")


def _source_order() -> List[str]:
    """枚举源顺序：ctypes → powershell → ipconfig（可用 BMCD_IFACE_SOURCE 覆盖）。"""
    raw = os.environ.get("BMCD_IFACE_SOURCE", "").strip().lower()
    if not raw:
        return list(_SOURCES)
    picked = [item.strip() for item in raw.split(",") if item.strip()]
    order = [item for item in picked if item in _SOURCES]
    return order or list(_SOURCES)


def _records_from_powershell() -> Tuple[List[AdapterRecord], str]:
    # 先把预算花掉再 spawn：同一次 /api/ifaces 里还要查默认路由，那条查询也是
    # powershell.exe —— 一次请求最多允许 spawn 一次（见 default_route_iface）。
    # 先置位是故意的：powershell_json_ex 超时/抛异常也算花掉，否则失败之后
    # 默认路由还会再 spawn 一个。
    _PS_CACHE[PS_BUDGET_KEY] = True
    data, err = powershell_json_ex(PS_ADAPTERS, timeout=8.0)
    records = records_from_json(data)
    if records:
        return records, ""
    return [], err or "Get-NetAdapter 没有返回任何网卡"


def _records_from_ipconfig() -> Tuple[List[AdapterRecord], str]:
    rc, out, err = run(["ipconfig", "/all"], timeout=20)
    if rc != 0:
        return [], "ipconfig 失败：%s" % ((err or out or "rc=%d" % rc).strip()[:200])
    names = _names_by_mac()
    name_error = LAST_NAME_ERROR
    records = records_from_ipconfig(out, names) if names else records_from_ipconfig(out)
    if records:
        # 出了网卡但名字反查失败：这一级算成功，同时把降级原因带出去
        return records, name_error
    detail = "ipconfig 输出解析不出网卡"
    if name_error:
        detail = "%s；%s" % (detail, name_error)
    return [], detail


def adapter_records(force: bool = False) -> List[AdapterRecord]:
    """枚举网卡：ctypes → PowerShell → ipconfig，任一级有结果就用它。

    每一级都会在 `adapter_report()` 里留下 {source, ok, count, ms, error}，
    全失败时 `adapter_source()['error']` 会逐级写明原因 —— 界面据此告诉用户
    「是没网卡还是读不到网卡」。
    """
    return adapter_records_with_flag(force=force)[0]


def adapter_records_with_flag(force: bool = False) -> Tuple[List[AdapterRecord], bool]:
    """同上，但把「这次是不是吃的缓存」一起返回：(records, from_cache)。

    `cached` 只描述**本次请求的顶层枚举**：真枚举过就是 False，哪怕同一次请求
    后面的内部调用（默认路由、is_wifi 之类）又复用了一次同一批记录。
    """
    now = time.time()
    if not force:
        cached = _PS_CACHE.get("records")
        ts = float(_PS_CACHE.get("ts") or 0)          # type: ignore[arg-type]
        if isinstance(cached, list) and now - ts < _PS_CACHE_TTL:
            if not _PS_CACHE.get(FRESH_WINDOW_KEY):
                _PS_CACHE["cached"] = True
            return list(cached), True                 # type: ignore[arg-type]

    # 真枚举：预算复位（这次请求还能 spawn 一个 powershell.exe），并开新窗口
    _PS_CACHE[PS_BUDGET_KEY] = False
    _PS_CACHE[FRESH_WINDOW_KEY] = True

    attempts: List[Dict[str, object]] = []
    records: List[AdapterRecord] = []
    chosen = ""
    for source in _source_order():
        started = time.time()
        got: List[AdapterRecord] = []
        err = ""
        try:
            if source == "ctypes":
                got, err = adapters_ctypes()
            elif source == "powershell":
                got, err = _records_from_powershell()
            else:
                got, err = _records_from_ipconfig()
        except Exception as exc:          # noqa: BLE001  一条源炸了不能把整条链带走
            got, err = [], "%s 源异常：%s" % (source, exc)
        attempts.append({
            "source": source,
            "ok": bool(got),
            "count": len(got),
            "ms": int((time.time() - started) * 1000),
            "error": "" if got else (err or "没有返回网卡"),
            # 出了结果但有降级（比如 ipconfig 的名字反查失败）：不能当没发生
            "warning": (err or "") if got else "",
            "skipped": bool(source == "ctypes" and not IS_WIN),
        })
        if got:
            records = got
            chosen = source
            break

    # 失败原因：非跳过级别的错误逐条列出；成功时也保留（前面几级确实失败了）
    failures = [a for a in attempts if not a["ok"] and not a["skipped"]]
    warnings = [a for a in attempts if a["ok"] and a.get("warning")]
    parts = ["%s：%s" % (a["source"], a["error"]) for a in failures]
    parts += ["%s：%s（已降级，不影响出网卡）" % (a["source"], a["warning"])
              for a in warnings]
    error = "；".join(parts)
    if not records and not error:
        error = "没有读到任何网卡（所有枚举源都返回空）"

    _PS_CACHE["records"] = records
    _PS_CACHE["ts"] = now
    _PS_CACHE["source"] = chosen
    _PS_CACHE["error"] = error
    _PS_CACHE["report"] = attempts
    _PS_CACHE["cached"] = False
    return records, False


def find_record(name: str) -> Optional[AdapterRecord]:
    """按接口名 / friendly 名 / 描述找记录（手填的名字也走这里）。"""
    target = (name or "").strip()
    if not target:
        return None
    low = target.lower()
    records = adapter_records()
    for rec in records:
        if rec.name == target or rec.best_name == target:
            return rec
    for rec in records:
        if (rec.name.lower() == low or rec.best_name.lower() == low
                or (rec.desc and rec.desc.lower() == low)):
            return rec
    return None


def addresses(name: str) -> List[str]:
    """这张网卡上所有 IPv4（含我们加的临时地址）。"""
    if not name:
        return []
    # 只在 cmdlet 上 SilentlyContinue：「这张卡上没有 IPv4」是正常结果，
    # 但别的错误（别名不存在/模块不可用）会落进 stderr 被 powershell_json_ex 带出来
    script = ("Get-NetIPAddress -InterfaceAlias %s -AddressFamily IPv4 "
              "-ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress }"
              % ps_quote(name))
    rc, out, _ = powershell(script)
    found: List[str] = []
    if rc == 0:
        for line in out.splitlines():
            text = line.strip()
            if not text:
                continue
            try:
                ipaddress.IPv4Address(text)
            except ValueError:
                continue
            found.append(text)
    if found:
        return found
    rec = find_record(name)
    return [rec.ip] if rec and rec.ip else []


def _readback(name: str, ip: str, present: bool = True,
              tries: int = 5, delay: float = 0.15) -> bool:
    """改完地址后回读确认。

    刚执行完 netsh 时查询接口可能还没刷新，所以重试几次；
    只看一次会把「其实成功了」判成失败，然后弹一个假的错误框。
    """
    for index in range(max(1, tries)):
        got = ip in addresses(name)
        if got == present:
            return True
        if index + 1 < tries:
            time.sleep(delay)
    return False


def best_interface_index(dest: str = "8.8.8.8") -> int:
    """内核会从哪张网卡出去（GetBestInterface，进程内，不 spawn 子进程）。"""
    lib = _iphlpapi()
    if lib is None:
        return 0
    try:
        addr = int(ipaddress.IPv4Address(dest))
    except ValueError:
        return 0
    index = ctypes.c_uint32(0)
    try:
        rc = int(lib.GetBestInterface(ctypes.c_uint32(socket.htonl(addr)),
                                       ctypes.byref(index)))
    except (OSError, ValueError):
        return 0
    return int(index.value) if rc == 0 else 0


def default_route_iface() -> str:
    """上网用的那个网卡（名字）。

    顺序：GetBestInterface（0 次 spawn）→ PowerShell（缓存 30s）→ UDP 路由试探。
    以前只有 PowerShell 一条路，它一挂「默认路由」标记全丢，界面就不再提示
    「启动会改上网网卡的地址（会断网）」—— 这是个安全提示，不能靠一条命令。
    """
    now = time.time()
    cached_name = str(_ROUTE_CACHE.get("name") or "")
    cached_ts = float(_ROUTE_CACHE.get("ts") or 0)         # type: ignore[arg-type]
    if cached_name and now - cached_ts < _ROUTE_CACHE_TTL:
        return cached_name

    def _remember(value: str) -> str:
        if value:
            _ROUTE_CACHE["name"] = value
            _ROUTE_CACHE["ts"] = now
        return value

    # 1) 进程内问内核：按 IfIndex 对上记录
    index = best_interface_index()
    if index:
        for rec in adapter_records():
            if rec.index == index and rec.best_name:
                return _remember(rec.best_name)

    # 2) PowerShell —— 只在本次枚举请求还没花掉预算时问一次，把
    #    「一次 /api/ifaces 最多 1 个 powershell.exe」钉死（下面还有 UDP 兜底，
    #    跳过不会让「默认路由」标记整段失效，只是少一次网络往返查询）。
    #    这里不看时间：PS 冷启 2 秒还是 10 秒，预算都一样只允许一次。
    if not bool(_PS_CACHE.get(PS_BUDGET_KEY)):
        _PS_CACHE[PS_BUDGET_KEY] = True         # 消费后置回：同一次请求不再 spawn
        rc, out, _ = powershell(PS_DEFAULT_ALIAS, timeout=8.0)
        text = (out or "").strip().splitlines()
        if rc == 0 and text:
            alias = text[0].strip()
            if alias:
                return _remember(alias)

    # 3) 兜底：连一个外网地址看内核选哪个源地址（不真的发包）
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 53))
        src = probe.getsockname()[0]
    except OSError:
        return ""
    finally:
        probe.close()
    for rec in adapter_records():
        if rec.ip and rec.ip == src:
            return _remember(rec.best_name)
    return ""


# ----------------------------------------------------------------------
# 配置网卡（netsh）
# ----------------------------------------------------------------------

def _q(name: str) -> str:
    """netsh 的 name= 必须带引号，否则「以太网 2」这种带空格的名字会被截断。"""
    return 'name="%s"' % name


def netsh_set_static(name: str, ip: str, mask: str, gateway: str = "") -> List[str]:
    """构造命令（纯函数，单测用）。"""
    cmd = [NETSH, "interface", "ipv4", "set", "address", _q(name),
           "source=static", "address=%s" % ip, "mask=%s" % mask]
    if gateway:
        cmd.append("gateway=%s" % gateway)
    else:
        cmd.append("gateway=none")
    return cmd


def netsh_set_dhcp(name: str) -> List[str]:
    return [NETSH, "interface", "ipv4", "set", "address", _q(name), "source=dhcp"]


def netsh_add_address(name: str, ip: str, mask: str,
                      store: str = "active") -> List[str]:
    """加一个附加地址。

    `store=active` 很关键：不带的话 netsh 会把它写进**持久配置**，
    重启后这个「临时地址」还挂在网卡上（mac 的 ifconfig alias 是重启就没）。
    """
    cmd = [NETSH, "interface", "ipv4", "add", "address", _q(name),
           "address=%s" % ip, "mask=%s" % mask]
    if store:
        cmd.append("store=%s" % store)
    return cmd


def netsh_delete_address(name: str, ip: str, store: str = "active") -> List[str]:
    cmd = [NETSH, "interface", "ipv4", "delete", "address", _q(name),
           "address=%s" % ip]
    if store:
        cmd.append("store=%s" % store)
    return cmd


def set_static(name: str, ip: str, mask: str, gateway: str = "") -> bool:
    rc, _, _ = run(netsh_set_static(name, ip, mask, gateway))
    if rc != 0:
        return False
    # netsh 偶尔返回 0 但没生效（也可能是查询滞后），回读确认
    return _readback(name, ip, present=True)


def set_dhcp(name: str) -> bool:
    rc, _, _ = run(netsh_set_dhcp(name))
    return rc == 0


def add_alias(name: str, ip: str, mask: str) -> bool:
    """再加一个地址（netsh 的 add address 等价于 `ifconfig alias`）。"""
    rc = 1
    for store in ("active", ""):        # 老版本 netsh 不认 store 参数
        rc, _, _ = run(netsh_add_address(name, ip, mask, store=store))
        if rc == 0 and _readback(name, ip, present=True, tries=2):
            return True
    return rc == 0


def remove_alias(name: str, ip: str) -> bool:
    rc = 1
    for store in ("active", ""):
        rc, _, _ = run(netsh_delete_address(name, ip, store=store))
        if rc == 0:
            break
    if rc != 0:
        return False
    return _readback(name, ip, present=False, tries=2)


def describe_config(name: str) -> Dict[str, object]:
    """当前配置：dhcp / manual + 地址 + 网关（用于停止时还原）。"""
    rec = find_record(name)
    result: Dict[str, object] = {"mode": "none", "ip": "", "mask": "", "router": ""}
    if rec is None:
        return result
    result["mode"] = "dhcp" if rec.dhcp else "manual"
    result["ip"] = rec.ip
    result["mask"] = rec.mask
    result["router"] = gateway_of(name)
    return result


def gateway_of(name: str) -> str:
    # 「没有默认网关」是正常结果，只需要让 cmdlet 安静；真正的错误会走 stderr
    script = ("(Get-NetRoute -InterfaceAlias %s -DestinationPrefix '0.0.0.0/0' "
              "-ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | "
              "Select-Object -First 1).NextHop" % ps_quote(name))
    rc, out, _ = powershell(script)
    text = (out or "").strip().splitlines()
    if rc != 0 or not text:
        return ""
    hop = text[0].strip()
    try:
        ipaddress.IPv4Address(hop)
    except ValueError:
        return ""
    return "" if hop == "0.0.0.0" else hop


# ----------------------------------------------------------------------
# ARP：SendARP（不需要 Npcap、不需要管理员）
# ----------------------------------------------------------------------

def send_arp(ip: str) -> str:
    """问「这个 IP 的 MAC 是多少」。同一段链路上立刻就有答案。"""
    if not IS_WIN:
        return ""
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:                     # noqa: BLE001
        return ""
    try:
        dest = int(ipaddress.IPv4Address(ip))
    except ValueError:
        return ""
    buf = (ctypes.c_ubyte * 8)()
    size = wintypes.ULONG(8)
    try:
        res = ctypes.windll.iphlpapi.SendARP(
            wintypes.ULONG(dest), wintypes.ULONG(0),
            ctypes.cast(buf, ctypes.POINTER(wintypes.ULONG)), ctypes.byref(size))
    except Exception:                     # noqa: BLE001
        return ""
    if res != 0 or size.value < 6:
        return ""
    return ":".join("%02x" % buf[i] for i in range(6))


ARP_MAX_TARGETS = 4096      # 单次调用最多问这么多（调用方会分批）


def arp_sweep(targets: object, timeout: float = 1.0,
              workers: int = 64) -> List[Tuple[str, str]]:
    """用 SendARP 问一批地址（同一根线上的才会答），返回 [(ip, mac)]。

    `targets` 可以是 CIDR 字符串，也可以是 IP 列表 —— 因为 BMC 的静态地址
    可能是任何地址，调用方经常只拿得到一串「猜出来的」具体 IP。
    **不再静默截断**：以前 [:1024] 会把大网段后面全吃掉，看着像「扫完了没东西」。
    """
    from concurrent.futures import ThreadPoolExecutor

    hosts: List[str] = []
    if isinstance(targets, str):
        try:
            net = ipaddress.IPv4Network(targets, strict=False)
        except ValueError:
            return []
        hosts = [str(h) for h in net.hosts()]
    else:
        for item in targets or []:            # type: ignore[union-attr]
            text = str(item).strip()
            try:
                ipaddress.IPv4Address(text)
            except ValueError:
                continue
            hosts.append(text)
    if len(hosts) > ARP_MAX_TARGETS:
        hosts = hosts[:ARP_MAX_TARGETS]
    found: List[Tuple[str, str]] = []
    if not hosts:
        return found
    with ThreadPoolExecutor(max_workers=max(4, min(128, workers))) as pool:
        for ip, mac in zip(hosts, pool.map(send_arp, hosts)):
            if mac:
                found.append((ip, mac))
    return sorted(found, key=lambda x: tuple(int(p) for p in x[0].split(".")))


def arp_table(text: str) -> List[Tuple[str, str]]:
    """解析 `arp -a` 的输出（兜底用）。

    表头是本地化的，但数据行永远是「IP  物理地址  类型」，
    所以只按 IP + xx-xx-xx 的形状匹配。
    """
    out: List[Tuple[str, str]] = []
    seen = set()
    for line in (text or "").splitlines():
        ipm = re.match(r"\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)", line)
        if not ipm:
            continue
        mac = norm_mac(ipm.group(2))
        if not mac or mac == "ff:ff:ff:ff:ff:ff" or mac == "00:00:00:00:00:00":
            continue
        try:
            addr = ipaddress.IPv4Address(ipm.group(1))
        except ValueError:
            continue
        if addr.is_multicast or addr.is_loopback or addr.is_link_local:
            continue
        key = str(addr)
        if key in seen:
            continue
        seen.add(key)
        out.append((key, mac))
    return out


def arp_lookup(ip: str) -> str:
    mac = send_arp(ip)
    if mac:
        return mac
    rc, out, _ = run(["arp", "-a", ip])
    if rc != 0:
        return ""
    for found_ip, found_mac in arp_table(out):
        if found_ip == ip:
            return found_mac
    return ""


# ----------------------------------------------------------------------
# ping
# ----------------------------------------------------------------------

def ping_alive(ip: str, timeout: float = 1.0) -> bool:
    ms = max(100, int(timeout * 1000))
    rc, _, _ = run(["ping", "-n", "1", "-w", str(ms), "-4", ip], timeout=timeout + 4)
    return rc == 0


# ----------------------------------------------------------------------
# 端口占用
# ----------------------------------------------------------------------

def udp_port_owners(port: int = 67) -> List[int]:
    """netstat -ano 里本地端口是 :port 的 PID。"""
    rc, out, _ = run(["netstat", "-ano", "-p", "UDP"], timeout=20)
    if rc != 0:
        return []
    pids: List[int] = []
    suffix = ":%d" % port
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[1]
        if not local.endswith(suffix):
            continue
        try:
            pid = int(parts[-1])
        except ValueError:
            continue
        if pid and pid not in pids:
            pids.append(pid)
    return pids


def process_name(pid: int) -> str:
    rc, out, _ = run(["tasklist", "/FI", "PID eq %d" % pid, "/FO", "CSV", "/NH"],
                     timeout=15)
    if rc != 0 or not out.strip():
        return ""
    first = out.strip().splitlines()[0]
    name = first.split(",")[0].strip().strip('"')
    # 没匹配到进程时 tasklist 会打印一句本地化提示（"信息: ..." / "INFO: ..."），
    # 中文系统上它不以 "info:" 开头，所以按「像不像可执行文件名」来判。
    if not name.lower().endswith((".exe", ".com", ".bat", ".cmd")):
        return ""
    return name


# ----------------------------------------------------------------------
# scapy 接口名映射（Npcap 用的是 \Device\NPF_{GUID}）
# ----------------------------------------------------------------------

_SCAPY_IFACE_CACHE: Dict[str, str] = {}


def scapy_iface(name: str) -> str:
    """友好名（"以太网 2"）→ scapy/Npcap 能用的设备名。"""
    if not IS_WIN or not name:
        return name
    cached = _SCAPY_IFACE_CACHE.get(name)
    if cached:
        return cached
    try:
        from scapy.all import conf  # type: ignore
    except Exception:                     # noqa: BLE001
        return name
    target = name.strip().lower()
    for entry in getattr(conf, "ifaces", {}).values():
        candidates = {
            str(getattr(entry, "name", "") or ""),
            str(getattr(entry, "description", "") or ""),
            str(getattr(entry, "network_name", "") or ""),
            str(getattr(entry, "friendly_name", "") or ""),
        }
        for cand in candidates:
            if cand and cand.strip().lower() == target:
                resolved = str(getattr(entry, "name", "") or name)
                _SCAPY_IFACE_CACHE[name] = resolved
                return resolved
    return name


def has_npcap() -> bool:
    """装了 Npcap 才能用 scapy 抓包/发二层帧。"""
    if not IS_WIN:
        return False
    try:
        from scapy.all import conf  # type: ignore
    except Exception:                     # noqa: BLE001
        return False
    for attr in ("use_pcap", "use_winpcap"):
        if getattr(conf, attr, False):
            return True
    # scapy 在 Windows 上装了 Npcap 后 conf.use_pcap 会是 True；
    # 某些版本不看这个开关，直接看有没有 NPF 设备
    try:
        for entry in getattr(conf, "ifaces", {}).values():
            if "NPF_" in str(getattr(entry, "name", "")):
                return True
    except Exception:                     # noqa: BLE001
        pass
    return False
