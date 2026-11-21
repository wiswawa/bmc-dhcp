"""IP 探测：把「已经配好地址、不会来要 DHCP」的机器找出来。

DHCP 只帮得到还没有地址的机器。出厂静态（192.168.0.120 之类）、或者上一任
管理员手工配过 IP 的 BMC，永远不发 DISCOVER，所以我们另外用两条腿走：

  1. **被动侦听**（passive）
     机器一上线就会发 gratuitous ARP（宣告「这个 IP 是我的」）、做 ARP 探测
     （源 0.0.0.0 问「这个 IP 有人用吗」，从这里能读出它**打算**用的地址）、
     发 mDNS / LLDP / NBNS / SSDP。这些都是二层广播，只要在同一根线/同一个
     交换机上就能听到，根本不需要我们跟它同网段。

  2. **主动扫网段**（active）
     ARP 请求本身就是以太网广播，所以"本机在同一网段里有地址"并不是前提：
     `srp(Ether(broadcast)/ARP(pdst='192.168.0.0/24'))` 会把出厂网段直接问一遍，
     目标机器单播回 ARP 应答。扫到之后临时给网卡加一个同网段别名，
     TCP 才连得上去（不然没有路由），然后就能识别厂商、打开管理页。

识别（是 iDRAC 还是 iLO）复用 discover / vendors，避免自己再编一套。
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from . import discover, vendors
from . import iface as I
from . import winnet

MAX_HOSTS = 512             # 一批 ARP 打多少个地址（也是「小段」的分界）
CHUNK_HOSTS = 512           # 大网段切成这么大的批，才能报进度 / 能中断
SWEEP_MAX_TOTAL = 131072    # 一次最多扫这么多地址（两个 /16）；再大必然扫不完
MAX_HITS = 512
MAX_ALIASES = 8             # 一次最多加这么多个临时地址，别把网卡堆满
MAX_PROBE = 64              # 只识别这么多台：扫到大网段时不至于卡几分钟
PASSIVE_MAX = 60.0
PASSIVE_DEFAULT = 8.0
SLICE = 1.0                 # 被动侦听切片：每秒 check 一次"要不要停"
SWEEP_TIMEOUT = 1.2
PROBE_TIMEOUT = 0.9
SWEEP_WORKERS = 6
ALIAS_HOSTS = (254, 253, 252, 251, 250, 249, 200, 111, 10)

# ----------------------------------------------------------------------
# 「猜」的地址：BMC 的静态地址可能是任何值（上一家单位留下的），
# 但绝大多数情况下跑不出厂商出厂默认值或常见的规划习惯。
# 这批只要几十个包、1 秒内出结果，命中率比盲扫一个大网段高得多。
# ----------------------------------------------------------------------
GUESS_SUBNETS = (
    "192.168.0", "192.168.1", "192.168.2", "192.168.10", "192.168.20",
    "192.168.50", "192.168.70", "192.168.88", "192.168.100", "192.168.120",
    "10.0.0", "10.1.1", "10.10.10", "172.16.0", "172.16.1",
)
GUESS_HOSTS = (120, 100, 125, 2, 1, 254, 101, 10)
GUESS_TARGETS = tuple("%s.%d" % (sub, host)
                      for sub in GUESS_SUBNETS for host in GUESS_HOSTS)

BPF_FILTER = (
    "arp or (udp and (port 5353 or port 1900 or port 137)) or (ether proto 0x88cc)"
)


class ScanError(Exception):
    """参数/环境不对，不能让扫描跑起来。"""


class ScanBusy(ScanError):
    """已经有一个扫描在跑。"""


# ----------------------------------------------------------------------
# 观察到的一条线索
# ----------------------------------------------------------------------

@dataclass
class Observation:
    ip: str
    mac: str = ""
    source: str = ""
    note: str = ""
    hostname: str = ""


@dataclass
class Hit:
    ip: str
    mac: str = ""
    alt_macs: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    hostname: str = ""
    vendor: str = ""
    confidence: str = ""
    summary: str = ""
    # ARP 查询本身失败的原因（跟「表里没有这个 MAC」区分开，界面单独显示成告警）
    arp_error: str = ""
    alive: bool = False
    ports: List[int] = field(default_factory=list)
    url: str = ""
    creds: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    probed: bool = False
    first_seen: float = 0.0
    score: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "alt_macs": list(self.alt_macs),
            "sources": list(self.sources),
            "hostname": self.hostname,
            "vendor": self.vendor,
            "confidence": self.confidence,
            "summary": self.summary,
            "arp_error": self.arp_error,
            "alive": self.alive,
            "ports": list(self.ports),
            "url": self.url,
            "creds": list(self.creds),
            "evidence": list(self.evidence),
            "probed": self.probed,
            "score": self.score,
        }


# ----------------------------------------------------------------------
# 纯解析函数（不碰网络，方便单元测试）
# ----------------------------------------------------------------------

def _ok_ip(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(str(ip).strip())
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified or addr.is_loopback:
        return False
    if addr.is_link_local or addr == ipaddress.IPv4Address("255.255.255.255"):
        return False
    return True


def _clean_name(raw: str) -> str:
    text = (raw or "").replace("\x00", "").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:96]


def parse_lldp(payload: bytes) -> Tuple[str, List[str]]:
    """解析 LLDP 的 system name / management address TLV。

    LLDP 是机器「我是谁、我管理地址是哪个」的自报家门，BMC 一般都开着，
    比猜 MAC 前缀可靠得多。
    """
    system_name = ""
    mgmt: List[str] = []
    i = 0
    total = len(payload)
    while i + 2 <= total:
        header = (payload[i] << 8) | payload[i + 1]
        tlv_type = header >> 9
        tlv_len = header & 0x1FF
        body = payload[i + 2:i + 2 + tlv_len]
        i += 2 + tlv_len
        if tlv_type == 0:
            break
        if len(body) < tlv_len:
            break
        if tlv_type == 5 and not system_name:
            system_name = _clean_name(body.decode("utf-8", "replace"))
        elif tlv_type == 8 and len(body) >= 2:
            addr_len = body[0]
            addr_sub = body[1]
            addr = body[2:2 + addr_len]
            if addr_sub == 1 and len(addr) == 4:
                ip = ".".join(str(b) for b in addr)
                if _ok_ip(ip) and ip not in mgmt:
                    mgmt.append(ip)
    return system_name, mgmt


def parse_mdns_names(raw: bytes, limit: int = 4) -> List[str]:
    """从 mDNS/DNS 问题段里读出 `iDRAC-XXXX._http._tcp.local` 这类名字。"""
    names: List[str] = []
    if len(raw) < 12:
        return names
    try:
        qdcount = int.from_bytes(raw[4:6], "big")
    except (IndexError, ValueError):
        return names
    pos = 12
    for _ in range(min(max(qdcount, 0), limit)):
        labels: List[str] = []
        while pos < len(raw):
            length = raw[pos]
            pos += 1
            if length == 0:
                break
            if length & 0xC0:            # 压缩指针，问题段里不该出现，遇到就放弃
                pos += 1
                break
            chunk = raw[pos:pos + length]
            pos += length
            labels.append(chunk.decode("latin-1", "replace"))
            if len(labels) > 8:
                break
        pos += 4                          # qtype + qclass
        name = ".".join(x for x in labels if x)
        if name and name not in names:
            names.append(_clean_name(name))
    return names


def classify(pkt: object, our_macs: Sequence[str] = (),
             our_ips: Sequence[str] = ()) -> List[Observation]:
    """把抓到的包翻译成 [(IP, MAC, 来源)]。自己发的一律丢掉。"""
    out: List[Observation] = []
    mine_mac = {m.lower() for m in our_macs if m}
    mine_ip = {ip for ip in our_ips if ip}

    try:
        src_mac = str(getattr(pkt, "src", "") or "").lower()
    except Exception:                     # noqa: BLE001 - 畸形包什么都有可能
        src_mac = ""
    if src_mac and src_mac in mine_mac:
        return out                           # 自己发的广播

    # ---- ARP：最直接，能拿到 (IP, MAC) 的对应关系 ----
    try:
        from scapy.layers.l2 import ARP  # type: ignore

        has_arp = pkt.haslayer(ARP)  # type: ignore[attr-defined]
    except Exception:                     # noqa: BLE001
        has_arp = False
    if has_arp:
        try:
            arp = pkt[ARP]                # type: ignore[index]
            psrc = str(arp.psrc)
            pdst = str(arp.pdst)
            hwsrc = str(arp.hwsrc).lower()
            op = int(arp.op)
        except Exception:                 # noqa: BLE001
            return out
        if not hwsrc or hwsrc in mine_mac or hwsrc == "00:00:00:00:00:00":
            return out
        if psrc == pdst and _ok_ip(psrc):
            if psrc in mine_ip:
                return out
            out.append(Observation(psrc, hwsrc, "arp-announce", "主动宣告地址（刚上线）"))
        elif psrc in ("0.0.0.0", "") and _ok_ip(pdst) and pdst not in mine_ip:
            out.append(Observation(pdst, hwsrc, "arp-probe",
                                   "正在确认 %s 有没有人用（准备使用这个地址）" % pdst))
        elif _ok_ip(psrc) and psrc not in mine_ip:
            out.append(Observation(psrc, hwsrc, "arp",
                                   "ARP %s" % ("请求" if op == 1 else "应答")))
        return out

    # ---- LLDP：自报系统名 + 管理地址 ----
    try:
        ether_type = int(getattr(pkt, "type", 0) or 0)
    except Exception:                     # noqa: BLE001
        ether_type = 0
    if ether_type == 0x88CC:
        payload = b""
        try:
            payload = bytes(pkt.payload)  # type: ignore[attr-defined]
        except Exception:                 # noqa: BLE001
            payload = b""
        name, mgmt = parse_lldp(payload)
        for ip in mgmt:
            if ip in mine_ip:
                continue
            out.append(Observation(ip, src_mac, "lldp",
                                   "LLDP 自报%s" % ("：" + name if name else ""),
                                   hostname=name))
        if not mgmt and src_mac:
            out.append(Observation("", src_mac, "lldp",
                                   "LLDP 邻居%s" % ("：" + name if name else ""),
                                   hostname=name))
        return out

    # ---- mDNS / SSDP / NBNS ----
    try:
        from scapy.layers.inet import IP, UDP  # type: ignore

        has_udp = pkt.haslayer(UDP) and pkt.haslayer(IP)  # type: ignore[attr-defined]
    except Exception:                     # noqa: BLE001
        has_udp = False
    if has_udp:
        try:
            udp = pkt[UDP]                # type: ignore[index]
            sport, dport = int(udp.sport), int(udp.dport)
            ip = str(pkt[IP].src)         # type: ignore[index]
            payload = bytes(udp.payload)
        except Exception:                 # noqa: BLE001
            return out
        if not _ok_ip(ip) or ip in mine_ip:
            return out
        if sport == 5353 or dport == 5353:
            names = parse_mdns_names(payload)
            host = ""
            for name in names:
                low = name.lower()
                if low.endswith(".local") or "._" in low or "." not in low:
                    host = name.split("._")[0]
                    if host.endswith(".local"):
                        host = host[:-6]
                    break
            out.append(Observation(ip, src_mac, "mdns",
                                   "mDNS%s" % ("：" + names[0] if names else ""),
                                   hostname=host))
        elif sport == 1900 or dport == 1900:
            out.append(Observation(ip, src_mac, "ssdp", "SSDP"))
        elif sport == 137 or dport == 137:
            out.append(Observation(ip, src_mac, "nbns", "NetBIOS 名字服务"))
        return out

    return out


# ----------------------------------------------------------------------
# 抓包 / 扫描：默认实现，单元测试里会被替换掉
# ----------------------------------------------------------------------

def sniff_slice(iface: str, seconds: float, on_packet: Callable[[object], None],
                stop: threading.Event) -> str:
    """抓一小段时间的包。返回错误信息（空串表示正常）。"""
    try:
        from scapy.all import sniff  # type: ignore
    except ImportError:
        return "没有安装 scapy，无法被动侦听"

    def prn(pkt: object) -> None:
        if stop.is_set():
            return
        try:
            on_packet(pkt)
        except Exception:                 # noqa: BLE001 - 单个坏包不能中断扫描
            pass

    dev = I.scapy_iface(iface)
    try:
        sniff(iface=dev, timeout=seconds, prn=prn, store=False,
              stop_filter=lambda _p: stop.is_set(), filter=BPF_FILTER)
        return ""
    except Exception:                     # noqa: BLE001
        # 过滤器要靠 tcpdump 编译，个别机器没有；改成收全量再在 Python 里挑
        try:
            sniff(iface=dev, timeout=seconds, prn=prn, store=False,
                  stop_filter=lambda _p: stop.is_set())
            return ""
        except Exception as exc:          # noqa: BLE001
            return "抓包失败：%s" % exc


def arp_scan(iface: str, targets: object,
             timeout: float = SWEEP_TIMEOUT) -> List[Tuple[str, str]]:
    """`targets` 可以是 CIDR，也可以是一串具体 IP（猜地址时就是后者）。"""
    return discover.arp_sweep(iface, targets, timeout=timeout)


def _has_scapy() -> bool:
    from .engines import has_scapy

    try:
        return has_scapy()
    except Exception:                     # noqa: BLE001 - find_spec 也可能炸
        return False


# ----------------------------------------------------------------------
# 临时地址别名登记表（退出时统一摘掉，不留垃圾）
# ----------------------------------------------------------------------

_ALIAS_LOCK = threading.Lock()
_LIVE_ALIASES: List[Tuple[str, str]] = []


def aliases_add(iface_name: str, ip: str) -> bool:
    if I.add_alias(iface_name, ip):
        with _ALIAS_LOCK:
            if (iface_name, ip) not in _LIVE_ALIASES:
                _LIVE_ALIASES.append((iface_name, ip))
        return True
    return False


def aliases_cleanup() -> List[str]:
    """把我们加过的临时地址全摘掉，返回摘掉的列表。"""
    with _ALIAS_LOCK:
        items = list(_LIVE_ALIASES)
        _LIVE_ALIASES.clear()
    removed: List[str] = []
    for iface_name, ip in items:
        if I.remove_alias(iface_name, ip):
            removed.append("%s %s" % (iface_name, ip))
    return removed


def aliases_live() -> List[Tuple[str, str]]:
    with _ALIAS_LOCK:
        return list(_LIVE_ALIASES)


# ----------------------------------------------------------------------
# 一个扫描任务
# ----------------------------------------------------------------------

@dataclass
class ScanTask:
    iface: str = ""
    cidrs: List[str] = field(default_factory=list)
    passive: bool = True
    guess: bool = True              # 先试一批常见出厂地址（几十个包，秒级）
    neighbors: bool = True          # IPv6 邻居 + 广播应答（不看 IPv4 配置）
    active: bool = True
    probe: bool = True
    duration: float = PASSIVE_DEFAULT
    state: str = "running"          # running / done / stopped / error
    phase: str = ""                 # passive / sweep / alias / probe
    message: str = ""
    errors: List[str] = field(default_factory=list)
    hits: Dict[str, Hit] = field(default_factory=dict)
    aliases: List[Dict[str, str]] = field(default_factory=list)
    # IPv6 邻居：IPv4 配成什么都不知道时，这是唯一「不靠猜」的入口
    v6: List[Dict[str, str]] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0
    total: int = 0
    done: int = 0
    stop_requested: bool = False

    def to_dict(self) -> Dict[str, object]:
        rows = sorted(self.hits.values(), key=lambda h: (-h.score, _ip_key(h.ip)))
        return {
            "state": self.state,
            "phase": self.phase,
            "message": self.message,
            "iface": self.iface,
            "cidrs": list(self.cidrs),
            "passive": self.passive,
            "guess": self.guess,
            "neighbors": self.neighbors,
            "active": self.active,
            "probe": self.probe,
            "duration": self.duration,
            "started_at": self.started_at,
            "elapsed": round((self.finished_at or time.time()) - self.started_at, 1)
            if self.started_at else 0,
            "total": self.total,
            "done": self.done,
            "errors": list(self.errors),
            "aliases": list(self.aliases),
            "v6": list(self.v6),
            "hits": [h.to_dict() for h in rows],
            "stop_requested": self.stop_requested,
        }


def _ip_key(ip: str) -> Tuple[int, ...]:
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999,)


class Scanner:
    """同一时间只跑一个扫描；结果保存在 self.task 里给界面轮询。"""

    def __init__(self, probe_fn: Optional[Callable[..., object]] = None,
                 sniff_fn: Optional[Callable[..., str]] = None,
                 scan_fn: Optional[Callable[..., List[Tuple[str, str]]]] = None,
                 iface_fn: Optional[Callable[[str], Optional[I.Interface]]] = None,
                 log_fn: Optional[Callable[[str, str], None]] = None,
                 v6_fn: Optional[Callable[..., List[Tuple[str, str]]]] = None,
                 bcast_fn: Optional[Callable[..., List[str]]] = None) -> None:
        # 全部可注入：单元测试不用真抓包、真发 ARP
        self._log_fn = log_fn
        self._probe_fn = probe_fn or discover.probe
        self._sniff_fn = sniff_fn or sniff_slice
        self._scan_fn = scan_fn or arp_scan
        self._iface_fn = iface_fn or I.find_by_name
        self._v6_fn = v6_fn or discover.ipv6_neighbors
        self._bcast_fn = bcast_fn or discover.broadcast_probe
        self._lock = threading.RLock()
        self._start_lock = threading.Lock()   # 串行化 start()，避免两次点击同时建任务
        self._stop = threading.Event()
        self._task: Optional[ScanTask] = None
        self._thread: Optional[threading.Thread] = None

    # ---------------- 对外 ----------------

    @property
    def task(self) -> Optional[ScanTask]:
        with self._lock:
            return self._task

    def running(self) -> bool:
        with self._lock:
            return bool(self._task and self._task.state == "running")

    def start(self, cfg: Dict[str, object]) -> Dict[str, object]:
        with self._start_lock:
            return self._start_locked(cfg)

    def _start_locked(self, cfg: Dict[str, object]) -> Dict[str, object]:
        with self._lock:
            if self._task is not None and self._task.state == "running":
                raise ScanBusy("上一次扫描还没结束，等它跑完或先点停止")

        iface_name = str(cfg.get("iface") or "").strip()
        if not iface_name:
            raise ScanError("先选一张网卡（插着 BMC 网线的那张）")
        iface = self._iface_fn(iface_name)
        if iface is None:
            raise ScanError("找不到网卡 %s（可能刚拔掉，点一下刷新）" % iface_name)

        # 注意：不能直接 bool()，字符串 "false" 也是 True，
        # 界面传的是真布尔，但 HTTP 接口是边界，得自己判
        passive = _as_bool(cfg.get("passive"), True)
        guess = _as_bool(cfg.get("guess"), True)
        neighbors = _as_bool(cfg.get("neighbors"), True)
        active = _as_bool(cfg.get("active"), True)
        probe = _as_bool(cfg.get("probe"), True)
        if not passive and not active and not guess and not neighbors:
            raise ScanError("被动侦听 / 猜地址 / 邻居探测 / 扫网段，至少开一个")

        try:
            duration = float(cfg.get("duration") or PASSIVE_DEFAULT)
        except (TypeError, ValueError):
            duration = PASSIVE_DEFAULT
        duration = max(1.0, min(PASSIVE_MAX, duration))

        cidrs: List[str] = []
        if active:
            cidrs = self._parse_cidrs(cfg.get("cidrs"), iface)
            if not cidrs:
                cidrs = default_cidrs(iface)

        if not I.is_root():
            raise ScanError(
                "IP 探测要管理员权限（抓 ARP 包、临时改网卡地址）。"
                + ("请右键 bmcd.cmd，选「以管理员身份运行」。"
                   if winnet.IS_WIN else
                   "请点右上角「退出」，再双击一次 App，在系统弹框里输入密码。"))
        if passive and not _has_scapy():
            raise ScanError("缺少 scapy：被动侦听靠它抓 ARP/mDNS/LLDP。"
                            "bmcd 首次运行会自动装；也可以手工 pip install scapy")
        if active and not winnet.IS_WIN and not _has_scapy():
            raise ScanError("缺少 scapy：扫网段靠它发 ARP 广播。"
                            "bmcd 首次运行会自动装；也可以手工 pip install scapy")
        win_note = ""
        if winnet.IS_WIN and passive and not winnet.has_npcap():
            # Windows 上没 Npcap 抓不了包，但 SendARP 扫网段照样能用
            passive = False
            win_note = "没装 Npcap，跳过被动侦听；扫网段照常（SendARP）"

        batches = 0
        for cidr in cidrs:
            batches += len(_chunks(ipaddress.IPv4Network(cidr)))
        task = ScanTask(
            iface=iface_name,
            cidrs=cidrs,
            passive=passive,
            guess=guess,
            neighbors=neighbors,
            active=active,
            probe=probe,
            duration=duration,
            started_at=time.time(),
        )
        task.total = ((batches if active else 0)
                      + (1 if passive else 0)
                      + (1 if guess else 0)
                      + (1 if neighbors else 0))
        task.message = "准备中…"
        if win_note:
            task.errors.append(win_note)
        with self._lock:
            self._task = task
        self._stop.clear()
        self._log("info", "开始 IP 探测（%s）：%s" % (iface_name, self._describe(task)))
        self._thread = threading.Thread(target=self._run, args=(task,),
                                        name="bmcd-scan", daemon=True)
        self._thread.start()
        return task.to_dict()

    def stop(self) -> Dict[str, object]:
        with self._lock:
            task = self._task
        if task is None:
            return {"ok": True, "state": "idle"}
        task.stop_requested = True
        self._stop.set()
        return {"ok": True, "state": task.state}

    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            task = self._task
        if task is None:
            return {"state": "idle", "hits": [], "errors": [], "aliases": [],
                    "message": "", "phase": "", "total": 0, "done": 0}
        return task.to_dict()

    def cleanup(self) -> List[str]:
        """摘掉我们加过的临时地址（停止/退出时调用）。

        扫描还在跑就先把停掉、等它收尾，否则它可能在我们清完之后又加一个。
        """
        with self._lock:
            task = self._task
        if task is not None and task.state == "running":
            self.stop()
            deadline = time.time() + 3.0
            while time.time() < deadline and task.state == "running":
                time.sleep(0.05)
        removed = aliases_cleanup()
        with self._lock:
            task = self._task
        if task is not None:
            task.aliases = []
        return removed

    # ---------------- 内部 ----------------

    @staticmethod
    def _parse_cidrs(raw: object, iface: I.Interface) -> List[str]:
        items: List[str] = []
        if isinstance(raw, str):
            items = [x.strip() for x in re.split(r"[,\s]+", raw) if x.strip()]
        elif isinstance(raw, (list, tuple)):
            items = [str(x).strip() for x in raw if str(x).strip()]
        out: List[str] = []
        for item in items:
            if not item:
                continue
            if "/" not in item:
                item += "/24"
            try:
                net = ipaddress.IPv4Network(item, strict=False)
            except ValueError:
                raise ScanError("网段写法不对：%s（示例 192.168.0.0/24）" % item)
            if net.prefixlen < 16:
                raise ScanError(
                    "%s 太大了：ARP 只能问同一根线上的设备，扫 /%d 只会白等。"
                    "最大的实用范围是 /16（比如 192.168.0.0/16，约 1～2 分钟）。"
                    % (item, net.prefixlen))
            text = str(net)
            if text not in out:
                out.append(text)
        total = 0
        for text in out:
            total += max(0, ipaddress.IPv4Network(text).num_addresses - 2)
        if total > SWEEP_MAX_TOTAL:
            raise ScanError("一共 %d 个地址，超过一次上限 %d。分几次扫，或者先用"
                            "「只侦听，等 BMC 自己喊」那招" % (total, SWEEP_MAX_TOTAL))
        # 本机自己那个网段排在最前面，用户最可能是想扫它
        if iface.ipv4 and not iface.is_link_local:
            try:
                own = str(ipaddress.IPv4Network(
                    "%s/%s" % (iface.ipv4, I.mask_to_dotted(iface.netmask)), strict=False))
                if own in out:
                    out.remove(own)
                    out.insert(0, own)
            except ValueError:
                pass
        return out

    def _log(self, level: str, text: str) -> None:
        if self._log_fn is None:
            return
        try:
            self._log_fn(level, text)
        except Exception:                 # noqa: BLE001 - 日志失败不能影响扫描
            pass

    def _set(self, task: ScanTask, **kw: object) -> None:
        with self._lock:
            for key, value in kw.items():
                setattr(task, key, value)

    def _record(self, task: ScanTask, obs: Observation) -> None:
        if not _ok_ip(obs.ip):
            return
        with self._lock:
            hit = task.hits.get(obs.ip)
            if hit is None:
                if len(task.hits) >= MAX_HITS:
                    return
                hit = Hit(ip=obs.ip, first_seen=time.time())
                task.hits[obs.ip] = hit
            if obs.mac:
                if not hit.mac:
                    hit.mac = obs.mac
                elif obs.mac != hit.mac and obs.mac not in hit.alt_macs:
                    hit.alt_macs.append(obs.mac)
                    hit.evidence.append("同一个 IP 出现两个 MAC（可能 IP 冲突）")
            if obs.source and obs.source not in hit.sources:
                hit.sources.append(obs.source)
            if obs.hostname and not hit.hostname:
                hit.hostname = obs.hostname
            if obs.note and obs.note not in hit.evidence:
                hit.evidence.append(obs.note)
            if not hit.vendor:
                vendor = vendors.oui_vendor(hit.mac)
                if vendor:
                    hit.vendor = vendor
                    hit.confidence = "低"

    def _run(self, task: ScanTask) -> None:
        try:
            iface = self._iface_fn(task.iface)
            own_ips: Set[str] = set(I.addresses(task.iface)) if iface else set()
            our_macs = {iface.mac} if iface and iface.mac else set()
            if iface is None:
                task.errors.append("网卡 %s 已经不在了" % task.iface)
            elif not iface.has_link:
                task.errors.append("%s 现在没有链路（status=%s），先插好网线"
                                   % (iface.name, iface.link or "?"))
            elif iface.is_default_route:
                task.errors.append("%s 是上网用的默认路由口，扫到的东西可能是你家里的设备"
                                   % iface.name)

            if task.passive:
                self._phase_passive(task, our_macs, own_ips)

            # 猜出厂地址最便宜（几十个包），先打；命中就不用盲扫大网段了
            if task.guess and not self._stop.is_set():
                self._phase_guess(task, our_macs)

            # IPv6 邻居 + 广播应答：完全不看对方的 IPv4 配成什么
            if task.neighbors and not self._stop.is_set():
                self._phase_neighbors(task, our_macs)

            if task.active and not self._stop.is_set():
                self._phase_active(task, our_macs)

            # 顺序很重要：先加临时地址，再探测。
            # 扫到的机器如果在本机没地址的网段里，没有这条路由就连不上，
            # 反过来的话「识别厂商/端口」会全部落空（看起来像设备没有管理口）。
            if not task.stop_requested:
                self._phase_alias(task)

            if task.probe and not self._stop.is_set():
                self._phase_probe(task)

            with self._lock:
                task.state = "stopped" if task.stop_requested else "done"
                task.phase = ""
                if task.state == "stopped":
                    task.message = "已停止"
                elif task.hits:
                    task.message = "扫到 %d 台" % len(task.hits)
                else:
                    task.message = "没扫到设备"
                task.finished_at = time.time()
            self._log("warn" if not task.hits else "ok", self._summarise(task))
        except Exception as exc:          # noqa: BLE001 - 后台线程不能把异常抛出去
            with self._lock:
                task.state = "error"
                task.phase = ""
                task.message = "扫描出错：%s" % exc
                task.finished_at = time.time()
            self._log("err", "IP 探测出错：%s" % exc)

    @staticmethod
    def _describe(task: ScanTask) -> str:
        bits: List[str] = []
        if task.passive:
            bits.append("被动侦听 %ds" % int(task.duration))
        if task.guess:
            bits.append("试 %d 个常见出厂地址" % len(GUESS_TARGETS))
        if task.neighbors:
            bits.append("IPv6/广播探测")
        if task.active and task.cidrs:
            bits.append("ARP 扫 " + "、".join(task.cidrs))
        return "，".join(bits) or "无"

    @staticmethod
    def _summarise(task: ScanTask) -> str:
        if not task.hits:
            return "IP 探测结束：没扫到设备"
        rows = sorted(task.hits.values(), key=lambda h: (-h.score, _ip_key(h.ip)))
        shown = ["%s%s" % (h.ip, "（%s）" % h.vendor if h.vendor else "") for h in rows[:6]]
        more = "" if len(rows) <= 6 else " 等 %d 台" % len(rows)
        text = "IP 探测结束：%s" % "，".join(shown) + more
        if task.aliases:
            text += "；已临时加地址 " + "、".join(a["ip"] for a in task.aliases)
        if task.v6:
            text += "；另有 %d 个 IPv6 邻居可直连" % len(task.v6)
        return text

    # ---- 三个阶段 ----

    def _phase_passive(self, task: ScanTask, our_macs: Set[str],
                       own_ips: Set[str]) -> None:
        self._set(task, phase="passive",
                  message="被动侦听 %d 秒（抓 ARP / mDNS / LLDP）…" % int(task.duration))
        deadline = time.time() + task.duration
        stop = self._stop

        def on_packet(pkt: object) -> None:
            for obs in classify(pkt, our_macs=our_macs, our_ips=own_ips):
                self._record(task, obs)

        while not stop.is_set() and time.time() < deadline:
            left = deadline - time.time()
            if left <= 0:
                break
            started = time.time()
            err = self._sniff_fn(task.iface, min(SLICE, max(0.2, left)),
                                 on_packet, stop)
            if err:
                task.errors.append(err)
                break
            if time.time() - started < 0.05:
                # 抓包立刻返回了（比如没有权限/接口消失），别把 CPU 打满
                stop.wait(0.05)
            with self._lock:
                task.message = "被动侦听中… 还剩 %d 秒，已发现 %d 台" % (
                    max(0, int(deadline - time.time())), len(task.hits))
        with self._lock:
            task.done += 1
            task.message = "被动侦听完成，发现 %d 台" % len(task.hits)
        self._log("info", "被动侦听 %ds 结束：%d 台" % (int(task.duration), len(task.hits)))

    def _phase_guess(self, task: ScanTask, our_macs: Set[str]) -> None:
        """先打一串「常见出厂地址」：几十个包、1 秒内出结果。

        BMC 的地址可能是任何值，但绝大多数是厂商默认值或常见的规划习惯。
        这比盲扫一个大网段便宜两个数量级，命中率却更高，所以放最前面。
        """
        total = len(GUESS_TARGETS)
        self._set(task, phase="guess", message="试 %d 个常见 BMC 出厂地址…" % total)
        for start in range(0, total, CHUNK_HOSTS):
            if self._stop.is_set():
                return
            batch = list(GUESS_TARGETS[start:start + CHUNK_HOSTS])
            try:
                found = self._scan_fn(task.iface, batch)
            except Exception as exc:      # noqa: BLE001
                task.errors.append("猜地址失败：%s" % exc)
                return
            for ip, mac in found:
                if mac and mac.lower() in our_macs:
                    continue
                self._record(task, Observation(ip, mac, "guess", "常见 BMC 出厂地址"))
            with self._lock:
                task.message = "试常见出厂地址… %d/%d，命中 %d 台" % (
                    min(start + CHUNK_HOSTS, total), total, len(task.hits))
        with self._lock:
            task.done += 1
            task.message = "常见出厂地址试完，命中 %d 台" % len(task.hits)

    def _phase_neighbors(self, task: ScanTask, our_macs: Set[str]) -> None:
        """两条「不看对方 IPv4 配置」的路子。

        1. IPv6 all-nodes 多播（ff02::1）：只要对端开了 IPv6 就一定回，
           回来的源地址就是它自己 —— 跟它 IPv4 是 192.168.x 还是 10.x 无关。
           拿到 link-local 就能直接 https://[fe80::…%en7] 打开管理页。
        2. 往 224.0.0.1 / 255.255.255.255 发 ICMP：不少实现在收到 all-hosts
           的 echo 时会回，回了就暴露它的 IPv4。
        """
        self._set(task, phase="neighbors", message="探 IPv6 邻居和广播应答…")
        if self._stop.is_set():
            return

        try:
            pairs = self._v6_fn(task.iface, timeout=3.0)
        except Exception as exc:          # noqa: BLE001
            task.errors.append("IPv6 邻居探测失败：%s" % exc)
            pairs = []
        with self._lock:
            for addr, mac in pairs:
                if not addr:
                    continue
                if any(item.get("addr") == addr for item in task.v6):
                    continue
                task.v6.append({
                    "addr": addr,
                    "mac": (mac or "").lower(),
                    "how": "IPv6 all-nodes（ff02::1）",
                    "link": _v6_url(addr, task.iface),
                })
            if task.v6:
                task.message = "发现 %d 个 IPv6 邻居" % len(task.v6)

        try:
            ips = self._bcast_fn(task.iface, timeout=2.0)
        except Exception as exc:          # noqa: BLE001
            task.errors.append("广播探测失败：%s" % exc)
            ips = []
        for ip in ips:
            self._record(task, Observation(ip, "", "broadcast", "广播 ICMP 应答"))

        with self._lock:
            task.done += 1
            bits = []
            if task.v6:
                bits.append("%d 个 IPv6 邻居" % len(task.v6))
            if ips:
                bits.append("%d 个广播应答" % len(ips))
            task.message = "，".join(bits) or "没有 IPv6 邻居/广播应答"
        if task.v6 or ips:
            self._log("info", "邻居探测：%s" % (task.message or ""))

    def _phase_active(self, task: ScanTask, our_macs: Set[str]) -> None:
        for index, cidr in enumerate(task.cidrs, 1):
            if self._stop.is_set():
                return
            try:
                batches = _chunks(ipaddress.IPv4Network(cidr))
            except ValueError:
                task.errors.append("%s 不是合法网段" % cidr)
                continue
            for bindex, batch in enumerate(batches, 1):
                if self._stop.is_set():
                    return
                self._set(
                    task, phase="sweep",
                    message="ARP 扫描 %s（%d/%d 段，第 %d/%d 批，已发现 %d 台）…"
                            % (cidr, index, len(task.cidrs), bindex, len(batches),
                               len(task.hits)))
                try:
                    found = self._scan_fn(task.iface, batch)
                except Exception as exc:  # noqa: BLE001
                    task.errors.append("%s 扫描失败：%s" % (batch, exc))
                    found = []
                for ip, mac in found:
                    if mac and mac.lower() in our_macs:
                        continue             # 本机自己回的，不算设备
                    self._record(task, Observation(ip, mac, "arp-scan", "ARP 扫描应答"))
                with self._lock:
                    task.done += 1
        with self._lock:
            task.message = "网段扫描完成，共 %d 台" % len(task.hits)
        self._log("info", "ARP 扫描结束：共 %d 台" % len(task.hits))

    def _phase_probe(self, task: ScanTask) -> None:
        with self._lock:
            hits = sorted(task.hits.values(), key=lambda h: _ip_key(h.ip))
        if not hits:
            return
        if len(hits) > MAX_PROBE:
            task.errors.append("设备太多（%d 台），只识别前 %d 台；其余只看 IP/MAC"
                               % (len(hits), MAX_PROBE))
            hits = hits[:MAX_PROBE]
        self._set(task, phase="probe",
                  message="识别 %d 台设备（端口 / 证书 / 页面）…" % len(hits))
        pool = ThreadPoolExecutor(max_workers=SWEEP_WORKERS)
        try:
            futures = {pool.submit(self._probe_fn, hit.ip, timeout=PROBE_TIMEOUT): hit
                       for hit in hits}
            for future in as_completed(futures):
                hit = futures[future]
                try:
                    fp = future.result()
                except Exception:         # noqa: BLE001
                    fp = None
                if fp is not None:
                    self._apply(task, hit, fp)
                with self._lock:
                    task.message = "识别中… %d/%d" % (
                        sum(1 for h in task.hits.values() if h.probed), len(task.hits))
        finally:
            pool.shutdown(wait=False)

    def _apply(self, task: ScanTask, hit: Hit, fp: object) -> None:
        ports = list(getattr(fp, "ports", []) or [])
        identity = getattr(fp, "identity", None)
        with self._lock:
            hit.probed = True
            hit.alive = bool(getattr(fp, "alive", False))
            hit.ports = ports
            if not hit.mac:
                hit.mac = str(getattr(fp, "mac", "") or "")
            url = str(getattr(fp, "url", "") or "")
            if url:
                hit.url = url
            tls = str(getattr(fp, "tls_cn", "") or "")
            http = getattr(fp, "http", None)
            summary = ""
            try:
                summary = str(fp.summary())    # type: ignore[attr-defined]
            except Exception:                  # noqa: BLE001
                summary = ""
            if summary:
                hit.summary = summary
            arp_error = str(getattr(fp, "arp_error", "") or "")
            if arp_error:
                hit.arp_error = arp_error
            if identity is not None and getattr(identity, "known", False):
                hit.vendor = str(getattr(identity, "vendor", "") or hit.vendor)
                hit.confidence = str(getattr(identity, "confidence", "") or "")
                creds = list(getattr(identity, "creds", []) or [])
                if creds:
                    hit.creds = creds
                for item in getattr(identity, "evidence", []) or []:
                    text = str(item)
                    if text and text not in hit.evidence:
                        hit.evidence.append(text)
            elif hit.mac and not hit.vendor:
                vendor = vendors.oui_vendor(hit.mac)
                if vendor:
                    hit.vendor = vendor
                    hit.confidence = "低"
            title = ""
            if http is not None:
                title = str(getattr(http, "title", "") or "")
            if title and not hit.hostname:
                hit.hostname = title
            if tls and ("证书 CN=" + tls) not in hit.evidence:
                hit.evidence.append("证书 CN=%s" % tls)
            hit.score = _score(hit)

    def _phase_alias(self, task: ScanTask) -> None:
        """扫到的机器如果跟本机不同网段，加个临时地址，否则连不上。"""
        with self._lock:
            hits = list(task.hits.values())
        if not hits:
            return
        self._set(task, phase="alias", message="为扫到的网段加临时地址…")
        existing = set(I.addresses(task.iface))
        by_net: Dict[str, List[str]] = {}
        for hit in hits:
            try:
                net = str(ipaddress.IPv4Network("%s/24" % hit.ip, strict=False))
            except ValueError:
                continue
            by_net.setdefault(net, []).append(hit.ip)
        for cidr, ips in by_net.items():
            if self._stop.is_set():
                return
            if len(task.aliases) >= MAX_ALIASES:
                task.errors.append("要加的临时地址超过 %d 个，剩下的网段没加"
                                   % MAX_ALIASES)
                break
            net = ipaddress.IPv4Network(cidr)
            if any(_in_net(ip, net) for ip in existing):
                continue
            pick = _pick_alias_ip(net, set(ips) | existing)
            if not pick:
                task.errors.append("%s 找不到空闲地址做临时网关" % cidr)
                continue
            if aliases_add(task.iface, pick):
                task.aliases.append({"iface": task.iface, "ip": pick, "cidr": cidr})
                existing.add(pick)
            else:
                task.errors.append("给 %s 加临时地址 %s 失败（要 root）" % (task.iface, pick))
        if task.aliases:
            task.message = "已临时加地址 %s，可以直接打开管理页" % "，".join(
                a["ip"] for a in task.aliases)
            self._log("info", "已临时加地址 %s（退出时自动摘掉）" % "、".join(
                "%s %s" % (a["iface"], a["ip"]) for a in task.aliases))


def _chunks(net: "ipaddress.IPv4Network") -> List[str]:
    """把一个大网段切成每批 CHUNK_HOSTS 个地址的小段。

    为什么要切：一个 /16 是 65534 个地址，一次性丢给 scapy 会做 6 万多个包，
    期间既没法报进度也没法中断，用户会以为程序卡死。切成 /23 之后每批 512 个，
    一秒左右一批，能显示「第 37/128 批」，也能随时停。
    """
    if net.num_addresses <= CHUNK_HOSTS + 2:
        return [str(net)]
    prefix = 32 - (CHUNK_HOSTS.bit_length() - 1)      # 512 → /23
    if net.prefixlen >= prefix:
        return [str(net)]
    return [str(sub) for sub in net.subnets(new_prefix=prefix)]


def _as_bool(value: object, default: bool = True) -> bool:
    """JSON 里的布尔可能是 true/false，也可能是 "false"/"0"/"no"。"""
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() not in ("", "0", "false", "no", "off")
    return bool(value)


_URL_SAFE_ZONE = re.compile(r"^[A-Za-z0-9._-]+$")


def _v6_url(addr: str, iface: str) -> str:
    """link-local IPv6 要带 zone id（%en7）浏览器才连得上。

    zone 只能是 URL 安全的接口名：mac 上 `en7` 没问题，Windows 上
    网卡显示名可能是「以太网 2」（带空格和中文），拼进去就是一个坏 URL。
    这种情况宁可不带 zone —— 界面上会提示「部分浏览器不认这种写法」。
    """
    text = (addr or "").strip()
    if not text:
        return ""
    host = text.split("%", 1)[0]
    zone = (iface or "").strip()
    if host.lower().startswith("fe80") and _URL_SAFE_ZONE.match(zone):
        return "https://[%s%%25%s]/" % (host, zone)
    return "https://[%s]/" % host


def _in_net(ip: str, net: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.IPv4Address(ip) in net
    except ValueError:
        return False


def _pick_alias_ip(net: ipaddress.IPv4Network, used: Set[str]) -> str:
    for host in ALIAS_HOSTS:
        try:
            cand = str(net.network_address + host)
        except (ipaddress.AddressValueError, IndexError):
            continue
        if not _in_net(cand, net):
            continue
        if cand in used or cand == str(net.broadcast_address) or cand == str(net.network_address):
            continue
        return cand
    for addr in list(net.hosts())[:MAX_HOSTS]:
        cand = str(addr)
        if cand not in used:
            return cand
    return ""


def _score(hit: Hit) -> int:
    score = 0
    if hit.vendor:
        score += 10
    if hit.confidence == "高":
        score += 6
    if 623 in hit.ports:
        score += 6                       # IPMI 活着，这就是台服务器 BMC
    if hit.url:
        score += 4
    if hit.hostname:
        score += 3
    if hit.confidence == "中":
        score += 2
    if 22 in hit.ports and not hit.url:
        score += 1
    return score


# ----------------------------------------------------------------------
# 出厂静态网段（GUI 里的默认值）
# ----------------------------------------------------------------------

FACTORY_CIDRS = [
    "192.168.0.0/24",
    "192.168.1.0/24",
    "192.168.100.0/24",
    "10.0.0.0/24",
    "172.16.0.0/24",
]


def default_cidrs(iface: Optional[I.Interface]) -> List[str]:
    out = list(FACTORY_CIDRS)
    if iface is not None and iface.ipv4 and not iface.is_link_local:
        try:
            own = str(ipaddress.IPv4Network(
                "%s/%s" % (iface.ipv4, I.mask_to_dotted(iface.netmask)), strict=False))
            if own not in out and ipaddress.IPv4Network(own).num_addresses <= MAX_HOSTS + 2:
                out.insert(0, own)
        except ValueError:
            pass
    return out
