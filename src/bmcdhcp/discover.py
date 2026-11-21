"""BMC 探测：拿到 IP 之后告诉你「这是什么机器、管理页面在哪、默认账号大概是什么」。

手段（从强到弱）：
  1. TCP 端口存活（443/80/8443/623/22）
  2. TLS 证书 CN —— BMC 自签证书里常带 iDRAC-XXXX / iLO-XXXX / XCC-XXXX 这类强特征
  3. HTTP 标题 / Server 头 / 跳转地址
  4. ASF/RMCP presence ping（UDP 623）—— IPMI 栈活着会有应答
  5. ARP 表取 MAC → OUI 提示
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import sys
import ssl
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import vendors
from . import winnet
from .iface import scapy_iface

IS_WINDOWS = winnet.IS_WIN

# macOS 的 arp 在 /usr/sbin（/sbin 里根本没有这个文件），Linux 常在 /usr/sbin 或 /sbin。
# 写死一条路径 + 吞掉 OSError 的话，ARP 查询会永远返回空串，MAC 列永远是「-」。
ARP_CANDIDATES = ("/usr/sbin/arp", "/sbin/arp", "/bin/arp")


def arp_binary() -> str:
    """按候选路径找可执行的 arp；都没有就退回 PATH 里找。找不到返回空串。"""
    if IS_WINDOWS:
        return "arp"
    for path in ARP_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return shutil.which("arp") or ""


ARP = arp_binary()

# 最近一次 ARP 查询的完整结果（诊断用；/api/diag 之类的接口不用再猜为什么 MAC 是空的）
LAST_ARP: Optional["ArpResult"] = None
# ARP 表整表读取的失败原因（成功时为空串）
LAST_ARP_TABLE_ERROR = ""
# 已经告警过的错误**类别** → 出现过几次。按类别（而不是含 IP 的整串）去重：
# 不然 sweep 一个 /24 就是一两百行一样的错误，等于没去重。
_ARP_WARNED: Dict[str, int] = {}
_ARP_LOCK = threading.Lock()


def arp_diag() -> Dict[str, object]:
    """ARP 这一层的自检快照：用的哪个命令、试过哪些路径、上次为什么失败。"""
    binary = ARP or arp_binary()
    with _ARP_LOCK:
        last = LAST_ARP
        warned = dict(_ARP_WARNED)
    return {
        "binary": binary,
        "candidates": list(ARP_CANDIDATES),
        "which": shutil.which("arp") or "",
        "available": bool(binary),
        "last_error": last.error if last else "",
        "last_ip": last.ip if last else "",
        "last_mac": last.mac if last else "",
        "table_error": LAST_ARP_TABLE_ERROR,
        # 每类错误出现过几次（stderr 每类只打了一行，这里给全量计数）
        "warned": warned,
    }


def _try_connect(ip: str, port: int, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def scan_ports(ip: str, ports: Optional[List[int]] = None, timeout: float = 0.8) -> List[int]:
    ports = ports or vendors.BMC_PORTS
    open_ports: List[int] = []
    with ThreadPoolExecutor(max_workers=min(16, len(ports))) as pool:
        futures = {pool.submit(_try_connect, ip, p, timeout): p for p in ports}
        for fut, port in futures.items():
            try:
                if fut.result():
                    open_ports.append(port)
            except Exception:
                pass
    return sorted(open_ports)


# ----------------------------------------------------------------------
# TLS / HTTP
# ----------------------------------------------------------------------

def _legacy_tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:  # 老 BMC 常有 TLS1.0 和弱套件
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (AttributeError, ValueError):
        pass
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


def tls_cn(ip: str, port: int = 443, timeout: float = 2.5) -> str:
    try:
        pem = ssl.get_server_certificate((ip, port), timeout=timeout)
    except (OSError, ssl.SSLError):
        return ""
    path = ""
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        info = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        for rdn in info.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    return str(value)
        alt = info.get("subjectAltName") or ()
        for kind, value in alt:
            if kind == "DNS" and value:
                return str(value)
    except Exception:
        m = re.search(r"CN\s*=\s*([^/\n,]+)", pem)
        if m:
            return m.group(1).strip()
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    return ""


@dataclass
class HttpInfo:
    port: int = 0
    scheme: str = ""
    status: str = ""
    title: str = ""
    server: str = ""
    location: str = ""
    body_marker: str = ""


def http_probe(ip: str, port: int, scheme: str, timeout: float = 2.0) -> Optional[HttpInfo]:
    sock: Optional[socket.socket] = None
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        if scheme == "https":
            sock = _legacy_tls_context().wrap_socket(raw, server_hostname=ip)
        else:
            sock = raw
        sock.settimeout(timeout)
        request = (
            "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: bmcdhcp/1.0\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n" % ip
        )
        sock.sendall(request.encode("ascii", "ignore"))
        buf = bytearray()
        while len(buf) < 200_000:
            chunk = sock.recv(16384)
            if not chunk:
                break
            buf += chunk
        text = bytes(buf).decode("utf-8", "replace")
    except (OSError, ssl.SSLError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    info = HttpInfo(port=port, scheme=scheme)
    head, _, body = text.partition("\r\n\r\n")
    lines = head.splitlines()
    if lines:
        info.status = lines[0].strip()[:120]
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        if k == "server":
            info.server = v.strip()[:80]
        elif k == "location":
            info.location = v.strip()[:120]
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
    if m:
        info.title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
    low = body.lower()
    for marker in (
        "idrac", "ilo", "supermicro", "xclarity", "ibmc", "megarac",
        "irmc", "cimc", "asmb", "asrock", "gigabyte",
    ):
        if marker in low:
            info.body_marker = marker
            break
    return info


# ----------------------------------------------------------------------
# IPMI / ASF presence ping
# ----------------------------------------------------------------------

def rmcp_ping(ip: str, timeout: float = 1.2) -> Tuple[bool, str]:
    """ASF presence ping（UDP 623）。有应答说明 IPMI 网络栈活着。"""
    asf_rand = os.urandom(7)
    body = b"\x00\x00\x11\xbe" + b"\x00\x00\x00\x00" + asf_rand
    checksum = (0x100 - (sum(body) & 0xFF)) & 0xFF
    payload = b"\x06\x00\xff\x07" + b"\x00\x00\x11\xbe" + b"\x80\x00\x00\x00" + body + bytes([checksum])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (ip, 623))
        data, _ = sock.recvfrom(2048)
        if data[:4] == b"\x06\x00\xff\x07":
            return True, "RMCP/ASF 有应答 (%d bytes)" % len(data)
        return True, "UDP/623 有应答"
    except (OSError, socket.timeout):
        return False, ""
    finally:
        sock.close()


@dataclass
class ArpResult:
    """一次 ARP 查询的结果：把「表里没有」和「根本查不了」分开。"""

    ip: str = ""
    mac: str = ""
    command: str = ""
    error: str = ""          # 空串 = 命令跑通了（mac 可能为空，那是真的没有）

    @property
    def ok(self) -> bool:
        return not self.error

    def describe(self) -> str:
        if self.error:
            return "ARP 查不了 %s：%s" % (self.ip, self.error)
        if self.mac:
            return "%s → %s" % (self.ip, self.mac)
        return "ARP 表里没有 %s（对端可能不在同网段）" % self.ip

    def category(self) -> str:
        """错误类别（去掉 IP、把数字抹平），用来做日志去重。

        `arp 返回码 1：10.0.0.9 (10.0.0.9) -- no entry` 这种整串每个 IP 都不一样，
        按它去重相当于不去重。
        """
        if not self.error:
            return ""
        text = self.error
        if self.ip:
            text = text.replace(self.ip, "<ip>")
        head = text.split("：", 1)[0]
        return re.sub(r"\d+", "<n>", head).strip() or "arp 错误"


# 「表里没有这一项」不是故障。各家的说法：
#   macOS  : "10.0.0.9 (10.0.0.9) -- no entry"（而且 rc=1）
#   BSD    : "? (10.0.0.9) at (incomplete)"
#   Windows: "Neighbor Unreachability Detection" / 空 MAC
_NO_ENTRY_RE = re.compile(
    r"--\s*no entry"
    r"|\bno entry\b"
    r"|\(incomplete\)"
    r"|incomplete\b"
    r"|neighbor unreachability"
    r"|neighbor unreachable",
    re.I,
)


def _looks_like_no_entry(*texts: str) -> bool:
    """输出里是不是「查无此项」。是的话就是正常结果，不该当错误刷出来。"""
    return any(_NO_ENTRY_RE.search(text or "") for text in texts)


def _arp_parse(text: str) -> str:
    """从 arp -n / arp -a 的输出里抠 MAC（mac 冒号、Windows 横线两种格式）。"""
    m = re.search(r"([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5}|[0-9a-f]{2}(?:-[0-9a-f]{2}){5})",
                  text, re.I)
    return m.group(1).lower().replace("-", ":") if m else ""


def _finish_arp(res: "ArpResult") -> "ArpResult":
    """ARP 查询的唯一出口：写 LAST_ARP（带锁）并按类别告警。

    以前「找不到 arp 命令」这条分支自己赋值 + 自己 return，绕过了告警 ——
    整条链就这一处失败是哑的，偏偏它又是最该被看见的那种（命令都没有）。
    """
    global LAST_ARP
    with _ARP_LOCK:
        LAST_ARP = res
    _warn_arp(res)
    return res


def arp_lookup_ex(ip: str) -> ArpResult:
    """查 ARP 并保留失败原因。

    以前这里是 `except (OSError, SubprocessError): return ""` —— 路径写错、没权限、
    命令超时，全都被吞成「这个 IP 没有 MAC」，排查时完全看不出发生过什么。
    """
    if IS_WINDOWS:
        return _finish_arp(ArpResult(ip=ip, mac=winnet.arp_lookup(ip), command="arp"))

    binary = ARP or arp_binary()
    if not binary:
        return _finish_arp(ArpResult(
            ip=ip,
            command="",
            error="找不到 arp 命令（试过 %s，PATH 里也没有）" % "、".join(ARP_CANDIDATES),
        ))

    res: ArpResult
    try:
        proc = subprocess.run([binary, "-n", ip], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        res = ArpResult(ip=ip, command=binary, error="arp 命令不存在：%s" % binary)
    except subprocess.TimeoutExpired:
        res = ArpResult(ip=ip, command=binary, error="arp 命令 10 秒没返回")
    except (OSError, subprocess.SubprocessError) as exc:
        res = ArpResult(ip=ip, command=binary, error="arp 执行失败：%s" % exc)
    else:
        out = proc.stdout or ""
        err = proc.stderr or ""
        mac = _arp_parse(out)
        if mac:
            res = ArpResult(ip=ip, mac=mac, command=binary)
        elif _looks_like_no_entry(out, err):
            # 「表里没有」≠「工具坏了」：macOS 对没有表项的 IP 返回 rc=1 +
            # "10.0.0.9 (10.0.0.9) -- no entry"。sweep 一个 /24 会有一两百个这种
            # 结果，判成错误就是刷屏的假告警（用户还以为 ARP 坏了）。
            res = ArpResult(ip=ip, command=binary)
        elif proc.returncode != 0:
            detail = (err or out or "").strip().replace("\n", " ")[:200] or "没有输出"
            res = ArpResult(ip=ip, command=binary,
                            error="arp 返回码 %s：%s" % (proc.returncode, detail))
        else:
            res = ArpResult(ip=ip, command=binary)      # 命令正常，表里就是没有

    return _finish_arp(res)


def _warn_once(kind: str, text: str) -> None:
    """同一类错误只往 stderr 打一行，次数记在 _ARP_WARNED 里给诊断用。

    并发场景（sweep 的线程池）下也不会重复打：计数在锁里做。
    """
    if not kind:
        return
    with _ARP_LOCK:
        seen = _ARP_WARNED.get(kind, 0)
        _ARP_WARNED[kind] = seen + 1
    if seen:
        return
    try:
        print("bmcd: %s" % text, file=sys.stderr)
    except (OSError, ValueError):
        pass


def _warn_arp(res: "ArpResult") -> None:
    """把 ARP 失败写一行到 stderr —— 命令行直接看得到，GUI 里走 Fingerprint。"""
    if not res.error:
        return
    _warn_once(res.category(), res.describe())


def arp_lookup(ip: str) -> str:
    """只要 MAC 的老接口。查不到/查不了都返回空串，原因见 arp_lookup_ex / arp_diag。"""
    return arp_lookup_ex(ip).mac


# ----------------------------------------------------------------------
# 综合探测
# ----------------------------------------------------------------------

@dataclass
class Fingerprint:
    ip: str
    alive: bool = False
    mac: str = ""
    ports: List[int] = field(default_factory=list)
    tls_cn: str = ""
    http: Optional[HttpInfo] = None
    rmcp: bool = False
    rmcp_detail: str = ""
    identity: vendors.Identity = field(default_factory=vendors.Identity)
    elapsed: float = 0.0
    # ARP 查询本身的失败原因（跟「表里没有这个 IP」区分开）
    arp_error: str = ""

    @property
    def url(self) -> str:
        if 443 in self.ports:
            return "https://%s/" % self.ip
        if 8443 in self.ports:
            return "https://%s:8443/" % self.ip
        if 80 in self.ports:
            return "http://%s/" % self.ip
        return ""

    def summary(self) -> str:
        bits: List[str] = []
        if self.identity.known:
            bits.append("%s（%s）" % (self.identity.vendor, self.identity.confidence))
        if self.tls_cn:
            bits.append("CN=%s" % self.tls_cn)
        if self.http and self.http.title:
            bits.append("标题=%s" % self.http.title)
        if self.ports:
            bits.append("端口=" + ",".join(str(p) for p in self.ports))
        if self.rmcp:
            bits.append("IPMI=活")
        if not bits:
            # arp_error 不进 summary：它是「查询本身失败」，跟设备画像不是一回事，
            # 单独走 Fingerprint.arp_error → /api/probe → 界面告警行
            bits.append("只回 ARP，无管理端口" if self.mac else "无响应")
        return "，".join(bits)


def probe(ip: str, timeout: float = 1.0, deep: bool = True) -> Fingerprint:
    started = time.time()
    fp = Fingerprint(ip=ip)
    arp = arp_lookup_ex(ip)
    fp.mac = arp.mac
    fp.arp_error = arp.error
    fp.ports = scan_ports(ip, timeout=timeout)
    fp.alive = bool(fp.ports) or bool(fp.mac)

    if 443 in fp.ports:
        fp.tls_cn = tls_cn(ip, 443)
        info = http_probe(ip, 443, "https")
        if info:
            fp.http = info
    if 80 in fp.ports and (fp.http is None or not (fp.http.title or fp.http.location)):
        info = http_probe(ip, 80, "http")
        if info:
            fp.http = info
    if 8443 in fp.ports and (fp.http is None or not (fp.http.title or fp.http.location)):
        info = http_probe(ip, 8443, "https")
        if info:
            fp.http = info
        if not fp.tls_cn:
            fp.tls_cn = tls_cn(ip, 8443)
    if deep:
        fp.rmcp, fp.rmcp_detail = rmcp_ping(ip, timeout=timeout + 0.4)

    hostname = ""
    fp.identity = vendors.identify(
        mac=fp.mac,
        hostname=hostname,
        tls_cn=fp.tls_cn,
        http_title=(fp.http.title if fp.http else ""),
        http_server=(fp.http.server if fp.http else ""),
        http_body_hint=(fp.http.body_marker if fp.http else ""),
    )
    if fp.http and fp.http.location:
        fp.identity.evidence.append("跳转 → %s" % fp.http.location)
    fp.elapsed = time.time() - started
    return fp


# ----------------------------------------------------------------------
# 网段清扫（找那些「已经跑着静态 IP」的 BMC）
# ----------------------------------------------------------------------

def ping_alive(ip: str, timeout: float = 1.0) -> bool:
    if IS_WINDOWS:
        return winnet.ping_alive(ip, timeout=timeout)
    try:
        rc = subprocess.run(
            ["/sbin/ping", "-c", "1", "-W", str(int(timeout * 1000)), "-t", "1", ip],
            capture_output=True, timeout=timeout + 2,
        ).returncode
        return rc == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _targets(cidr_or_hosts: object) -> List[str]:
    """`"192.168.0.0/24"` 或 `["10.0.0.1", ...]` 都接受，统一成 IP 列表。

    为什么要支持显式列表：BMC 的静态地址可能是**任何**地址（上一家单位留下的），
    所以扫描器会把一个大网段切成很多小批、或者干脆只打一串「常见出厂地址」，
    这些目标不构成任何 CIDR，只能一个个发 ARP。
    """
    if isinstance(cidr_or_hosts, str):
        try:
            return [str(h) for h in ipaddress.IPv4Network(cidr_or_hosts, strict=False).hosts()]
        except ValueError:
            return []
    out: List[str] = []
    for item in cidr_or_hosts or []:          # type: ignore[union-attr]
        text = str(item).strip()
        if not text:
            continue
        try:
            ipaddress.IPv4Address(text)
        except ValueError:
            continue
        out.append(text)
    return out


def _scapy_arp_sweep(iface: str, cidr_or_hosts: object, timeout: float = 2.0,
                     retry: int = 1) -> List[Tuple[str, str]]:
    targets = _targets(cidr_or_hosts)
    if not targets:
        return []
    try:
        from scapy.all import ARP, Ether, srp, conf  # type: ignore
    except ImportError:
        return []
    conf.verb = 0
    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets),
            iface=scapy_iface(iface),
            timeout=timeout,
            retry=retry,
            verbose=0,
        )
    except Exception:
        return []
    return [(rcv.psrc, (rcv.hwsrc or "").lower()) for _, rcv in answered]


def arp_sweep(iface: str, cidr_or_hosts: object, timeout: float = 1.2,
              retry: int = 1) -> List[Tuple[str, str]]:
    """纯二层 ARP 扫描：不需要本机在该网段里有地址，也不需要加路由。

    ARP 请求是以太网广播，目标机器只要在同一根线/同一个交换机上就会回；
    应答是单播回来的，所以跨网段也能问到。这是找「出厂静态 IP」的关键。

    Windows 上没有 Npcap 时 scapy 发不了二层帧，这时退到系统自带的
    SendARP（同样是 ARP，只是限定在本网段）。
    """
    found = _scapy_arp_sweep(iface, cidr_or_hosts, timeout=timeout, retry=retry)
    if found:
        return found
    if IS_WINDOWS:
        targets = _targets(cidr_or_hosts)
        if not targets:
            return []
        return winnet.arp_sweep(targets, timeout=timeout)
    return []


def ipv6_neighbors(iface: str, timeout: float = 3.0) -> List[Tuple[str, str]]:
    """发一次 IPv6 all-nodes 多播（ff02::1）的 echo request。

    这是「IPv4 配成什么都不知道」时**唯一不靠猜**的入口：只要对端开了 IPv6，
    它就一定会回（all-nodes 是协议强制），回来的源地址就是它自己。
    拿到 link-local 之后直接 https://[fe80::xxxx%en7] 就能打开管理页，
    跟它 IPv4 是 192.168.x 还是 10.x 完全无关。返回 [(addr, mac)]。
    """
    try:
        from scapy.all import Ether, ICMPv6EchoRequest, IPv6, conf, srp  # type: ignore
    except ImportError:
        return []
    conf.verb = 0
    try:
        answered, _ = srp(
            Ether(dst="33:33:00:00:00:01") / IPv6(dst="ff02::1") / ICMPv6EchoRequest(),
            iface=scapy_iface(iface), timeout=timeout, verbose=0)
    except Exception:                     # noqa: BLE001
        return []
    out: List[Tuple[str, str]] = []
    for _, rcv in answered:
        src = str(getattr(rcv, "src", "") or "")
        if not src or src == "::1":
            continue
        mac = str(getattr(rcv, "hwsrc", "") or "").lower()
        if (src, mac) not in out:
            out.append((src, mac))
    return out


def broadcast_probe(iface: str, timeout: float = 2.0) -> List[str]:
    """往 224.0.0.1（all-hosts）和 255.255.255.255 发 ICMP echo。

    Linux/BusyBox 上不少实现会回 all-hosts 的 echo，只要回了就暴露自己的
    IPv4 —— 跟它配在哪个网段无关，属于白捡的线索。
    """
    try:
        from scapy.all import Ether, ICMP, IP, conf, srp  # type: ignore
    except ImportError:
        return []
    conf.verb = 0
    out: List[str] = []
    tried = (("224.0.0.1", "01:00:5e:00:00:01"),
             ("255.255.255.255", "ff:ff:ff:ff:ff:ff"))
    for dst, mac in tried:
        try:
            answered, _ = srp(Ether(dst=mac) / IP(dst=dst) / ICMP(),
                              iface=scapy_iface(iface), timeout=timeout, verbose=0)
        except Exception:                 # noqa: BLE001
            continue
        for _, rcv in answered:
            src = str(getattr(rcv, "src", "") or "")
            if not src or src.startswith("127.") or src in out:
                continue
            try:
                addr = ipaddress.IPv4Address(src)
            except ValueError:
                continue
            if addr.is_multicast or addr.is_unspecified:
                continue
            out.append(src)
    return out


def _arp_table_scan(net: ipaddress.IPv4Network) -> List[Tuple[str, str]]:
    """从 ARP 表里挑出该网段的条目（mac 与 Windows 两种格式）。"""
    global LAST_ARP_TABLE_ERROR
    binary = ARP or arp_binary()
    if not binary:
        LAST_ARP_TABLE_ERROR = "找不到 arp 命令（试过 %s，PATH 里也没有）" % "、".join(ARP_CANDIDATES)
        _warn_once("table:找不到 arp 命令",
                   "ARP 表读不出来：%s；扫表兜底会没有结果" % LAST_ARP_TABLE_ERROR)
        return []
    try:
        proc = subprocess.run([binary, "-a"], capture_output=True, text=True, timeout=20)
        table = proc.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        LAST_ARP_TABLE_ERROR = "arp -a 执行失败：%s" % exc
        # 扫不到设备时，用户必须知道「是网段里没有设备」还是「ARP 表根本读不出来」
        _warn_once("table:arp -a 执行失败",
                   "ARP 表读不出来（%s）：扫表兜底这一轮不作数" % LAST_ARP_TABLE_ERROR)
        return []
    LAST_ARP_TABLE_ERROR = ""
    rows: List[Tuple[str, str]] = []
    if IS_WINDOWS:
        rows = winnet.arp_table(table)
    else:
        for line in table.splitlines():
            m = re.match(r"\? \(([\d.]+)\) at ([0-9a-f:]+|\(incomplete\))", line)
            if not m:
                continue
            ip, mac = m.group(1), m.group(2)
            if mac.startswith("(") or mac == "ff:ff:ff:ff:ff:ff":
                continue
            rows.append((ip, mac.lower()))
    out: List[Tuple[str, str]] = []
    for ip, mac in rows:
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if addr not in net:
            continue
        out.append((ip, mac))
    return out


def sweep(cidr: str, iface: str = "", timeout: float = 1.5,
          workers: int = 96) -> List[Tuple[str, str]]:
    """返回 [(ip, mac)]。

    顺序：scapy 二层 ARP（最准，跨网段也行）→ Windows 的 SendARP
    → ping 一遍再看 ARP 表（后两种只在本网段有效）。
    """
    net = ipaddress.IPv4Network(cidr, strict=False)
    if iface:
        found = _scapy_arp_sweep(iface, str(net), timeout)
        if found:
            return sorted(found, key=lambda x: ipaddress.IPv4Address(x[0]))
    if IS_WINDOWS:
        found = winnet.arp_sweep(str(net), timeout=timeout)
        if found:
            return found
        return sorted(_arp_table_scan(net), key=lambda x: ipaddress.IPv4Address(x[0]))
    hosts = [str(h) for h in net.hosts()][:1024]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(lambda h: ping_alive(h, timeout=0.6), hosts))
    return sorted(_arp_table_scan(net), key=lambda x: ipaddress.IPv4Address(x[0]))
