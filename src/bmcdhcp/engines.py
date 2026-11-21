"""三种发包引擎，按优先级自动挑选：

  raw      —— scapy + BPF 直接发以太网帧（最可靠，DHCP 就该这么干；需要 root）
  udp      —— 纯标准库 UDP 广播（不需要 scapy，只对置了 broadcast 位的客户端可靠）
  dnsmasq  —— 交给 brew 装的 dnsmasq（久经考验，但要多装一个东西）

raw 和 udp 共享同一套『解析 → Core 处理 → 发包』流程，只是搬运方式不同。
"""

from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from . import dhcp as D
from .core import Reply, ServerCore, ServerConfig
from .iface import Interface, broadcast_of, scapy_iface
from . import winnet

IS_WINDOWS = winnet.IS_WIN


class EngineUnavailable(RuntimeError):
    pass


# ----------------------------------------------------------------------
# 帧解析（不依赖 scapy 的 dissector，避免 BOOTP/DHCP 层解析差异）
# ----------------------------------------------------------------------

@dataclass
class UdpFrame:
    src_mac: str
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    payload: bytes


def parse_eth_ipv4_udp(raw: bytes) -> Optional[UdpFrame]:
    if len(raw) < 42:
        return None
    offset = 14
    ethertype = raw[12:14]
    if ethertype in (b"\x81\x00", b"\x88\xa8"):   # 802.1Q / QinQ：跳过 4 字节 tag
        if len(raw) < 46:
            return None
        ethertype = raw[16:18]
        offset = 18
    if ethertype != b"\x08\x00":
        return None
    ip = raw[offset:]
    version = ip[0] >> 4
    if version != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17 or len(ip) < ihl + 8:
        return None
    src_ip = ".".join(str(b) for b in ip[12:16])
    dst_ip = ".".join(str(b) for b in ip[16:20])
    udp = ip[ihl:]
    sport, dport, ulen = struct.unpack("!HHH", udp[:6])
    payload = udp[8:ulen] if 8 <= ulen <= len(udp) else udp[8:]
    src_mac = ":".join("%02x" % b for b in raw[6:12])
    return UdpFrame(src_mac, src_ip, dst_ip, sport, dport, payload)


# ----------------------------------------------------------------------
# 基类
# ----------------------------------------------------------------------

class Engine:
    kind = "base"

    def __init__(self, iface: Interface, core: ServerCore, log: Callable[[str, str], None]):
        self.iface = iface
        self.core = core
        self.log = log
        self._stop = threading.Event()

    # 子类实现
    def start(self, on_ready: Optional[Callable[[], None]] = None) -> None:
        raise NotImplementedError

    @staticmethod
    def _ready(on_ready: Optional[Callable[[], None]]) -> None:
        if on_ready is not None:
            try:
                on_ready()
            except Exception:
                pass

    def stop(self) -> None:
        self._stop.set()

    def sleep(self, seconds: float = 0.3) -> None:
        self._stop.wait(seconds)

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()


# ----------------------------------------------------------------------
# raw 引擎（scapy）
# ----------------------------------------------------------------------

class RawEngine(Engine):
    kind = "raw"

    def __init__(self, iface: Interface, core: ServerCore, log: Callable[[str, str], None]):
        super().__init__(iface, core, log)
        try:
            from scapy.all import sendp, sniff  # type: ignore  # noqa: F401
        except ImportError as exc:
            raise EngineUnavailable("scapy 未安装: %s" % exc) from exc
        from scapy.all import conf as scapy_conf  # type: ignore

        self._sendp = sendp
        self._sniff = sniff
        self._scapy_name = scapy_iface(self.iface.name)
        self._conf = scapy_conf
        self._conf.verb = 0
        self._filter_ok = True

    def send(self, reply: Reply) -> None:
        from scapy.all import Ether, IP, Raw, UDP  # type: ignore

        payload = reply.msg.pack()
        dst_ip = reply.dst_ip or "255.255.255.255"
        eth_dst = reply.eth_dst or b"\xff" * 6
        pkt = (
            Ether(dst=eth_dst, src=self.iface.mac or None)
            / IP(src=self.core.cfg.server_ip, dst=dst_ip)
            / UDP(sport=67, dport=68)
            / Raw(load=payload)
        )
        try:
            self._sendp(pkt, iface=self._scapy_name, verbose=False)
        except Exception as exc:  # 发包失败不能让服务崩
            self.log("err", "发包失败: %s" % exc)

    def _handle_frame(self, raw: bytes) -> None:
        frame = parse_eth_ipv4_udp(raw)
        if frame is None:
            return
        if frame.dport != 67 and frame.sport != 68:
            return
        try:
            pkt = D.DHCPMessage.parse(frame.payload)
        except ValueError:
            return
        if pkt.op != D.BOOTREQUEST:
            return
        for reply in self.core.handle(pkt, frame.src_mac, frame.src_ip):
            self.send(reply)

    def _callback(self, pkt) -> None:  # scapy Packet
        try:
            self._handle_frame(bytes(pkt))
        except Exception as exc:
            self.log("err", "处理报文异常: %s" % exc)

    @staticmethod
    def preflight() -> None:
        """没有抓包权限时提前说清楚，别等进循环才炸。"""
        if IS_WINDOWS:
            if not winnet.has_npcap():
                raise EngineUnavailable(
                    "Windows 上抓包要装 Npcap（npcap.com，勾选 WinPcap 兼容模式）；"
                    "不装也能用 udp 引擎发 DHCP")
            return
        if os.geteuid() == 0:
            return
        try:
            fd = os.open("/dev/bpf0", os.O_RDONLY)
            os.close(fd)
        except PermissionError as exc:
            raise PermissionError("打开 /dev/bpf0 被拒绝（需要 root）") from exc
        except OSError:
            return

    def start(self, on_ready: Optional[Callable[[], None]] = None) -> None:
        self.preflight()
        # 试抓一小段，确认 BPF 真的能开（比“进循环后才发现没权限”友好）
        try:
            self._sniff(iface=self._scapy_name, timeout=0.25, store=False)
        except Exception as exc:
            text = str(exc).lower()
            if "permission" in text or "not permitted" in text:
                raise PermissionError(str(exc)) from exc
        self._ready(on_ready)
        self.log("info", "raw 引擎启动：%s（BPF 抓 UDP/67）" % self.iface.name)
        while not self.stopping:
            try:
                kwargs = dict(
                    iface=self._scapy_name,
                    prn=self._callback,
                    store=False,
                    stop_filter=lambda _p: self.stopping,
                )
                if self._filter_ok:
                    kwargs["filter"] = "udp and (dst port 67 or src port 68)"
                self._sniff(timeout=2, **kwargs)
            except Exception as exc:
                text = str(exc).lower()
                if isinstance(exc, PermissionError) or "permission" in text or "not permitted" in text:
                    raise PermissionError(str(exc)) from exc
                if self._filter_ok:
                    # 没有 libpcap/BPF 过滤器支持时退回用户态过滤
                    self.log("warn", "BPF 过滤器不可用（%s），改为用户态过滤" % exc)
                    self._filter_ok = False
                    continue
                self.log("err", "抓包循环异常: %s" % exc)
                self.sleep(1.0)


# ----------------------------------------------------------------------
# udp 引擎（纯标准库）
# ----------------------------------------------------------------------

class UdpEngine(Engine):
    kind = "udp"

    def __init__(
        self,
        iface: Interface,
        core: ServerCore,
        log: Callable[[str, str], None],
        *,
        bind_ip: str = "0.0.0.0",
        bind_port: int = 67,
        client_port: int = 68,
        reply_targets: Optional[List[Tuple[str, int]]] = None,
    ):
        super().__init__(iface, core, log)
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.client_port = client_port
        self.reply_targets = reply_targets
        self._recv: Optional[socket.socket] = None
        self._send: Optional[socket.socket] = None

    def start(self, on_ready: Optional[Callable[[], None]] = None) -> None:
        recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if not IS_WINDOWS:
            # Windows 上 SO_REUSEADDR 会让两个进程同时绑上 67（互相抢包），
            # 不设它才能「端口被占就明确报错」
            recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        recv.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            recv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        except OSError:
            pass
        try:
            if IS_WINDOWS and self.bind_ip == "0.0.0.0":
                # Microsoft IP_IFLIST / IP_ADD_IFLIST restrict incoming packets;
                # IP_UNICAST_IF chooses the outgoing interface. Fail closed.
                index = self.iface.if_index
                if index <= 0:
                    raise EngineUnavailable("Windows UDP 需要网卡索引，请刷新网卡列表或使用 Npcap raw 引擎")
                try:
                    recv.setsockopt(socket.IPPROTO_IP, 28, 1)  # IP_IFLIST
                    recv.setsockopt(socket.IPPROTO_IP, 29, struct.pack("=I", index))
                    recv.setsockopt(socket.IPPROTO_IP, 31, struct.pack("!I", index))
                except OSError as exc:
                    raise EngineUnavailable("Windows UDP 无法限定网卡 %s：%s" % (self.iface.name, exc)) from exc
            if sys.platform == "darwin" and not IS_WINDOWS:
                # macOS 的 IP_BOUND_IF 同时约束收发，不能只绑定 0.0.0.0:67
                # 再靠路由选出口，否则会回答其他网口上的 DHCP 请求。
                try:
                    index = socket.if_nametoindex(self.iface.name)
                    recv.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_BOUND_IF", 25), index)
                except OSError as exc:
                    raise EngineUnavailable("无法将 UDP DHCP 绑定到网卡 %s：%s"
                                            % (self.iface.name, exc)) from exc
            recv.bind((self.bind_ip, self.bind_port))
        except (OSError, EngineUnavailable) as exc:
            try:
                recv.close()
            except OSError:
                pass
            if getattr(exc, "errno", None) in (48, 98, 10048):  # macOS / Linux / Windows
                raise EngineUnavailable(
                    "UDP/%d 已被占用（是不是还开着另一个 bmcd，或者系统「互联网共享」？）"
                    % self.bind_port
                ) from exc
            raise
        recv.settimeout(0.5)
        self._recv = recv

        # 使用接收 socket 发回包，源端口才是 67（测试时为指定端口）。
        # 单独新建 socket 会获得随机源端口，部分 BMC 会丢弃 OFFER/ACK。
        self._send = recv
        self._ready(on_ready)
        self.log("info", "udp 引擎启动：绑定 %s:%d" % (self.bind_ip, self.bind_port))

        while not self.stopping:
            try:
                data, addr = recv.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError as exc:
                if self.stopping:
                    break
                self.log("err", "收包失败: %s" % exc)
                self.sleep(0.5)
                continue
            try:
                pkt = D.DHCPMessage.parse(data)
                if pkt.op != D.BOOTREQUEST:
                    continue
                for reply in self.core.handle(pkt, pkt.mac, addr[0]):
                    self.send(reply)
            except (ValueError, OSError, IndexError) as exc:
                self.log("warn", "丢弃一个异常报文: %s" % exc)
                continue

    def send(self, reply: Reply) -> None:
        if self._send is None:
            return
        payload = reply.msg.pack()
        try:
            targets = self._targets(reply)
        except Exception:
            targets = [(self.iface.ipv4 or "255.255.255.255", self.client_port)]
        for target in targets:
            try:
                self._send.sendto(payload, target)
            except (OSError, ValueError):
                continue

    def _targets(self, reply: Reply) -> List[Tuple[str, int]]:
        if self.reply_targets:
            return list(self.reply_targets)
        if not reply.broadcast:
            return [(reply.dst_ip, self.client_port)]
        targets: List[Tuple[str, int]] = []
        if self.iface.ipv4 and self.iface.netmask:
            targets.append((
                broadcast_of(self.iface.ipv4, self.iface.netmask),
                self.client_port,
            ))
        targets.append(("255.255.255.255", self.client_port))
        return targets

    def stop(self) -> None:
        super().stop()
        for sock in (self._recv, self._send):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


# ----------------------------------------------------------------------
# dnsmasq 引擎（外挂进程）
# ----------------------------------------------------------------------

class DnsmasqEngine(Engine):
    kind = "dnsmasq"

    def __init__(
        self,
        iface: Interface,
        core: ServerCore,
        log: Callable[[str, str], None],
        *,
        workdir: str = "",
        on_lease: Optional[Callable[[str, str, str], None]] = None,
    ):
        super().__init__(iface, core, log)
        binary = shutil.which("dnsmasq")
        if not binary:
            raise EngineUnavailable("未找到 dnsmasq（brew install dnsmasq）")
        self.binary = binary
        # 每次一个 0700 的私有目录，避免 /tmp 固定路径被符号链接攻击
        self.workdir = os.path.abspath(workdir) if workdir else tempfile.mkdtemp(prefix="bmcd-dnsmasq-")
        self.on_lease = on_lease
        # 必须挂到 self.workdir 上：用入参 workdir 的话，调用方给空串时这里就是个相对路径
        # "dnsmasq.leases"，会落在进程 CWD（App 从访达启动时是 /），既写不进去也读不回来。
        self.leasefile = os.path.join(self.workdir, "dnsmasq.leases")
        self.proc: Optional[subprocess.Popen] = None
        self._seen: set = set()

    def _config(self) -> str:
        cfg: ServerConfig = self.core.cfg
        lines = [
            "port=0",
            "bind-interfaces",
            "interface=%s" % self.iface.name,
            "except-interface=lo0",
            "dhcp-range=%s,%s,%s,%ds" % (
                cfg.pool_start,
                cfg.pool_end,
                cfg.netmask,
                cfg.lease_seconds,
            ),
            "dhcp-leasefile=%s" % self.leasefile,
            "dhcp-authoritative",
            "dhcp-option=1,%s" % cfg.netmask,
            "dhcp-option=28,%s" % cfg.broadcast,
            "pid-file=",
            "log-dhcp",
        ]
        if cfg.routers:
            lines.append("dhcp-option=3,%s" % ",".join(cfg.routers))
        else:
            lines.append("dhcp-option=3")
        if cfg.dns:
            lines.append("dhcp-option=6,%s" % ",".join(cfg.dns))
        else:
            lines.append("dhcp-option=6")
        if cfg.domain:
            lines.append("dhcp-option=15,%s" % cfg.domain)
        return "\n".join(lines) + "\n"

    def start(self, on_ready: Optional[Callable[[], None]] = None) -> None:
        os.makedirs(self.workdir, mode=0o700, exist_ok=True)
        conf_path = os.path.join(self.workdir, "dnsmasq.conf")
        with open(conf_path, "w", encoding="utf-8") as fh:
            fh.write(self._config())
        self.log("info", "dnsmasq 引擎启动：%s" % conf_path)
        self.proc = subprocess.Popen(
            [self.binary, "--keep-in-foreground", "--conf-file=%s" % conf_path,
             "--dhcp-leasefile=%s" % self.leasefile,
             "--pid-file=", "--log-facility=-"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        self._ready(on_ready)
        try:
            while not self.stopping:
                if self.proc.poll() is not None:
                    self.log("err", "dnsmasq 退出，返回码 %s" % self.proc.returncode)
                    break
                self._poll_leases()
                self.sleep(0.8)
        finally:
            self.stop()

    def _poll_leases(self) -> None:
        if not os.path.exists(self.leasefile):
            return
        try:
            with open(self.leasefile, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            mac, ip, hostname = parts[1], parts[2], parts[3]
            key = (mac.lower(), ip)
            if key in self._seen:
                continue
            self._seen.add(key)
            if self.on_lease:
                self.on_lease(mac.lower(), ip, "" if hostname == "*" else hostname)

    def stop(self) -> None:
        super().stop()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                try:
                    self.proc.kill()
                except OSError:
                    pass


# ----------------------------------------------------------------------
# 选引擎
# ----------------------------------------------------------------------

def enable_reuse(sock: socket.socket, broadcast: bool = False) -> None:
    """给「客户端」套接字设可复用选项。

    `SO_REUSEPORT` 在 Windows 上连常量都没有，写死 `socket.SO_REUSEPORT`
    在 Windows 上是 AttributeError（自检脚本之前就是这么崩的）；
    `SO_REUSEADDR` 两边都有，但只有 POSIX 上语义是「时间等待期可重绑」。
    """
    opt = getattr(socket, "SO_REUSEADDR", None)
    if opt is not None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, 1)
        except OSError:
            pass
    if not IS_WINDOWS:
        opt = getattr(socket, "SO_REUSEPORT", None)
        if opt is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, opt, 1)
            except OSError:
                pass
    if broadcast:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass


def has_scapy() -> bool:
    import importlib.util

    return importlib.util.find_spec("scapy") is not None


def has_dnsmasq() -> bool:
    return shutil.which("dnsmasq") is not None


def make_engine(
    kind: str,
    iface: Interface,
    core: ServerCore,
    log: Callable[[str, str], None],
    on_lease: Optional[Callable[[str, str, str], None]] = None,
) -> Engine:
    kind = (kind or "auto").lower()
    if kind == "auto":
        import importlib.util

        if importlib.util.find_spec("scapy") is not None:
            # Windows 上 scapy 要 Npcap 才能发二层帧，没装就直接用 udp，
            # 免得先起 raw 再失败再回退（每次启动都多耗几秒）
            kind = "raw" if (not IS_WINDOWS or winnet.has_npcap()) else "udp"
        elif shutil.which("dnsmasq"):
            kind = "dnsmasq"
        else:
            kind = "udp"
    if kind == "raw":
        return RawEngine(iface, core, log)
    if kind == "udp":
        return UdpEngine(iface, core, log)
    if kind == "dnsmasq":
        return DnsmasqEngine(iface, core, log, on_lease=on_lease)
    raise EngineUnavailable("未知引擎: %s" % kind)
