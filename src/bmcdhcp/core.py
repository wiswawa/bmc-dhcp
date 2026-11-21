"""DHCP 状态机：把收到的报文变成要发回去的报文（纯逻辑，可离线单测）。"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from . import dhcp as D
from .leases import LeaseManager


@dataclass
class ServerConfig:
    server_ip: str
    network: str                      # CIDR，如 10.99.0.0/24
    pool_start: str
    pool_end: str
    lease_seconds: int = 300
    routers: List[str] = field(default_factory=list)
    dns: List[str] = field(default_factory=list)
    domain: str = "bmc.local"
    hostname_prefix: str = "bmc"
    vendor_echo: bool = True          # 回显 option 60，兼容部分挑剔的 BMC
    client_id_echo: bool = True       # 回显 option 61（RFC 6842）

    @property
    def net(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.network, strict=False)

    @property
    def netmask(self) -> str:
        return str(self.net.netmask)

    @property
    def broadcast(self) -> str:
        return str(self.net.broadcast_address)


@dataclass
class Reply:
    msg: D.DHCPMessage
    broadcast: bool = True
    dst_ip: str = "255.255.255.255"
    eth_dst: bytes = b"\xff" * 6
    kind: str = ""


Event = Dict[str, object]


class ServerCore:
    def __init__(
        self,
        cfg: ServerConfig,
        leases: LeaseManager,
        on_event: Optional[Callable[[Event], None]] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.cfg = cfg
        self.leases = leases
        self.on_event = on_event
        self.clock = clock

    # ------------------------------------------------------------------

    def handle(self, pkt: D.DHCPMessage, src_mac: str, src_ip: str = D.ZERO_IP) -> List[Reply]:
        if pkt.op != D.BOOTREQUEST:
            return []
        msg_type = pkt.msg_type
        if msg_type is None:
            return []

        try:
            mac = D.norm_mac(src_mac or pkt.mac)
        except (ValueError, IndexError):
            self._emit("bad_packet", detail="报文里的 MAC 解析失败，丢弃")
            return []
        if mac == "00:00:00:00:00:00":
            return []

        if msg_type == D.DISCOVER:
            return self._on_discover(pkt, mac)
        if msg_type == D.REQUEST:
            return self._on_request(pkt, mac)
        if msg_type == D.RELEASE:
            return self._on_release(pkt, mac)
        if msg_type == D.DECLINE:
            return self._on_decline(pkt, mac)
        if msg_type == D.INFORM:
            return self._on_inform(pkt, mac)
        return []

    # ------------------------------------------------------------------
    # 各状态处理
    # ------------------------------------------------------------------

    def _on_discover(self, pkt: D.DHCPMessage, mac: str) -> List[Reply]:
        now = self.clock()
        hint = pkt.get_ip(D.O_REQUESTED_IP)
        hostname = pkt.get_str(D.O_HOSTNAME)
        vendor = pkt.get_str(D.O_VENDOR_CLASS)
        client_id = self._client_id(pkt)

        ip = self.leases.offer(
            mac, hint=hint, hostname=hostname, vendor=vendor, client_id=client_id, now=now
        )
        self._emit(
            "discover",
            mac=mac,
            ip=ip or "",
            ip_hint=hint or "",
            hostname=hostname,
            vendor=vendor,
            detail="收到 DISCOVER",
        )
        if ip is None:
            self._emit("pool_exhausted", mac=mac, detail="地址池已满，无法分配")
            return []

        reply = self._base_reply(pkt, D.OFFER)
        reply.yiaddr = ip
        echo_options(reply, pkt, self.cfg)
        self._add_lease_options(reply, mac, pkt.get_str(D.O_HOSTNAME))
        self._emit("offer", mac=mac, ip=ip, hostname=hostname, vendor=vendor, detail="发出 OFFER")
        return [self._route(pkt, reply, ip)]

    def _on_request(self, pkt: D.DHCPMessage, mac: str) -> List[Reply]:
        now = self.clock()
        sid = pkt.get_ip(D.O_SERVER_ID)
        if sid and sid != self.cfg.server_ip:
            # 客户端选了别的 DHCP 服务器（典型：同一个口上还有别的 DHCP）
            self._emit(
                "request_other",
                mac=mac,
                ip=sid or "",
                detail="客户端选择了其它 DHCP 服务器 %s，本机忽略" % sid,
            )
            return []

        requested = pkt.get_ip(D.O_REQUESTED_IP)
        if not requested and pkt.ciaddr not in (D.ZERO_IP, ""):
            requested = pkt.ciaddr

        hostname = pkt.get_str(D.O_HOSTNAME)
        vendor = pkt.get_str(D.O_VENDOR_CLASS)
        if not hostname:
            lease = self.leases.by_mac(mac)
            hostname = lease.hostname if lease else ""
        if not vendor:
            lease = self.leases.by_mac(mac)
            vendor = lease.vendor if lease else ""

        if not requested:
            # 没有 option 50、也没有 ciaddr：给一个已有租约或重新分配
            lease = self.leases.by_mac(mac)
            requested = lease.ip if lease else None

        ok = False
        if requested and self.leases.in_pool(requested):
            if self.leases.owns(requested, mac) or self.leases.is_free_for(requested, mac, now):
                ok = True

        if not ok:
            self._emit(
                "nak",
                mac=mac,
                ip=requested or "",
                hostname=hostname,
                detail="REQUEST 的地址不可用，回 NAK",
            )
            reply = self._base_reply(pkt, D.NAK)
            reply.yiaddr = D.ZERO_IP
            reply.set_str(D.O_MESSAGE, "requested address not available")
            return [self._route(pkt, reply, None)]

        if requested is None:            # 不该发生；用显式判断，-O 下也不会被删掉
            return []
        lease = self.leases.bind(
            requested, mac, hostname=hostname, vendor=vendor,
            client_id=self._client_id(pkt), now=now,
        )
        reply = self._base_reply(pkt, D.ACK)
        reply.yiaddr = requested
        echo_options(reply, pkt, self.cfg)
        self._add_lease_options(reply, mac, pkt.get_str(D.O_HOSTNAME))
        self._emit(
            "ack",
            mac=mac,
            ip=requested,
            hostname=lease.hostname,
            vendor=lease.vendor,
            detail="绑定成功，租期 %ds" % self.cfg.lease_seconds,
        )
        return [self._route(pkt, reply, requested)]

    def _on_release(self, pkt: D.DHCPMessage, mac: str) -> List[Reply]:
        ip = pkt.ciaddr
        if ip in (D.ZERO_IP, ""):
            lease = self.leases.by_mac(mac)
            ip = lease.ip if lease else ""
        if ip:
            self.leases.release(ip)
            self._emit("release", mac=mac, ip=ip, detail="客户端释放地址")
        return []

    def _on_decline(self, pkt: D.DHCPMessage, mac: str) -> List[Reply]:
        ip = pkt.get_ip(D.O_REQUESTED_IP) or pkt.ciaddr
        if ip and self.leases.in_pool(ip):
            self.leases.decline(ip, seconds=min(600, self.cfg.lease_seconds))
            self._emit(
                "decline",
                mac=mac,
                ip=ip,
                detail="客户端报告地址冲突，暂时封禁该地址",
            )
        return []

    def _on_inform(self, pkt: D.DHCPMessage, mac: str) -> List[Reply]:
        reply = self._base_reply(pkt, D.ACK)
        reply.yiaddr = D.ZERO_IP
        reply.ciaddr = pkt.ciaddr
        self._add_config_options(reply, include_lease=False)
        self._emit("inform", mac=mac, detail="INFORM：只回配置不分配地址")
        return [self._route(pkt, reply, None)]

    # ------------------------------------------------------------------
    # 组包工具
    # ------------------------------------------------------------------

    def _base_reply(self, req: D.DHCPMessage, msg_type: int) -> D.DHCPMessage:
        reply = D.DHCPMessage(
            op=D.BOOTREPLY,
            htype=req.htype or 1,
            hlen=req.hlen or 6,
            hops=0,
            xid=req.xid,
            secs=0,
            flags=req.flags,
            ciaddr=D.ZERO_IP,
            yiaddr=D.ZERO_IP,
            siaddr=D.ZERO_IP,
            giaddr=req.giaddr,
            chaddr=req.chaddr,
        )
        reply.set(D.O_MSG_TYPE, bytes([msg_type]))
        reply.set(D.O_SERVER_ID, D.ip_to_bytes(self.cfg.server_ip))
        return reply

    def _add_lease_options(self, reply: D.DHCPMessage, mac: str, client_hostname: str = "") -> None:
        lease_seconds = self.cfg.lease_seconds
        reply.set_u32(D.O_LEASE_TIME, lease_seconds)
        t1 = max(1, lease_seconds // 2)
        t2 = min(max(t1 + 1, int(lease_seconds * 0.875)), max(t1 + 1, lease_seconds - 1))
        reply.set_u32(D.O_T1, t1)
        reply.set_u32(D.O_T2, t2)
        self._add_config_options(reply, include_lease=True, mac=mac, client_hostname=client_hostname)

    def _add_config_options(
        self,
        reply: D.DHCPMessage,
        include_lease: bool,
        mac: str = "",
        client_hostname: str = "",
    ) -> None:
        reply.set_ip(D.O_SUBNET_MASK, self.cfg.netmask)
        reply.set_ip(D.O_BROADCAST, self.cfg.broadcast)
        if self.cfg.routers:
            reply.set(D.O_ROUTER, b"".join(D.ip_to_bytes(r) for r in self.cfg.routers))
        if self.cfg.dns:
            reply.set(D.O_DNS, b"".join(D.ip_to_bytes(d) for d in self.cfg.dns))
        if self.cfg.domain:
            reply.set_str(D.O_DOMAIN, self.cfg.domain)
        if mac and self.cfg.hostname_prefix and not client_hostname:
            short = mac.split(":")[-2] + mac.split(":")[-1]
            reply.set_str(D.O_HOSTNAME, "%s-%s" % (self.cfg.hostname_prefix, short))

    def _route(
        self,
        req: D.DHCPMessage,
        reply: D.DHCPMessage,
        yiaddr: Optional[str],
    ) -> Reply:
        # RFC 2131 §4.1：客户端置了 broadcast 位，或还没 IP，一律广播
        broadcast = req.broadcast_flagged or not yiaddr or req.ciaddr == D.ZERO_IP
        if broadcast:
            return Reply(
                msg=reply,
                broadcast=True,
                dst_ip="255.255.255.255",
                eth_dst=b"\xff" * 6,
                kind=reply.msg_type_name,
            )
        return Reply(
            msg=reply,
            broadcast=False,
            dst_ip=req.ciaddr if req.ciaddr != D.ZERO_IP else str(yiaddr),
            eth_dst=req.chaddr[:6],
            kind=reply.msg_type_name,
        )

    def _client_id(self, pkt: D.DHCPMessage) -> str:
        raw = pkt.get(D.O_CLIENT_ID) or b""
        return raw.hex()

    def _emit(self, kind: str, **kwargs: object) -> None:
        if not self.on_event:
            return
        event: Event = {"type": kind, "ts": self.clock()}
        event.update(kwargs)
        try:
            self.on_event(event)
        except Exception:  # 日志失败不能影响 DHCP 服务
            pass


def echo_options(reply: D.DHCPMessage, req: D.DHCPMessage, cfg: ServerConfig) -> None:
    """把客户端的 option 60 / 61 原样回显（RFC 6842 + 部分 BMC 的硬性要求）。"""
    if cfg.vendor_echo:
        vc = req.get(D.O_VENDOR_CLASS)
        if vc:
            reply.set(D.O_VENDOR_CLASS, vc)
    if cfg.client_id_echo:
        cid = req.get(D.O_CLIENT_ID)
        if cid:
            reply.set(D.O_CLIENT_ID, cid)
