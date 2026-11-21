"""DHCPv4 报文编解码（纯标准库，零依赖，方便单测）。

只实现给 BMC / IPMI 分配地址所需的最小但完整的 RFC 2131/2132 子集：
  DISCOVER / OFFER / REQUEST / ACK / NAK / RELEASE / DECLINE / INFORM

设计要点：
  * 报文头按 BOOTP 固定 236 字节 + magic cookie + options；
  * options 用一个有序 dict 保存，保证 53(msg type)、54(server id) 排在前面；
  * 解析时支持 option 52 overload（file/sname 里塞 options，部分 BMC 会这么干）；
  * 所有地址用点分字符串，收发都走同一套 pack/unpack，可round-trip 自测。
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

MAGIC_COOKIE = b"\x63\x82\x53\x63"

BOOTREQUEST = 1
BOOTREPLY = 2

DISCOVER = 1
OFFER = 2
REQUEST = 3
DECLINE = 4
ACK = 5
NAK = 6
RELEASE = 7
INFORM = 8

MSG_NAMES = {
    DISCOVER: "DISCOVER",
    OFFER: "OFFER",
    REQUEST: "REQUEST",
    DECLINE: "DECLINE",
    ACK: "ACK",
    NAK: "NAK",
    RELEASE: "RELEASE",
    INFORM: "INFORM",
}

# DHCP option code 常量
O_SUBNET_MASK = 1
O_ROUTER = 3
O_DNS = 6
O_HOSTNAME = 12
O_DOMAIN = 15
O_BROADCAST = 28
O_NTP = 42
O_REQUESTED_IP = 50
O_LEASE_TIME = 51
O_OVERLOAD = 52
O_MSG_TYPE = 53
O_SERVER_ID = 54
O_PARAM_REQ = 55
O_MESSAGE = 56
O_MAX_MSG = 57
O_T1 = 58
O_T2 = 59
O_VENDOR_CLASS = 60
O_CLIENT_ID = 61
O_TFTP = 66
O_BOOTFILE = 67
O_RELAY = 82
O_END = 255

ZERO_IP = "0.0.0.0"


def ip_to_bytes(ip: str) -> bytes:
    return ipaddress.IPv4Address(ip).packed


def bytes_to_ip(raw: bytes) -> str:
    return str(ipaddress.IPv4Address(raw))


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(p, 16) for p in mac.replace("-", ":").split(":"))


def bytes_to_mac(raw: bytes) -> str:
    return ":".join("%02x" % b for b in raw)


def norm_mac(mac: str) -> str:
    """统一成小写冒号分隔。"""
    return ":".join("%02x" % int(p, 16) for p in mac.replace("-", ":").split(":"))


@dataclass
class DHCPMessage:
    """一个（已解析或待发送的）DHCP 报文。"""

    op: int = BOOTREPLY
    htype: int = 1
    hlen: int = 6
    hops: int = 0
    xid: int = 0
    secs: int = 0
    flags: int = 0
    ciaddr: str = ZERO_IP
    yiaddr: str = ZERO_IP
    siaddr: str = ZERO_IP
    giaddr: str = ZERO_IP
    chaddr: bytes = b"\x00" * 16
    sname: bytes = b""
    file: bytes = b""
    options: Dict[int, bytes] = field(default_factory=dict)

    # ---------- option 读写 ----------

    def set(self, code: int, value: bytes) -> "DHCPMessage":
        self.options[code] = value
        return self

    def set_u32(self, code: int, value: int) -> "DHCPMessage":
        return self.set(code, struct.pack("!I", int(value)))

    def set_ip(self, code: int, ip: str) -> "DHCPMessage":
        return self.set(code, ip_to_bytes(ip))

    def set_str(self, code: int, text: str) -> "DHCPMessage":
        return self.set(code, text.encode("utf-8", "replace"))

    def get(self, code: int) -> Optional[bytes]:
        return self.options.get(code)

    def get_u32(self, code: int) -> Optional[int]:
        raw = self.options.get(code)
        if raw is None or len(raw) < 4:
            return None
        return struct.unpack("!I", raw[:4])[0]

    def get_ip(self, code: int) -> Optional[str]:
        raw = self.options.get(code)
        if raw is None or len(raw) < 4:
            return None
        return bytes_to_ip(raw[:4])

    def get_str(self, code: int) -> str:
        raw = self.options.get(code)
        if not raw:
            return ""
        return raw.decode("utf-8", "replace").strip("\x00").strip()

    def get_ips(self, code: int) -> List[str]:
        raw = self.options.get(code) or b""
        out = []
        for i in range(0, len(raw) - 3, 4):
            out.append(bytes_to_ip(raw[i:i + 4]))
        return out

    @property
    def msg_type(self) -> Optional[int]:
        raw = self.options.get(O_MSG_TYPE)
        if raw:
            return raw[0]
        return None

    @property
    def msg_type_name(self) -> str:
        return MSG_NAMES.get(self.msg_type or 0, "UNKNOWN")

    @property
    def mac(self) -> str:
        hlen = self.hlen or 6
        return bytes_to_mac(self.chaddr[:hlen])

    @property
    def broadcast_flagged(self) -> bool:
        return bool(self.flags & 0x8000)

    # ---------- 序列化 ----------

    def pack(self) -> bytes:
        sname = (self.sname or b"")[:64].ljust(64, b"\x00")
        boot = (self.file or b"")[:128].ljust(128, b"\x00")
        head = struct.pack(
            "!BBBBIHH",
            self.op,
            self.htype,
            self.hlen,
            self.hops,
            self.xid,
            self.secs,
            self.flags,
        )
        head += (
            ip_to_bytes(self.ciaddr)
            + ip_to_bytes(self.yiaddr)
            + ip_to_bytes(self.siaddr)
            + ip_to_bytes(self.giaddr)
        )
        head += self.chaddr[:16].ljust(16, b"\x00") + sname + boot
        return head + MAGIC_COOKIE + self._pack_options()

    def _pack_options(self) -> bytes:
        out = bytearray()
        for code, value in self.options.items():
            if code in (0, O_END):
                continue
            value = bytes(value)
            while True:  # 超长 option 分片（几乎用不到，留着防身）
                chunk, value = value[:255], value[255:]
                out += bytes([code & 0xFF, len(chunk)]) + chunk
                if not value:
                    break
        out.append(O_END)
        return bytes(out)

    # ---------- 反序列化 ----------

    @classmethod
    def parse(cls, data: bytes) -> "DHCPMessage":
        if len(data) < 240:
            raise ValueError("DHCP 报文过短: %d bytes" % len(data))
        (op, htype, hlen, hops, xid, secs, flags) = struct.unpack("!BBBBIHH", data[:12])
        ciaddr = bytes_to_ip(data[12:16])
        yiaddr = bytes_to_ip(data[16:20])
        siaddr = bytes_to_ip(data[20:24])
        giaddr = bytes_to_ip(data[24:28])
        chaddr = data[28:44]
        sname = data[44:108]
        boot = data[108:236]
        cookie = data[236:240]
        if cookie != MAGIC_COOKIE:
            raise ValueError("magic cookie 不匹配，可能不是 DHCP 报文")
        msg = cls(
            op=op,
            htype=htype,
            hlen=hlen,
            hops=hops,
            xid=xid,
            secs=secs,
            flags=flags,
            ciaddr=ciaddr,
            yiaddr=yiaddr,
            siaddr=siaddr,
            giaddr=giaddr,
            chaddr=chaddr,
            sname=sname,
            file=boot,
        )
        msg._parse_options(data[240:])
        # option 52 overload：file/sname 里也可能带 options
        overload = msg.options.get(O_OVERLOAD)
        if overload:
            flag = overload[0]
            if flag & 1:
                msg._parse_options(msg.file, only_if_absent=True)
            if flag & 2:
                msg._parse_options(msg.sname, only_if_absent=True)
        return msg

    def _parse_options(self, blob: bytes, only_if_absent: bool = False) -> None:
        """按 RFC 3396 把同一个 code 的多个分片拼起来；overload 段则只填补空缺。"""
        into = self.options
        i = 0
        n = len(blob)
        while i < n:
            code = blob[i]
            if code == 0:  # pad
                i += 1
                continue
            if code == O_END:
                return
            if i + 1 >= n:
                return
            length = blob[i + 1]
            value = blob[i + 2:i + 2 + length]
            if len(value) < length:
                return
            if only_if_absent:
                into.setdefault(code, value)
            elif code in into:
                into[code] = into[code] + value
            else:
                into[code] = value
            i += 2 + length


def build_client_packet(
    msg_type: int,
    mac: str,
    xid: int,
    *,
    requested_ip: Optional[str] = None,
    server_id: Optional[str] = None,
    vendor_class: Optional[str] = None,
    hostname: Optional[str] = None,
    client_id: Optional[bytes] = None,
    broadcast: bool = True,
    ciaddr: str = ZERO_IP,
) -> DHCPMessage:
    """构造一个客户端报文（仅测试/自检用）。"""
    pkt = DHCPMessage(
        op=BOOTREQUEST,
        htype=1,
        hlen=6,
        xid=xid,
        flags=0x8000 if broadcast else 0,
        ciaddr=ciaddr,
        chaddr=mac_to_bytes(mac).ljust(16, b"\x00"),
    )
    pkt.set(O_MSG_TYPE, bytes([msg_type]))
    pkt.set(O_PARAM_REQ, bytes([O_SUBNET_MASK, O_ROUTER, O_HOSTNAME]))
    pkt.set(O_MAX_MSG, struct.pack("!H", 1500))
    if client_id is not None:
        pkt.set(O_CLIENT_ID, client_id)
    if requested_ip:
        pkt.set_ip(O_REQUESTED_IP, requested_ip)
    if server_id:
        pkt.set_ip(O_SERVER_ID, server_id)
    if vendor_class:
        pkt.set_str(O_VENDOR_CLASS, vendor_class)
    if hostname:
        pkt.set_str(O_HOSTNAME, hostname)
    return pkt


def summarise(pkt: DHCPMessage) -> str:
    """一行式摘要，用于日志。"""
    bits = [pkt.msg_type_name, pkt.mac]
    host = pkt.get_str(O_HOSTNAME)
    if host:
        bits.append("host=%s" % host)
    vendor = pkt.get_str(O_VENDOR_CLASS)
    if vendor:
        bits.append("class=%s" % vendor[:40])
    want = pkt.get_ip(O_REQUESTED_IP)
    if want:
        bits.append("want=%s" % want)
    return " ".join(bits)
