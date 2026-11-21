"""`bmcd simulate`：没有 BMC 也能把整条链路真跑一遍。

它扮演一台「假 BMC」：
  1. 在指定网卡上发 DHCP DISCOVER（可以用另一块网卡发，模拟真正的两台设备）；
  2. 收 OFFER、发 REQUEST、收 ACK；
  3. 检查服务器记的租约对不对；
  4. （可选）把拿到的地址临时挂到网卡上，起一个自签证书的 HTTPS「管理页」，
     再让服务器去探测 —— 验证厂商识别和"打开管理页"这条链路。

用法：
  ./bmcd simulate                      # 自动挑口，10 秒出报告
  ./bmcd simulate --iface en7 --client-iface en9   # 两块网卡对插，最真实
"""

from __future__ import annotations

import os
import random
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List, Optional, Tuple

from . import dhcp as D
from . import engines
from . import iface as I
from .session import Session, SessionConfig, SessionError

FAKE_MAC = "02:00:5e:00:53:01"
PAGE = (
    b"<html><head><title>iDRAC Virtual Console</title></head>"
    b"<body>Dell Remote Access Controller (simulated)</body></html>"
)


class _Page(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "iDRAC/7.10")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *args: object) -> None:
        return



def _loopback_iface():
    """找一个环回口：mac 是 lo0，Windows 是 "Loopback Pseudo-Interface 1"。"""
    for iface in I.enumerate_all():
        if iface.loopback or iface.name in ("lo0", "lo"):
            return iface
    for iface in I.enumerate_all():
        if iface.ipv4.startswith("127."):
            return iface
    return I.find_by_name("lo0")

def _make_cert(directory: str) -> Tuple[str, str]:
    crt = os.path.join(directory, "cert.pem")
    key = os.path.join(directory, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=idrac-SIMULATED"],
        capture_output=True, timeout=30,
    )
    return crt, key


def _start_fake_bmc(ip: str, directory: str) -> Optional[HTTPServer]:
    crt, key = _make_cert(directory)
    if not (os.path.exists(crt) and os.path.exists(key)):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv = HTTPServer((ip, 443), _Page)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _send_raw(client_iface: str, payload: bytes, log) -> bool:
    try:
        from scapy.all import Ether, IP, Raw, UDP, sendp  # type: ignore
    except ImportError:
        log("warn", "没装 scapy，改用 UDP 广播发送（仍然有效，只是不走二层）")
        return False
    frame = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / Raw(load=payload)
    )
    try:
        sendp(frame, iface=client_iface, verbose=False)
        return True
    except Exception as exc:  # noqa: BLE001
        log("warn", "二层发送失败（%s），改用 UDP 广播" % exc)
        return False


def _recv(sock: socket.socket, want: int, timeout: float = 6.0) -> Optional[D.DHCPMessage]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            continue
        try:
            msg = D.DHCPMessage.parse(data)
        except ValueError:
            continue
        if msg.msg_type == want:
            return msg
    return None


def run(
    iface_name: str = "",
    client_iface: str = "",
    subnet: str = "10.99.0.0/24",
    with_web: bool = True,
    keep: bool = False,
    color: bool = True,
) -> int:
    from . import ui

    console = ui.Console(color=color)
    results: List[Tuple[str, Optional[bool], str]] = []

    def check(name: str, ok: Optional[bool], detail: str = "") -> None:
        results.append((name, ok, detail))
        if ok is None:
            mark = console.c("SKIP", ui.YELLOW)
        else:
            mark = console.c("PASS", ui.GREEN) if ok else console.c("FAIL", ui.RED)
        console.raw("[%s] %s%s" % (mark, name, ("  " + detail) if detail else ""))

    def log(level: str, text: str) -> None:
        if level == "err":
            console.err(text)
        elif level == "warn":
            console.warn(text)
        else:
            console.info(text)

    # ---- 选口 ----
    if iface_name:
        srv_iface = I.find_by_name(iface_name)
    else:
        cands = I.ethernet_candidates()
        srv_iface = cands[0] if cands else _loopback_iface()
    if srv_iface is None:
        console.err("找不到网卡")
        return 2
    loopback = bool(srv_iface.loopback) or srv_iface.name in ("lo0", "lo")
    if loopback:
        subnet = "127.0.0.0/8"
        console.warn("没有插网卡，用环回口（%s）模式：能验证软件链路，但不验证网线收发"
                     % srv_iface.name)
    if client_iface and not I.find_by_name(client_iface):
        console.err("找不到发客户端报文的网卡 %s" % client_iface)
        return 2

    cfg = SessionConfig(
        iface=srv_iface.name,
        subnet=subnet,
        pool="127.0.0.1-127.0.0.3" if loopback else "",
        server_ip="127.0.0.2" if loopback else "",
        lease_seconds=120,
        configure=not loopback,
        probe_retry=0,
        state_path="",
        engine="udp" if loopback else "auto",
    )
    session = Session(cfg, log=log)

    console.raw()
    console.raw(console.c("  模拟一台 BMC 接入 %s（%s）" % (srv_iface.name, subnet), ui.BOLD))
    console.raw()

    alias_ip = ""
    srv = None
    tmpdir = tempfile.mkdtemp(prefix="bmcd-sim-")
    try:
        try:
            session.start()
        except SessionError as exc:
            console.err("服务起不来：%s" % exc)
            return 2
        check("DHCP 服务启动", True, "引擎 %s" % session.engine_kind)

        # ---- 客户端 ----
        cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        engines.enable_reuse(cli)          # Windows 上没有 SO_REUSEPORT
        try:
            cli.bind(("0.0.0.0", 68))
        except OSError as exc:
            console.err("客户端端口 68 绑不上（%s）：Windows 上 DHCP 客户端服务会占着它，"
                        "可以先用 bmcd selftest 验软件链路，或换台机器跑 simulate" % exc)
            return 3
        cli.settimeout(0.4)

        xid = random.randrange(1, 0xFFFFFFFF)
        disc = D.build_client_packet(
            D.DISCOVER, FAKE_MAC, xid,
            vendor_class="iDRAC", hostname="idrac-simulated",
        )
        offered = None
        for _ in range(6):
            sent_raw = bool(client_iface) and _send_raw(client_iface, disc.pack(), log)
            if not sent_raw:
                try:
                    cli.sendto(disc.pack(), ("255.255.255.255", 67))
                except OSError:
                    cli.sendto(disc.pack(), ("127.0.0.1", 67))
            offered = _recv(cli, D.OFFER, timeout=2.0)
            if offered:
                break
        check("收到 OFFER", bool(offered),
              (offered.yiaddr if offered else "6 次重试都没有回应"))
        if not offered:
            return 1

        req = D.build_client_packet(
            D.REQUEST, FAKE_MAC, xid,
            requested_ip=offered.yiaddr, server_id=offered.get_ip(D.O_SERVER_ID),
            vendor_class="iDRAC", hostname="idrac-simulated",
        )
        acked = None
        for _ in range(4):
            if client_iface:
                _send_raw(client_iface, req.pack(), log)
            else:
                try:
                    cli.sendto(req.pack(), ("255.255.255.255", 67))
                except OSError:
                    cli.sendto(req.pack(), ("127.0.0.1", 67))
            acked = _recv(cli, D.ACK, timeout=1.5)
            if acked:
                break
        check("收到 ACK", bool(acked), acked.yiaddr if acked else "没有回应")
        if not acked:
            return 1
        check("OFFER 与 ACK 地址一致", offered.yiaddr == acked.yiaddr, acked.yiaddr)
        check("租期/掩码/网关齐全", bool(
            acked.get_u32(D.O_LEASE_TIME) and acked.get_ip(D.O_SUBNET_MASK)),
            "%ss / %s / %s" % (acked.get_u32(D.O_LEASE_TIME),
                               acked.get_ip(D.O_SUBNET_MASK),
                               acked.get_ip(D.O_ROUTER) or "无网关"))

        time.sleep(0.4)
        leases = [l for l in session.snapshot(0)["leases"] if l["mac"] == FAKE_MAC]
        check("服务器租约表里有这台设备", bool(leases) and leases[0]["bound"],
              "%s %s" % (leases[0]["ip"], leases[0]["hostname"]) if leases else "没记录")
        cli.close()

        # ---- 假装它还有管理页面 ----
        if with_web:
            ip = acked.yiaddr
            if loopback:
                check("管理页探测", None, "环回模式跳过（地址不真实）")
            elif not I.is_root():
                check("管理页探测", None, "需要管理员权限才能临时挂地址")
            else:
                I.add_alias(srv_iface.name, ip, "255.255.255.0")
                alias_ip = ip
                time.sleep(0.4)
                srv = _start_fake_bmc(ip, tmpdir)
                if srv is None:
                    check("管理页探测", False,
                          "自签证书没生成：PATH 里要有 openssl（Windows 上可用 "
                          "--no-web 跳过这一项）")
                else:
                    time.sleep(0.3)
                    fp = session.probe(ip)
                    good = fp.get("vendor") == "Dell iDRAC" and fp.get("url", "").startswith("https://")
                    check("探测到厂商和管理地址", good,
                          "%s %s → %s" % (fp.get("vendor"), fp.get("confidence"),
                                          fp.get("url") or fp.get("ports")))

        console.raw()
        passed = sum(1 for _, ok, _ in results if ok is True)
        failed = sum(1 for _, ok, _ in results if ok is False)
        skipped = sum(1 for _, ok, _ in results if ok is None)
        suffix = ("，%d 项跳过" % skipped) if skipped else ""
        if failed == 0:
            console.ok("%d 项通过%s：这台 Mac 上的 DHCP 链路是通的" % (passed, suffix))
            console.raw("  真机接上以后，界面上应该出现同样的 DISCOVER → ACK → FOUND。")
            return 0
        console.err("%d 项失败，%d 项通过%s" % (failed, passed, suffix))
        return 1
    finally:
        if srv is not None:
            try:
                srv.shutdown()
            except Exception:
                pass
        if alias_ip:
            I.remove_alias(srv_iface.name, alias_ip)
        if not keep:
            session.shutdown()
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)
