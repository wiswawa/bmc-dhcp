"""单测：不碰真实网卡、不需要 root。跑法：

    PYTHONPATH=src python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# 测试隔离：把 BMCD_HOME 钉到一个临时目录。
# session.py / webapp.py 在 import 期就用 user_home() 算出了 state.json / web.json
# 的完整路径，所以这一段必须排在 `from bmcdhcp import ...` 之前；否则整套测试
# 会往真实家目录里建 ~/.bmcd（实测会留下一个空目录）。
# ---------------------------------------------------------------------------
def _isolate_test_home() -> str:
    home = os.environ.get("BMCD_TEST_HOME") or tempfile.mkdtemp(prefix="bmcd-test-home-")
    os.environ["BMCD_HOME"] = home
    os.environ["BMCD_TEST_HOME"] = home
    return home


TEST_HOME = _isolate_test_home()

from bmcdhcp import cli                # noqa: E402
from bmcdhcp import dhcp as D          # noqa: E402
from bmcdhcp import discover           # noqa: E402
from bmcdhcp import engines, vendors   # noqa: E402
from bmcdhcp import iface as I         # noqa: E402
from bmcdhcp.core import ServerConfig, ServerCore  # noqa: E402
from bmcdhcp.leases import LeaseManager            # noqa: E402

import support_ports                               # noqa: E402  测试端口分配器（禁止写死端口）


def make_core(**overrides):
    cfg_kwargs = dict(
        server_ip="10.99.0.1",
        network="10.99.0.0/24",
        pool_start="10.99.0.100",
        pool_end="10.99.0.105",
        lease_seconds=300,
        routers=["10.99.0.1"],
    )
    cfg_kwargs.update(overrides)
    cfg = ServerConfig(**cfg_kwargs)
    leases = LeaseManager(
        server_ip=cfg.server_ip,
        network=cfg.network,
        pool_start=cfg.pool_start,
        pool_end=cfg.pool_end,
        lease_seconds=cfg.lease_seconds,
        state_path=None,
    )
    events = []
    core = ServerCore(cfg, leases, on_event=events.append)
    return cfg, leases, core, events


def discover_packet(mac="aa:bb:cc:00:00:01", xid=1, vendor="iDRAC", hint=None):
    pkt = D.build_client_packet(
        D.DISCOVER, mac, xid, vendor_class=vendor, hostname="idrac-x", requested_ip=hint
    )
    return pkt


def request_packet(mac, xid, server_id, ip):
    return D.build_client_packet(
        D.REQUEST, mac, xid, requested_ip=ip, server_id=server_id, vendor_class="iDRAC"
    )


class TestCodec(unittest.TestCase):
    def test_roundtrip(self):
        pkt = discover_packet()
        pkt.set(D.O_CLIENT_ID, b"\x01\xaa\xbb\xcc\x00\x00\x01")
        blob = pkt.pack()
        back = D.DHCPMessage.parse(blob)
        self.assertEqual(back.xid, pkt.xid)
        self.assertEqual(back.mac, pkt.mac)
        self.assertEqual(back.msg_type, D.DISCOVER)
        self.assertEqual(back.get_str(D.O_VENDOR_CLASS), "iDRAC")
        self.assertEqual(back.get(D.O_CLIENT_ID), b"\x01\xaa\xbb\xcc\x00\x00\x01")
        self.assertEqual(bytes(back.pack()), blob)

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            D.DHCPMessage.parse(b"hello")
        with self.assertRaises(ValueError):
            D.DHCPMessage.parse(b"\x02" * 250)  # 长度够但没有 magic cookie

    def test_option_overload_file(self):
        """option 52 让 file 字段也当 options 用。"""
        pkt = discover_packet()
        pkt.file = bytes([D.O_VENDOR_CLASS, 5]) + b"iDRAC" + b"\xff"
        pkt.file = pkt.file.ljust(128, b"\x00")
        pkt.set(D.O_OVERLOAD, b"\x01")
        back = D.DHCPMessage.parse(pkt.pack())
        self.assertEqual(back.get_str(D.O_VENDOR_CLASS), "iDRAC")

    def test_long_option_chunks(self):
        pkt = discover_packet()
        pkt.set_str(43, "x" * 300)
        back = D.DHCPMessage.parse(pkt.pack())
        self.assertEqual(back.get_str(43), "x" * 300)


class TestDora(unittest.TestCase):
    def test_full_cycle(self):
        cfg, leases, core, events = make_core()
        replies = core.handle(discover_packet(), "aa:bb:cc:00:00:01")
        self.assertEqual(len(replies), 1)
        offer = replies[0]
        self.assertEqual(offer.msg.msg_type, D.OFFER)
        self.assertEqual(offer.msg.yiaddr, "10.99.0.100")
        self.assertEqual(offer.msg.get_ip(D.O_SUBNET_MASK), "255.255.255.0")
        self.assertEqual(offer.msg.get_ip(D.O_SERVER_ID), "10.99.0.1")
        self.assertEqual(offer.msg.get_u32(D.O_LEASE_TIME), 300)
        self.assertTrue(offer.broadcast)

        req = request_packet("aa:bb:cc:00:00:01", 1, "10.99.0.1", offer.msg.yiaddr)
        replies = core.handle(req, "aa:bb:cc:00:00:01")
        self.assertEqual(replies[0].msg.msg_type, D.ACK)
        self.assertEqual(replies[0].msg.yiaddr, "10.99.0.100")
        self.assertTrue(leases.get("10.99.0.100").bound)
        self.assertEqual(leases.sticky["aa:bb:cc:00:00:01"], "10.99.0.100")

    def test_echo_vendor_and_client_id(self):
        cfg, leases, core, events = make_core()
        pkt = discover_packet()
        pkt.set(D.O_CLIENT_ID, b"\x01\xaa\xbb\xcc\x00\x00\x01")
        offer = core.handle(pkt, "aa:bb:cc:00:00:01")[0].msg
        self.assertEqual(offer.get_str(D.O_VENDOR_CLASS), "iDRAC")
        self.assertEqual(offer.get(D.O_CLIENT_ID), b"\x01\xaa\xbb\xcc\x00\x00\x01")

    def test_sticky_same_mac(self):
        cfg, leases, core, events = make_core()
        first = core.handle(discover_packet(), "aa:bb:cc:00:00:01")[0].msg.yiaddr
        core.handle(request_packet("aa:bb:cc:00:00:01", 1, cfg.server_ip, first), "aa:bb:cc:00:00:01")
        # 换 xid 再来一次 DISCOVER
        second = core.handle(discover_packet(xid=99), "aa:bb:cc:00:00:01")[0].msg.yiaddr
        self.assertEqual(first, second)

    def test_two_clients_get_different_ips(self):
        cfg, leases, core, events = make_core()
        a = core.handle(discover_packet("aa:bb:cc:00:00:01", 1), "aa:bb:cc:00:00:01")[0].msg.yiaddr
        b = core.handle(discover_packet("aa:bb:cc:00:00:02", 2), "aa:bb:cc:00:00:02")[0].msg.yiaddr
        self.assertNotEqual(a, b)

    def test_request_other_server_ignored(self):
        cfg, leases, core, events = make_core()
        req = request_packet("aa:bb:cc:00:00:01", 1, "10.99.0.254", "10.99.0.50")
        self.assertEqual(core.handle(req, "aa:bb:cc:00:00:01"), [])
        self.assertTrue(any(e["type"] == "request_other" for e in events))

    def test_nak_for_out_of_pool(self):
        cfg, leases, core, events = make_core()
        req = request_packet("aa:bb:cc:00:00:01", 1, cfg.server_ip, "10.99.0.250")
        replies = core.handle(req, "aa:bb:cc:00:00:01")
        self.assertEqual(replies[0].msg.msg_type, D.NAK)
        self.assertEqual(replies[0].msg.yiaddr, "0.0.0.0")

    def test_pool_exhaustion(self):
        cfg, leases, core, events = make_core(pool_end="10.99.0.101")
        got = []
        for i in range(3):
            mac = "aa:bb:cc:00:00:%02x" % i
            replies = core.handle(discover_packet(mac, i), mac)
            got.append(replies[0].msg.yiaddr if replies else "")
        self.assertEqual(sorted(got[:2]), ["10.99.0.100", "10.99.0.101"])
        self.assertEqual(got[2], "")
        self.assertTrue(any(e["type"] == "pool_exhausted" for e in events))

    def test_decline_blacklists(self):
        cfg, leases, core, events = make_core()
        ip = core.handle(discover_packet(), "aa:bb:cc:00:00:01")[0].msg.yiaddr
        pkt = D.build_client_packet(D.DECLINE, "aa:bb:cc:00:00:01", 5, requested_ip=ip)
        core.handle(pkt, "aa:bb:cc:00:00:01")
        self.assertTrue(leases.is_bad(ip))
        # 另一个客户端不会拿到这个地址
        other = core.handle(discover_packet("aa:bb:cc:00:00:02", 6), "aa:bb:cc:00:00:02")[0].msg.yiaddr
        self.assertNotEqual(other, ip)

    def test_other_mac_cannot_steal_offered_address(self):
        """A 刚被 OFFER 的地址，B 直接 REQUEST 不能拿走。"""
        cfg, leases, core, events = make_core(pool_end="10.99.0.100")
        offer = core.handle(discover_packet("aa:bb:cc:00:00:01", 1), "aa:bb:cc:00:00:01")[0].msg
        self.assertEqual(offer.yiaddr, "10.99.0.100")
        req = request_packet("aa:bb:cc:00:00:02", 2, cfg.server_ip, "10.99.0.100")
        replies = core.handle(req, "aa:bb:cc:00:00:02")
        self.assertEqual(replies[0].msg.msg_type, D.NAK)
        # 原主还能正常拿到
        replies = core.handle(request_packet("aa:bb:cc:00:00:01", 1, cfg.server_ip,
                                             "10.99.0.100"), "aa:bb:cc:00:00:01")
        self.assertEqual(replies[0].msg.msg_type, D.ACK)

    def test_t1_t2_within_lease(self):
        for lease in (30, 45, 60, 103, 300, 3600):
            cfg, leases, core, events = make_core(lease_seconds=lease)
            offer = core.handle(discover_packet(), "aa:bb:cc:00:00:01")[0].msg
            t1 = offer.get_u32(D.O_T1)
            t2 = offer.get_u32(D.O_T2)
            self.assertEqual(offer.get_u32(D.O_LEASE_TIME), lease)
            self.assertLess(t1, t2, "lease=%s" % lease)
            self.assertLess(t2, lease, "lease=%s" % lease)

    def test_release_then_reallocate(self):
        cfg, leases, core, events = make_core()
        ip = core.handle(discover_packet(), "aa:bb:cc:00:00:01")[0].msg.yiaddr
        core.handle(request_packet("aa:bb:cc:00:00:01", 1, cfg.server_ip, ip), "aa:bb:cc:00:00:01")
        rel = D.build_client_packet(D.RELEASE, "aa:bb:cc:00:00:01", 7, ciaddr=ip)
        core.handle(rel, "aa:bb:cc:00:00:01")
        self.assertFalse(leases.get(ip).bound)

    def test_lease_expiry_reuses_address(self):
        cfg, leases, core, events = make_core()
        now = [1000.0]
        core.clock = lambda: now[0]
        ip = core.handle(discover_packet(), "aa:bb:cc:00:00:01")[0].msg.yiaddr
        core.handle(request_packet("aa:bb:cc:00:00:01", 1, cfg.server_ip, ip), "aa:bb:cc:00:00:01")
        self.assertTrue(leases.get(ip).bound)
        now[0] += 301
        core.handle(discover_packet("aa:bb:cc:00:00:02", 2), "aa:bb:cc:00:00:02")
        self.assertFalse(leases.get(ip).bound)

    def test_unicast_route_when_renewing(self):
        cfg, leases, core, events = make_core()
        ip = core.handle(discover_packet(), "aa:bb:cc:00:00:01")[0].msg.yiaddr
        core.handle(request_packet("aa:bb:cc:00:00:01", 1, cfg.server_ip, ip), "aa:bb:cc:00:00:01")
        renew = D.build_client_packet(
            D.REQUEST, "aa:bb:cc:00:00:01", 2, ciaddr=ip, broadcast=False
        )
        reply = core.handle(renew, "aa:bb:cc:00:00:01")[0]
        self.assertFalse(reply.broadcast)
        self.assertEqual(reply.dst_ip, ip)

    def test_inform(self):
        cfg, leases, core, events = make_core()
        pkt = D.build_client_packet(D.INFORM, "aa:bb:cc:00:00:01", 3, ciaddr="10.99.0.77")
        reply = core.handle(pkt, "aa:bb:cc:00:00:01")[0]
        self.assertEqual(reply.msg.msg_type, D.ACK)
        self.assertEqual(reply.msg.yiaddr, "0.0.0.0")
        self.assertEqual(reply.msg.get_ip(D.O_SUBNET_MASK), "255.255.255.0")

    def test_no_router_when_requested(self):
        cfg, leases, core, events = make_core(routers=[])
        offer = core.handle(discover_packet(), "aa:bb:cc:00:00:01")[0].msg
        self.assertIsNone(offer.get(D.O_ROUTER))


class TestFrameParse(unittest.TestCase):
    def test_parse_udp_frame(self):
        payload = discover_packet().pack()
        udp_len = 8 + len(payload)
        ip_len = 20 + udp_len
        ip = bytes.fromhex("45 00") + ip_len.to_bytes(2, "big") + b"\x00\x00\x00\x00\x40\x11\x00\x00"
        ip += bytes([10, 99, 0, 1]) + bytes([255, 255, 255, 255])
        udp = (68).to_bytes(2, "big") + (67).to_bytes(2, "big") + udp_len.to_bytes(2, "big") + b"\x00\x00"
        frame = b"\xff" * 6 + bytes.fromhex("aabbccddeeff") + b"\x08\x00" + ip + udp + payload
        parsed = engines.parse_eth_ipv4_udp(frame)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.src_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsed.src_ip, "10.99.0.1")
        self.assertEqual(parsed.dport, 67)
        self.assertEqual(parsed.sport, 68)
        self.assertEqual(bytes(parsed.payload), payload)

    def test_reject_non_udp(self):
        self.assertIsNone(engines.parse_eth_ipv4_udp(b"\x00" * 20))

    def test_parse_vlan_tagged_frame(self):
        payload = discover_packet().pack()
        udp_len = 8 + len(payload)
        ip_len = 20 + udp_len
        ip = bytes.fromhex("45 00") + ip_len.to_bytes(2, "big") + b"\x00\x00\x00\x00\x40\x11\x00\x00"
        ip += bytes([10, 99, 0, 1]) + bytes([255, 255, 255, 255])
        udp = (68).to_bytes(2, "big") + (67).to_bytes(2, "big") + udp_len.to_bytes(2, "big") + b"\x00\x00"
        frame = (b"\xff" * 6 + bytes.fromhex("aabbccddeeff") + b"\x81\x00" + b"\x00\x64"
                 + b"\x08\x00" + ip + udp + payload)
        parsed = engines.parse_eth_ipv4_udp(frame)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.dport, 67)
        self.assertEqual(parsed.src_mac, "aa:bb:cc:dd:ee:ff")


class TestCliProbeArpVisibility(unittest.TestCase):
    """t18-F2：`bmcd probe` 在 ARP 查询失败时不能只说「确认网线」。"""

    def test_probe_reports_arp_failure(self):
        args = argparse.Namespace(ips=["10.0.0.9"], cidr=None, no_color=True)
        out = io.StringIO()
        with mock.patch.object(discover, "ARP", ""), \
                mock.patch.object(discover, "arp_binary", lambda: ""), \
                mock.patch.object(discover, "scan_ports", lambda *a, **k: []), \
                mock.patch.object(discover, "rmcp_ping", lambda *a, **k: (False, "")), \
                contextlib.redirect_stdout(out):
            code = cli.cmd_probe(args)
        text = out.getvalue()
        self.assertEqual(code, 1, text)
        self.assertIn("ARP 查询失败", text)
        self.assertIn("找不到 arp 命令", text)
        # 旧文案把「没响应」直接归因到网线，会把人带偏
        self.assertNotIn("都没响应。确认网线/网段/防火墙。", text)

    def test_probe_without_arp_problem_keeps_old_hint(self):
        fake_fp = discover.Fingerprint(ip="10.0.0.9", alive=False)
        with mock.patch.object(discover, "probe", lambda ip, timeout=0.9: fake_fp), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.cmd_probe(argparse.Namespace(ips=["10.0.0.9"], cidr=None,
                                                    no_color=True))
        self.assertEqual(code, 1)
        self.assertIn("都没响应。确认网线/网段/防火墙。", out.getvalue())
        self.assertNotIn("ARP 查询失败", out.getvalue())


class TestEnginePortGuard(unittest.TestCase):
    """端口守卫：端口一律向系统现要（见 support_ports），绝不写死。

    写死端口会带来两种假失败：
      1) 两套全套测试并行跑时互相抢端口（先起的占住，后起的先绑失败 → 卡住/rc=143）；
      2) 用户机器上真实 bmcd、系统「互联网共享」等程序正好占着那个端口。
    """

    def _fixtures(self):
        from bmcdhcp.iface import Interface

        cfg = ServerConfig(server_ip="127.0.0.1", network="127.0.0.0/8",
                           pool_start="127.0.0.2", pool_end="127.0.0.9")
        core = ServerCore(cfg, LeaseManager(cfg.server_ip, cfg.network,
                                            cfg.pool_start, cfg.pool_end, state_path=None))
        return core, Interface(name="lo0", ipv4="127.0.0.1", netmask="255.0.0.0")

    def _engine(self, core, fake, port):
        return engines.UdpEngine(fake, core, lambda *a: None,
                                 bind_ip=support_ports.HOST, bind_port=port,
                                 reply_targets=[(support_ports.HOST,
                                                 support_ports.free_udp_port())])

    def test_second_udp_engine_on_same_port_fails(self):
        core, fake = self._fixtures()
        tried = []
        for _ in range(6):
            port = support_ports.acquire_udp_port()
            tried.append(port)
            first = self._engine(core, fake, port)
            ready = threading.Event()
            thread = threading.Thread(target=first.start, kwargs={"on_ready": ready.set},
                                      daemon=True)
            thread.start()
            try:
                if not ready.wait(5.0):
                    # 端口在我们拿到之后被外部抢走了 → 换一个端口重来（自愈，不假失败）
                    continue
                second = self._engine(core, fake, port)
                with self.assertRaises(engines.EngineUnavailable) as ctx:
                    second.start()
                self.assertIn("已被占用", str(ctx.exception))
                self.assertIn("UDP/%d" % port, str(ctx.exception))
                return
            finally:
                first.stop()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive(), "第一个引擎 stop 之后收包线程还活着")
        self.fail("连着 %d 次都没能把第一个引擎绑上（试过 UDP %s）—— 端口一直在被外部抢走"
                  % (len(tried), tried))

    def test_udp_engine_reports_port_already_held(self):
        """「端口被占用」场景由用例自己占住端口，不依赖外部环境。"""
        core, fake = self._fixtures()
        with support_ports.occupy_udp() as (_sock, port):
            self.assertFalse(support_ports.is_udp_port_free(port),
                             "自带占用者没占上 UDP/%d，场景不成立" % port)
            with self.assertRaises(engines.EngineUnavailable) as ctx:
                self._engine(core, fake, port).start()
        self.assertIn("UDP/%d 已被占用" % port, str(ctx.exception))
        self.assertIn("互联网共享", str(ctx.exception))     # 报错要能指导用户排障


class TestSupportPorts(unittest.TestCase):
    """分配器自身必须靠谱：同一进程连续取 24 个端口全部不同且都能立刻绑上。"""

    def test_udp_port_allocator_yields_24_distinct_bindable_ports(self):
        wanted = 24
        bound = []
        socks = []
        try:
            for _ in range(wanted):
                port = support_ports.acquire_udp_port()
                for _attempt in range(4):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        sock.bind((support_ports.HOST, port))
                    except OSError:
                        sock.close()
                        port = support_ports.free_udp_port()   # 被抢走 → 换一个
                        continue
                    socks.append(sock)
                    bound.append(port)
                    break
                else:
                    self.fail("换了 4 个端口都绑不上，分配器不可用（最后试的是 UDP/%d）" % port)
            self.assertEqual(wanted, len(bound))
            self.assertEqual(wanted, len(set(bound)),
                             "分配器给出的端口有重复：%s" % sorted(bound))
            self.assertTrue(all(isinstance(p, int) and 0 < p < 65536 for p in bound), bound)
        finally:
            for sock in socks:
                sock.close()

    def test_udp_allocator_self_heals_when_candidate_is_taken(self):
        with support_ports.occupy_udp() as (_sock, busy):
            good = support_ports.free_udp_port()
            with mock.patch.object(support_ports, "free_udp_port",
                                   side_effect=[busy, good, good]):
                self.assertEqual(good, support_ports.acquire_udp_port())

    def test_udp_allocator_fails_loudly_when_every_candidate_is_taken(self):
        with support_ports.occupy_udp() as (_sock, busy):
            with mock.patch.object(support_ports, "free_udp_port", return_value=busy):
                with self.assertRaises(RuntimeError) as ctx:
                    support_ports.acquire_udp_port(attempts=3)
        self.assertIn("被别人占走", str(ctx.exception))
        self.assertIn(str(busy), str(ctx.exception))

    def test_udp_allocator_fails_loudly_when_system_is_exhausted(self):
        with mock.patch.object(support_ports, "_probe", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                support_ports.free_udp_port(attempts=2)
        self.assertIn("拿不到空闲 UDP 端口", str(ctx.exception))

    def test_tcp_port_allocator_is_bindable(self):
        port = support_ports.free_tcp_port()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind((support_ports.HOST, port))
        finally:
            sock.close()

    def test_occupy_udp_holds_and_releases_the_port(self):
        with support_ports.occupy_udp() as (sock, port):
            self.assertEqual(port, int(sock.getsockname()[1]))
            self.assertFalse(support_ports.is_udp_port_free(port))
        self.assertTrue(support_ports.is_udp_port_free(port),
                        "占用者退出后 UDP/%d 应该放开" % port)

    def test_wait_udp_bound_detects_holder(self):
        with support_ports.occupy_udp() as (_sock, port):
            self.assertTrue(support_ports.wait_udp_bound(port, timeout=1.0))
        self.assertFalse(support_ports.wait_udp_bound(support_ports.free_udp_port(),
                                                      timeout=0.2))

    # ------------------------------------------------------------------
    # 防回归：任何 test_*.py 里都不许再出现写死的 bind_port
    # ------------------------------------------------------------------
    @staticmethod
    def _scan_fixed_bind_ports(directory):
        found = []
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".py"):
                continue
            path = os.path.join(directory, name)
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
            try:
                tree = ast.parse(source, filename=path)
            except SyntaxError:                     # 解析不了的不要在这里报（不是本用例职责）
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                for kw in node.keywords:
                    if kw.arg != "bind_port":
                        continue
                    value = kw.value
                    if isinstance(value, ast.Constant) and isinstance(value.value, int) \
                            and value.value != 0:
                        found.append("%s:%d bind_port=%d" % (name, value.lineno, value.value))
        return found

    def test_no_test_file_hardcodes_a_fixed_bind_port(self):
        tests_dir = os.path.dirname(os.path.abspath(__file__))
        found = self._scan_fixed_bind_ports(tests_dir)
        self.assertEqual([], found,
                         "测试里出现了写死的 bind_port，并行/端口被占时会假失败：%s；"
                         "请改成 support_ports.acquire_udp_port()" % found)

    def test_guard_detects_a_planted_fixed_bind_port(self):
        tmp = tempfile.mkdtemp(prefix="bmcd-port-guard-")
        try:
            planted = os.path.join(tmp, "test_planted.py")
            with open(planted, "w", encoding="utf-8") as fh:
                fh.write("def f(engine):\n"
                         "    return engine.bind(bind_port=6771)\n"
                         "def ok(engine):\n"
                         "    return engine.bind(bind_port=0)\n")
            found = self._scan_fixed_bind_ports(tmp)
        finally:
            for name in os.listdir(tmp):
                os.unlink(os.path.join(tmp, name))
            os.rmdir(tmp)
        self.assertEqual(1, len(found), found)
        self.assertIn("bind_port=6771", found[0])
        self.assertIn(":2", found[0])               # 行号要能定位


class TestVendors(unittest.TestCase):
    def test_http_title_wins_over_oui(self):
        ident = vendors.identify(mac="b0:83:fe:00:00:01", http_title="iDRAC Virtual Console")
        self.assertEqual(ident.vendor, "Dell iDRAC")
        self.assertEqual(ident.confidence, "高")

    def test_oui_only_is_low_confidence(self):
        ident = vendors.identify(mac="00:25:90:aa:bb:cc")
        self.assertEqual(ident.vendor, "Supermicro")
        self.assertEqual(ident.confidence, "低")

    def test_tls_cn_ilo(self):
        ident = vendors.identify(mac="", tls_cn="iLO5-ABCD1234")
        self.assertEqual(ident.vendor, "HPE iLO")

    def test_unknown(self):
        self.assertFalse(vendors.identify(mac="02:00:00:00:00:01").known)


class TestLeaseManager(unittest.TestCase):
    def test_invalid_pool_rejected(self):
        with self.assertRaises(ValueError):
            LeaseManager("10.99.0.1", "10.99.0.0/24", "10.99.1.10", "10.99.1.20")

    def test_state_roundtrip(self):
        import tempfile

        path = os.path.join(tempfile.mkdtemp(), "state.json")
        lm = LeaseManager("10.99.0.1", "10.99.0.0/24", "10.99.0.100", "10.99.0.110",
                          lease_seconds=60, state_path=path)
        ip = lm.offer("aa:bb:cc:00:00:01")
        lm.bind(ip, "aa:bb:cc:00:00:01", hostname="idrac")
        lm2 = LeaseManager("10.99.0.1", "10.99.0.0/24", "10.99.0.100", "10.99.0.110",
                           lease_seconds=60, state_path=path)
        self.assertEqual(lm2.sticky.get("aa:bb:cc:00:00:01"), ip)
        self.assertEqual(lm2.offer("aa:bb:cc:00:00:01"), ip)

    def test_stats(self):
        lm = LeaseManager("10.99.0.1", "10.99.0.0/24", "10.99.0.100", "10.99.0.104")
        ip = lm.offer("aa:bb:cc:00:00:01")
        lm.bind(ip, "aa:bb:cc:00:00:01")
        stats = lm.stats()
        self.assertEqual(stats["bound"], 1)
        self.assertEqual(stats["pool"], 5)


class TestCliHelpers(unittest.TestCase):
    def test_parse_pool_forms(self):
        import ipaddress

        from bmcdhcp.cli import parse_pool

        net = ipaddress.IPv4Network("10.99.0.0/24")
        self.assertEqual(parse_pool("10.99.0.100-10.99.0.200", net), ("10.99.0.100", "10.99.0.200"))
        self.assertEqual(parse_pool(".100-.200", net), ("10.99.0.100", "10.99.0.200"))
        self.assertEqual(parse_pool("100-200", net), ("10.99.0.100", "10.99.0.200"))
        self.assertEqual(parse_pool("10.99.0.50", net), ("10.99.0.50", "10.99.0.50"))

    def test_parse_pool_rejects_outside(self):
        import ipaddress

        from bmcdhcp.cli import parse_pool
        from bmcdhcp.session import SessionError

        with self.assertRaises(SessionError):
            parse_pool("10.99.1.1", ipaddress.IPv4Network("10.99.0.0/24"))


class TestIfaceHelpers(unittest.TestCase):
    def test_hex_mask(self):
        from bmcdhcp.iface import broadcast_of, mask_to_dotted

        self.assertEqual(mask_to_dotted("0xffffff00"), "255.255.255.0")
        self.assertEqual(mask_to_dotted("0xff000000"), "255.0.0.0")
        self.assertEqual(mask_to_dotted("255.255.0.0"), "255.255.0.0")
        self.assertEqual(broadcast_of("10.99.0.1", "0xffffff00"), "10.99.0.255")
        self.assertEqual(broadcast_of("192.168.10.52", "255.255.255.0"), "192.168.10.255")


class TestIfaceVirtual(unittest.TestCase):
    """mac 上哪些接口算「虚拟」——这决定了下拉框里会不会出现一堆没用的口。"""

    def test_virtual_families(self):
        from bmcdhcp import iface as I

        for name in ("utun0", "utun7", "gif0", "stf0", "awdl0", "llw0",
                     "anpi0", "ap1", "bridge0", "bridge100", "vmenet0",
                     "vmnet1", "feth0", "ipsec0", "ppp0", "tap0", "tun0", "vlan3"):
            self.assertTrue(I._mac_is_virtual(name, ""), name)

    def test_physical_families(self):
        from bmcdhcp import iface as I

        for name in ("en0", "en1", "en7", "en13"):
            self.assertFalse(I._mac_is_virtual(name, ""), name)

    def test_media_hint(self):
        from bmcdhcp import iface as I

        self.assertTrue(I._mac_is_virtual("en9", "VMware Virtual Ethernet Adapter"))
        self.assertFalse(I._mac_is_virtual("en9", "USB 10/100/1000 LAN"))

    def test_wifi_is_not_virtual(self):
        """开了「互联网共享」时 en0 也是桥成员，但它是唯一能用的口，不能藏。"""
        from bmcdhcp import iface as I

        self.assertFalse(I._mac_is_virtual("en0", "Broadcom Wi-Fi"))


class TestCliIfaceDiagnostics(unittest.TestCase):
    """`bmcd ifaces` 要把每级枚举源的结果打出来（读不到网卡时这是唯一线索）。"""

    def _iface(self):
        return I.Interface(name="以太网 2", service="以太网 2", mac="aa:bb:cc:dd:ee:01",
                           ipv4="192.168.0.10", netmask="255.255.255.0",
                           link="active", up=True, running=True, source="ctypes")

    def test_ifaces_json_payload(self):
        iface = self._iface()
        args = argparse.Namespace(no_color=True, json=True)
        buf = io.StringIO()
        report = {"source": "ctypes", "error": "",
                  "sources": [{"source": "ctypes", "ok": True, "count": 1, "ms": 2,
                               "error": "", "skipped": False}],
                  "cached": False}
        with mock.patch.object(I, "enumerate_all", return_value=[iface]), \
                mock.patch.object(I, "ethernet_candidates", return_value=[iface]), \
                mock.patch.object(I.winnet, "adapter_report", return_value=report), \
                mock.patch.object(I, "IS_WINDOWS", True), \
                contextlib.redirect_stdout(buf):
            code = cli.cmd_ifaces(args)
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["source"], "ctypes")
        self.assertEqual(data["ifaces"][0]["name"], "以太网 2")
        self.assertEqual(data["candidates"], ["以太网 2"])
        self.assertTrue(data["sources"][0]["ok"])

    def test_ifaces_text_mode_prints_per_source_report(self):
        iface = self._iface()
        args = argparse.Namespace(no_color=True, json=False)
        buf = io.StringIO()
        report = {"source": "", "error": "ctypes：GAA 炸了",
                  "sources": [
                      {"source": "ctypes", "ok": False, "count": 0, "ms": 1,
                       "error": "GAA 炸了", "skipped": False},
                      {"source": "powershell", "ok": True, "count": 1, "ms": 900,
                       "error": "", "skipped": False}],
                  "cached": False}
        with mock.patch.object(I, "enumerate_all", return_value=[iface]), \
                mock.patch.object(I, "ethernet_candidates", return_value=[iface]), \
                mock.patch.object(I.winnet, "adapter_report", return_value=report), \
                mock.patch.object(I, "IS_WINDOWS", True), \
                contextlib.redirect_stdout(buf):
            code = cli.cmd_ifaces(args)
        out = buf.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("ctypes", out)
        self.assertIn("GAA 炸了", out)
        self.assertIn("powershell", out)

    def test_ifaces_empty_returns_nonzero(self):
        args = argparse.Namespace(no_color=True, json=False)
        buf = io.StringIO()
        report = {"source": "", "error": "ctypes：x；powershell：y；ipconfig：z",
                  "sources": [], "cached": False}
        with mock.patch.object(I, "enumerate_all", return_value=[]), \
                mock.patch.object(I.winnet, "adapter_report", return_value=report), \
                mock.patch.object(I, "IS_WINDOWS", True), \
                contextlib.redirect_stdout(buf):
            code = cli.cmd_ifaces(args)
        self.assertEqual(code, 1)
        self.assertIn("一张网卡都没读到", buf.getvalue())

    def test_selftest_enum_check_runs_on_this_platform(self):
        ok, detail = cli._adapter_enum_check()
        self.assertIsInstance(ok, bool)
        self.assertTrue(detail)


class TestDnsmasqLeaseDir(unittest.TestCase):
    """附录 D-1：leasefile 必须落在引擎自己的 workdir 里，不能落在进程 CWD。

    以前 self.leasefile = os.path.join(workdir, ...) 用的是入参，workdir="" 时
    就是相对路径 "dnsmasq.leases" —— 从访达启动 App 时 CWD 是 /，dnsmasq 写不进去，
    _poll_leases 也读不回来，界面上永远看不到 dnsmasq 引擎的租约。
    """

    def setUp(self):
        self._cwd = os.getcwd()
        self.cwd = tempfile.mkdtemp(prefix="bmcd-fake-cwd-")
        os.chdir(self.cwd)
        self.addCleanup(os.chdir, self._cwd)

    def _engine(self, workdir="", on_lease=None):
        from bmcdhcp.iface import Interface

        cfg, _leases, core, _events = make_core()
        fake = Interface(name="en9", ipv4="10.99.0.1", netmask="255.255.255.0")
        # 本机没装 dnsmasq 也要能测：只把二进制探测换成固定值，其余逻辑走真的
        with mock.patch.object(engines.shutil, "which", return_value="/usr/local/bin/dnsmasq"):
            return engines.DnsmasqEngine(fake, core, lambda *a: None,
                                         workdir=workdir, on_lease=on_lease)

    def test_leasefile_lives_in_workdir_when_workdir_is_blank(self):
        engine = self._engine("")
        self.assertTrue(os.path.isabs(engine.workdir), engine.workdir)
        self.assertTrue(os.path.isabs(engine.leasefile), engine.leasefile)
        self.assertEqual(os.path.dirname(engine.leasefile), engine.workdir)
        self.assertIn("bmcd-dnsmasq-", engine.workdir)

    def test_leasefile_is_absolute_for_relative_workdir(self):
        engine = self._engine("relwork")
        self.assertTrue(os.path.isabs(engine.workdir), engine.workdir)
        # macOS 的 /var 是指向 /private/var 的符号链接，两边都取 realpath 再比
        self.assertEqual(os.path.realpath(engine.workdir),
                         os.path.realpath(os.path.join(self.cwd, "relwork")))
        self.assertEqual(os.path.dirname(engine.leasefile), engine.workdir)

    def test_start_passes_absolute_leasefile_everywhere(self):
        """conf 和命令行里都必须是同一个绝对路径。"""
        engine = self._engine("")
        seen = {}

        class FakeProc:
            returncode = 0

            def poll(self):
                return 0

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

            def kill(self):
                pass

        def fake_popen(args, **kwargs):
            seen["args"] = list(args)
            return FakeProc()

        with mock.patch.object(engines.subprocess, "Popen", fake_popen):
            engine.start()          # 假进程立刻"退出"，start 会自己收尾

        argv = seen["args"]
        lease_args = [a for a in argv if a.startswith("--dhcp-leasefile=")]
        self.assertEqual(len(lease_args), 1, argv)
        self.assertEqual(lease_args[0], "--dhcp-leasefile=%s" % engine.leasefile)
        self.assertTrue(os.path.isabs(lease_args[0].split("=", 1)[1]))
        with open(os.path.join(engine.workdir, "dnsmasq.conf"), encoding="utf-8") as fh:
            conf = fh.read()
        self.assertIn("dhcp-leasefile=%s" % engine.leasefile, conf)
        self.assertNotIn("dhcp-leasefile=dnsmasq.leases", conf)
        self.assertFalse(os.path.exists(os.path.join(self.cwd, "dnsmasq.leases")))

    def test_no_leasefile_residue_in_cwd(self):
        engine = self._engine("")
        os.makedirs(engine.workdir, mode=0o700, exist_ok=True)
        with open(engine.leasefile, "w", encoding="utf-8") as fh:
            fh.write("1750000000 aa:bb:cc:dd:ee:ff 10.99.0.101 bmc-1 *\n")
        self.assertFalse(os.path.exists(os.path.join(self.cwd, "dnsmasq.leases")))

    def test_poll_leases_reads_workdir_not_cwd(self):
        seen = []
        engine = self._engine("", on_lease=lambda *a: seen.append(a))
        os.makedirs(engine.workdir, mode=0o700, exist_ok=True)
        with open(engine.leasefile, "w", encoding="utf-8") as fh:
            fh.write("1750000000 aa:bb:cc:dd:ee:ff 10.99.0.101 bmc-1 *\n")
        # CWD 下的同名文件是上一版留下的残渣，绝不能被当成租约
        with open(os.path.join(self.cwd, "dnsmasq.leases"), "w", encoding="utf-8") as fh:
            fh.write("1750000000 11:22:33:44:55:66 10.99.0.102 ghost *\n")
        engine._poll_leases()
        self.assertEqual(seen, [("aa:bb:cc:dd:ee:ff", "10.99.0.101", "bmc-1")])

    def test_workdir_permission_is_private(self):
        engine = self._engine("")
        os.makedirs(engine.workdir, mode=0o700, exist_ok=True)
        mode = os.stat(engine.workdir).st_mode & 0o777
        self.assertEqual(oct(mode), oct(0o700))


if __name__ == "__main__":
    unittest.main()
