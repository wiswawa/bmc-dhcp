"""IP 探测的单元测试：不发真包、不改网卡，全部用注入的假实现。"""

from __future__ import annotations

import contextlib
import io
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from bmcdhcp import cli, discover, scan, vendors  # noqa: E402
from bmcdhcp import iface as I  # noqa: E402

HAS_SCAPY = True
try:
    from scapy.layers.inet import IP, UDP  # noqa: E402
    from scapy.layers.l2 import ARP, Ether  # noqa: E402
except Exception:  # pragma: no cover - 没装 scapy 时跳过抓包解析相关用例
    HAS_SCAPY = False


def lldp_frame(system_name: str, mgmt_ip: str, src_mac: str = "aa:bb:cc:00:00:02"):
    def tlv(kind: int, body: bytes) -> bytes:
        header = (kind << 9) | len(body)
        return header.to_bytes(2, "big") + body

    chassis = tlv(1, b"\x04" + bytes.fromhex(src_mac.replace(":", "")))
    name = tlv(5, system_name.encode())
    addr = bytes(int(x) for x in mgmt_ip.split("."))
    mgmt = tlv(8, bytes([4, 1]) + addr + bytes([2, 0, 0, 0, 1, 0]))
    ttl = tlv(3, b"\x00\x78")
    end = tlv(0, b"")
    payload = chassis + name + mgmt + ttl + end
    return payload


def dns_query(name: str) -> bytes:
    header = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b""
    for label in name.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    return header + qname + b"\x00\x0c\x00\x01"


class TestParsers(unittest.TestCase):
    def test_lldp_system_name_and_management_address(self):
        payload = lldp_frame("IDRAC-9F3K2J", "192.168.0.120")
        name, mgmt = scan.parse_lldp(payload)
        self.assertEqual(name, "IDRAC-9F3K2J")
        self.assertEqual(mgmt, ["192.168.0.120"])

    def test_lldp_truncated_is_safe(self):
        name, mgmt = scan.parse_lldp(b"\xfe\x05\x00")
        self.assertIsInstance(name, str)
        self.assertIsInstance(mgmt, list)

    def test_lldp_ignores_bad_management_address(self):
        payload = lldp_frame("x", "0.0.0.0")
        _, mgmt = scan.parse_lldp(payload)
        self.assertEqual(mgmt, [])

    def test_mdns_name(self):
        raw = dns_query("iDRAC-9F3K2J._http._tcp.local")
        names = scan.parse_mdns_names(raw)
        self.assertTrue(names)
        self.assertIn("IDRAC", names[0].upper())

    def test_mdns_garbage(self):
        self.assertEqual(scan.parse_mdns_names(b""), [])
        self.assertEqual(scan.parse_mdns_names(b"\x00" * 5), [])

    def test_pick_alias_ip_skips_used(self):
        import ipaddress

        net = ipaddress.IPv4Network("192.168.0.0/24")
        pick = scan._pick_alias_ip(net, {"192.168.0.254", "192.168.0.120"})
        self.assertTrue(pick.startswith("192.168.0."))
        self.assertNotIn(pick, ("192.168.0.254", "192.168.0.120"))

    def test_ok_ip(self):
        self.assertTrue(scan._ok_ip("192.168.0.120"))
        self.assertFalse(scan._ok_ip("0.0.0.0"))
        self.assertFalse(scan._ok_ip("224.0.0.1"))
        self.assertFalse(scan._ok_ip("169.254.1.1"))
        self.assertFalse(scan._ok_ip(""))
        self.assertFalse(scan._ok_ip("not-an-ip"))


@unittest.skipUnless(HAS_SCAPY, "需要 scapy 才能构造报文")
class TestClassify(unittest.TestCase):
    OUR_MAC = "f0:18:98:11:22:33"
    OUR_IP = "10.99.0.1"

    def classify(self, pkt):
        return scan.classify(pkt, our_macs=[self.OUR_MAC], our_ips=[self.OUR_IP])

    def test_gratuitous_arp(self):
        pkt = Ether(src="aa:bb:cc:00:00:02") / ARP(
            op=2, hwsrc="aa:bb:cc:00:00:02", psrc="192.168.0.120", pdst="192.168.0.120")
        obs = self.classify(pkt)
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].ip, "192.168.0.120")
        self.assertEqual(obs[0].mac, "aa:bb:cc:00:00:02")
        self.assertEqual(obs[0].source, "arp-announce")

    def test_arp_probe_reveals_intended_address(self):
        pkt = Ether(src="aa:bb:cc:00:00:03") / ARP(
            op=1, hwsrc="aa:bb:cc:00:00:03", psrc="0.0.0.0", pdst="10.0.0.50")
        obs = self.classify(pkt)
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].ip, "10.0.0.50")
        self.assertEqual(obs[0].source, "arp-probe")

    def test_ordinary_arp_reply(self):
        pkt = Ether(src="aa:bb:cc:00:00:04") / ARP(
            op=2, hwsrc="aa:bb:cc:00:00:04", psrc="192.168.1.100", pdst=self.OUR_IP)
        obs = self.classify(pkt)
        self.assertEqual(obs[0].ip, "192.168.1.100")
        self.assertEqual(obs[0].source, "arp")

    def test_ignores_own_traffic(self):
        pkt = Ether(src=self.OUR_MAC) / ARP(
            op=1, hwsrc=self.OUR_MAC, psrc=self.OUR_IP, pdst="192.168.0.1")
        self.assertEqual(self.classify(pkt), [])

    def test_ignores_broadcast_psrc(self):
        pkt = Ether(src="aa:bb:cc:00:00:05") / ARP(
            op=1, hwsrc="aa:bb:cc:00:00:05", psrc="0.0.0.0", pdst="0.0.0.0")
        self.assertEqual(self.classify(pkt), [])

    def test_lldp(self):
        pkt = Ether(src="aa:bb:cc:00:00:06", type=0x88CC) / lldp_frame(
            "XCC-7Z", "172.16.0.9")
        obs = self.classify(pkt)
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].ip, "172.16.0.9")
        self.assertEqual(obs[0].source, "lldp")
        self.assertEqual(obs[0].hostname, "XCC-7Z")

    def test_mdns(self):
        pkt = (Ether(src="aa:bb:cc:00:00:07") /
               IP(src="192.168.0.130", dst="224.0.0.251") /
               UDP(sport=5353, dport=5353) /
               dns_query("iLO-ABCDEF._http._tcp.local"))
        obs = self.classify(pkt)
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].ip, "192.168.0.130")
        self.assertEqual(obs[0].source, "mdns")
        self.assertIn("iLO", obs[0].hostname)

    def test_ignores_own_ip(self):
        pkt = (Ether(src="aa:bb:cc:00:00:08") /
               IP(src=self.OUR_IP, dst="224.0.0.251") /
               UDP(sport=5353, dport=5353) / dns_query("mac.local"))
        self.assertEqual(self.classify(pkt), [])

    def test_unrelated_tcp_is_ignored(self):
        from scapy.layers.inet import TCP

        pkt = (Ether(src="aa:bb:cc:00:00:09") /
               IP(src="192.168.0.140", dst="192.168.0.1") /
               TCP(sport=443, dport=51000))
        self.assertEqual(self.classify(pkt), [])

    def test_vlan_tagged_arp_uses_inner_mac(self):
        """打 802.1Q 标签时外层 Ether.src 是交换机，MAC 必须取 ARP.hwsrc。"""
        try:
            from scapy.layers.l2 import Dot1Q
        except Exception:  # noqa: BLE001
            self.skipTest("scapy 没有 Dot1Q")
        pkt = (Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
               Dot1Q(vlan=100) /
               ARP(op=2, hwsrc="b0:83:fe:11:22:33",
                   psrc="192.168.0.120", pdst="192.168.0.120"))
        obs = self.classify(pkt)
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].ip, "192.168.0.120")
        self.assertEqual(obs[0].mac, "b0:83:fe:11:22:33")

    def test_vlan_tagged_own_frame_ignored(self):
        try:
            from scapy.layers.l2 import Dot1Q
        except Exception:  # noqa: BLE001
            self.skipTest("scapy 没有 Dot1Q")
        pkt = (Ether(src=self.OUR_MAC) / Dot1Q(vlan=100) /
               ARP(op=1, hwsrc=self.OUR_MAC, psrc=self.OUR_IP, pdst="10.99.0.255"))
        self.assertEqual(self.classify(pkt), [])

    def test_normal_arp_request_from_peer(self):
        pkt = Ether(src="aa:bb:cc:00:00:0a") / ARP(
            op=1, hwsrc="aa:bb:cc:00:00:0a", psrc="192.168.0.150", pdst=self.OUR_IP)
        obs = self.classify(pkt)
        self.assertEqual(obs[0].ip, "192.168.0.150")


def fake_iface(name="en7", mac="f0:18:98:aa:bb:cc", ipv4="", link="active"):
    return I.Interface(name=name, mac=mac, ipv4=ipv4, netmask="255.255.255.0",
                       link=link, flags="UP", up=True, running=True)


class FakeProbe:
    """假装探测：443 + 623 开着，证书 CN 像 iDRAC。"""

    def __init__(self):
        self.calls = []

    def __call__(self, ip, timeout=1.0):
        self.calls.append(ip)
        fp = discover.Fingerprint(ip=ip, mac="aa:bb:cc:00:00:02", alive=True,
                                  ports=[443, 623], tls_cn="idrac-9f3k2j",
                                  rmcp=True, elapsed=0.2)
        fp.http = discover.HttpInfo(port=443, scheme="https",
                                    title="iDRAC Virtual Console")
        fp.identity = vendors.identify(tls_cn=fp.tls_cn,
                                       http_title=fp.http.title,
                                       mac=fp.mac)
        return fp


class TestAnyAddress(unittest.TestCase):
    """「BMC 的地址可能是任何值」相关的三条腿：猜、邻居、大网段分块。"""

    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(I, "is_root", return_value=True).start()
        mock.patch.object(I, "addresses", return_value=["10.99.0.1"]).start()
        mock.patch.object(scan, "aliases_add", side_effect=lambda i, ip: True).start()

    # ---- 分块 ----

    def test_chunks_of_a_sixteen(self):
        import ipaddress

        chunks = scan._chunks(ipaddress.IPv4Network("192.168.0.0/16"))
        self.assertEqual(len(chunks), 128)              # 65536 / 512
        self.assertEqual(chunks[0], "192.168.0.0/23")
        self.assertEqual(chunks[-1], "192.168.254.0/23")
        # 拼起来必须首尾相接，不能漏也不能重
        self.assertEqual(len(set(chunks)), len(chunks))

    def test_small_segment_is_one_chunk(self):
        import ipaddress

        for cidr in ("192.168.0.0/24", "10.1.0.0/23", "192.168.0.0/30"):
            self.assertEqual(scan._chunks(ipaddress.IPv4Network(cidr)), [cidr])

    def test_seventeen_splits_evenly(self):
        import ipaddress

        self.assertEqual(len(scan._chunks(ipaddress.IPv4Network("10.0.0.0/17"))), 64)

    # ---- 网段上限 ----

    def test_big_segment_accepted(self):
        scanner = self.make()
        nets = scanner._parse_cidrs("192.168.0.0/16", fake_iface("en7"))
        self.assertEqual(nets, ["192.168.0.0/16"])

    def test_too_big_segment_rejected_with_hint(self):
        scanner = self.make()
        with self.assertRaises(scan.ScanError) as ctx:
            scanner._parse_cidrs("10.0.0.0/8", fake_iface("en7"))
        self.assertIn("/16", str(ctx.exception))

    def test_total_budget_enforced(self):
        scanner = self.make()
        with self.assertRaises(scan.ScanError):
            scanner._parse_cidrs("192.168.0.0/16, 10.0.0.0/16, 172.16.0.0/16",
                                 fake_iface("en7"))

    # ---- 猜出厂地址 ----

    def test_guess_targets_look_sane(self):
        import ipaddress

        self.assertGreaterEqual(len(scan.GUESS_TARGETS), 50)
        self.assertEqual(len(set(scan.GUESS_TARGETS)), len(scan.GUESS_TARGETS))
        for ip in scan.GUESS_TARGETS:
            ipaddress.IPv4Address(ip)

    def test_guess_sends_plain_ip_list_and_records_hit(self):
        calls = []

        def scan_fn(iface_name, targets):
            calls.append(targets)
            # 只对其中一个「出厂地址」应答
            return [("192.168.0.120", "b0:83:fe:aa:bb:cc")] if "192.168.0.120" in targets else []

        scanner = scan.Scanner(
            probe_fn=FakeProbe(), sniff_fn=lambda *a, **k: "",
            scan_fn=scan_fn, iface_fn=lambda n: fake_iface(n),
            v6_fn=lambda *a, **k: [], bcast_fn=lambda *a, **k: [],
        )
        scanner.start({"iface": "en7", "passive": False, "neighbors": False,
                       "active": False, "guess": True, "probe": False})
        self.assertTrue(scanner.wait_done if False else True)
        task = scanner.task
        deadline = time.time() + 6
        while task is not None and task.state == "running" and time.time() < deadline:
            time.sleep(0.02)
        self.assertTrue(calls, "猜地址阶段应当真的发出去了")
        self.assertIsInstance(calls[0], list, "猜地址要传具体 IP 列表，不是 CIDR 字符串")
        self.assertIn("192.168.0.120", calls[0])
        self.assertIn("192.168.0.120", task.hits)
        self.assertIn("guess", task.hits["192.168.0.120"].sources)
        self.assertEqual(task.hits["192.168.0.120"].vendor, "Dell")   # b0:83:fe = Dell

    # ---- IPv6 / 广播 ----

    def test_ipv6_neighbors_surface_as_links(self):
        scanner = scan.Scanner(
            probe_fn=FakeProbe(), sniff_fn=lambda *a, **k: "",
            scan_fn=lambda i, t: [], iface_fn=lambda n: fake_iface(n),
            v6_fn=lambda *a, **k: [("fe80::1c2d:3e4f:5a6b:7c8d", "aa:bb:cc:dd:ee:01")],
            bcast_fn=lambda *a, **k: [],
        )
        scanner.start({"iface": "en7", "passive": False, "active": False,
                       "guess": False, "neighbors": True, "probe": False})
        task = scanner.task
        deadline = time.time() + 6
        while task is not None and task.state == "running" and time.time() < deadline:
            time.sleep(0.02)
        snap = scanner.snapshot()
        self.assertEqual(len(snap["v6"]), 1)
        row = snap["v6"][0]
        self.assertTrue(row["addr"].startswith("fe80::"))
        # link-local 必须带 zone id，否则浏览器连不上
        self.assertIn("%25en7", row["link"])
        self.assertTrue(row["link"].startswith("https://[fe80::"))

    def test_broadcast_reply_becomes_a_hit(self):
        scanner = scan.Scanner(
            probe_fn=FakeProbe(), sniff_fn=lambda *a, **k: "",
            scan_fn=lambda i, t: [], iface_fn=lambda n: fake_iface(n),
            v6_fn=lambda *a, **k: [],
            bcast_fn=lambda *a, **k: ["172.20.30.40"],
        )
        scanner.start({"iface": "en7", "passive": False, "active": False,
                       "guess": False, "neighbors": True, "probe": False})
        task = scanner.task
        deadline = time.time() + 6
        while task is not None and task.state == "running" and time.time() < deadline:
            time.sleep(0.02)
        self.assertIn("172.20.30.40", task.hits)
        self.assertIn("broadcast", task.hits["172.20.30.40"].sources)

    def test_v6_url(self):
        self.assertEqual(scan._v6_url("fe80::1", "en7"), "https://[fe80::1%25en7]/")
        self.assertEqual(scan._v6_url("fe80::1%en7", "en7"), "https://[fe80::1%25en7]/")
        self.assertEqual(scan._v6_url("2001:db8::1", "en7"), "https://[2001:db8::1]/")
        self.assertEqual(scan._v6_url("", "en7"), "")

    def test_v6_url_drops_unsafe_zone(self):
        """Windows 的网卡名可能是「以太网 2」，拼进 URL 就是坏链接。"""
        self.assertEqual(scan._v6_url("fe80::1", "以太网 2"), "https://[fe80::1]/")
        self.assertEqual(scan._v6_url("fe80::1", "en7 /8"), "https://[fe80::1]/")
        self.assertEqual(scan._v6_url("fe80::1", ""), "https://[fe80::1]/")
        self.assertEqual(scan._v6_url("fe80::1", "ethernet_2"), "https://[fe80::1%25ethernet_2]/")

    def make(self):
        return scan.Scanner(
            probe_fn=FakeProbe(), sniff_fn=lambda *a, **k: "",
            scan_fn=lambda i, t: [], iface_fn=lambda n: fake_iface(n),
            v6_fn=lambda *a, **k: [], bcast_fn=lambda *a, **k: [],
        )


class TestScanner(unittest.TestCase):
    def setUp(self):
        patches = [
            mock.patch.object(I, "is_root", return_value=True),
            mock.patch.object(I, "addresses", return_value=["10.99.0.1"]),
            mock.patch.object(scan, "aliases_add", side_effect=lambda iface, ip: True),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def make(self, packets=None, sweep=None, probe=None, iface=None):
        packets = packets or []

        def sniff_fn(iface_name, seconds, on_packet, stop):
            for pkt in packets:
                on_packet(pkt)
            return ""

        def scan_fn(iface_name, cidr):
            return list(sweep or [])

        scanner = scan.Scanner(
            probe_fn=probe or FakeProbe(),
            sniff_fn=sniff_fn,
            scan_fn=scan_fn,
            iface_fn=lambda name: iface if iface is not None else fake_iface(name),
            # 默认不出网：单测里绝不真发 IPv6/广播包
            v6_fn=lambda *a, **k: [],
            bcast_fn=lambda *a, **k: [],
        )
        return scanner

    def wait_done(self, scanner, timeout=8.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if scanner.snapshot()["state"] != "running":
                return scanner.snapshot()
            time.sleep(0.02)
        self.fail("扫描没有在 %.1fs 内结束" % timeout)

    def test_passive_only_finds_arp_announce(self):
        if not HAS_SCAPY:
            self.skipTest("需要 scapy")
        pkt = Ether(src="aa:bb:cc:00:00:02") / ARP(
            op=2, hwsrc="aa:bb:cc:00:00:02", psrc="192.168.0.120", pdst="192.168.0.120")
        scanner = self.make(packets=[pkt])
        scanner.start({"iface": "en7", "cidrs": "", "passive": True,
                       "active": False, "probe": False, "duration": 1})
        snap = self.wait_done(scanner)
        self.assertEqual(snap["state"], "done")
        self.assertEqual([h["ip"] for h in snap["hits"]], ["192.168.0.120"])
        self.assertIn("arp-announce", snap["hits"][0]["sources"])

    def test_active_sweep_and_probe_and_alias(self):
        scanner = self.make(sweep=[("192.168.0.120", "aa:bb:cc:00:00:02")])
        scanner.start({"iface": "en7", "cidrs": "192.168.0.0/24", "passive": False,
                       "active": True, "probe": True, "duration": 1})
        snap = self.wait_done(scanner)
        self.assertEqual(snap["state"], "done")
        hits = snap["hits"]
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["ip"], "192.168.0.120")
        self.assertTrue(hit["probed"])
        self.assertEqual(hit["url"], "https://192.168.0.120/")
        self.assertIn("Dell iDRAC", hit["vendor"])
        self.assertIn(443, hit["ports"])
        self.assertGreater(hit["score"], 0)
        # 扫到别的网段 → 自动加临时地址
        self.assertEqual(len(snap["aliases"]), 1)
        self.assertEqual(snap["aliases"][0]["cidr"], "192.168.0.0/24")
        self.assertNotEqual(snap["aliases"][0]["ip"], "192.168.0.120")

    def test_no_alias_when_same_subnet(self):
        scanner = self.make(sweep=[("10.99.0.150", "aa:bb:cc:00:00:03")])
        scanner.start({"iface": "en7", "cidrs": "10.99.0.0/24", "passive": False,
                       "active": True, "probe": False, "duration": 1})
        snap = self.wait_done(scanner)
        self.assertEqual(snap["aliases"], [])

    def test_stop_mid_scan(self):
        stop_flag = threading.Event()

        def slow_sniff(iface_name, seconds, on_packet, stop):
            stop.wait(0.05)
            return ""

        scanner = scan.Scanner(sniff_fn=slow_sniff, scan_fn=lambda i, c: [],
                               probe_fn=FakeProbe(),
                               iface_fn=lambda name: fake_iface(name))
        scanner.start({"iface": "en7", "passive": True, "active": False,
                       "probe": False, "duration": 30})
        time.sleep(0.15)
        scanner.stop()
        stop_flag.set()
        snap = self.wait_done(scanner, timeout=6)
        self.assertEqual(snap["state"], "stopped")

    def test_busy(self):
        def slow_sniff(iface_name, seconds, on_packet, stop):
            time.sleep(0.3)
            return ""

        scanner = scan.Scanner(sniff_fn=slow_sniff, scan_fn=lambda i, c: [],
                               probe_fn=FakeProbe(),
                               iface_fn=lambda name: fake_iface(name))
        scanner.start({"iface": "en7", "passive": True, "active": False,
                       "probe": False, "duration": 5})
        with self.assertRaises(scan.ScanBusy):
            scanner.start({"iface": "en7", "passive": True, "active": False,
                           "probe": False, "duration": 5})
        scanner.stop()
        self.wait_done(scanner, timeout=6)

    def test_concurrent_start_only_one_wins(self):
        def slow_sniff(iface_name, seconds, on_packet, stop):
            time.sleep(0.2)
            return ""

        scanner = scan.Scanner(sniff_fn=slow_sniff, scan_fn=lambda i, c: [],
                               probe_fn=FakeProbe(),
                               iface_fn=lambda name: fake_iface(name))
        results = []

        def go():
            try:
                scanner.start({"iface": "en7", "passive": True, "active": False,
                               "probe": False, "duration": 5})
                results.append("ok")
            except scan.ScanBusy:
                results.append("busy")

        threads = [threading.Thread(target=go) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(3)
        self.assertEqual(results.count("ok"), 1, results)
        self.assertEqual(results.count("busy"), 3, results)
        scanner.stop()
        self.wait_done(scanner, timeout=6)

    def test_bad_cidr(self):
        scanner = self.make()
        with self.assertRaises(scan.ScanError):
            scanner.start({"iface": "en7", "cidrs": "999.1.2.3/24"})

    def test_too_big_cidr(self):
        scanner = self.make()
        with self.assertRaises(scan.ScanError):
            scanner.start({"iface": "en7", "cidrs": "10.0.0.0/8"})

    def test_requires_iface(self):
        scanner = self.make()
        with self.assertRaises(scan.ScanError):
            scanner.start({"iface": "", "passive": True})

    def test_requires_root(self):
        scanner = self.make()
        with mock.patch.object(I, "is_root", return_value=False):
            with self.assertRaises(scan.ScanError):
                scanner.start({"iface": "en7", "passive": True})

    def test_needs_some_mode(self):
        scanner = self.make()
        with self.assertRaises(scan.ScanError):
            scanner.start({"iface": "en7", "passive": False, "active": False,
                           "guess": False, "neighbors": False})

    def test_guess_alone_is_enough(self):
        """只猜出厂地址也是一种合法扫法（不扫网段也能命中）。"""
        scanner = self.make()
        task = scanner.start({"iface": "en7", "passive": False, "active": False,
                              "guess": True, "neighbors": False, "probe": False})
        self.assertIn(task["state"], ("running", "done"))
        self.assertTrue(task["guess"])
        scanner.stop()

    def test_sniff_error_is_reported(self):
        def bad_sniff(iface_name, seconds, on_packet, stop):
            return "抓包失败：Operation not permitted"

        scanner = scan.Scanner(sniff_fn=bad_sniff, scan_fn=lambda i, c: [],
                               probe_fn=FakeProbe(),
                               iface_fn=lambda name: fake_iface(name))
        scanner.start({"iface": "en7", "passive": True, "active": False,
                       "probe": False, "duration": 3})
        snap = self.wait_done(scanner)
        self.assertTrue(any("Operation not permitted" in e for e in snap["errors"]))

    def test_ip_conflict_detected(self):
        def sniff_fn(iface_name, seconds, on_packet, stop):
            if HAS_SCAPY:
                for mac in ("aa:bb:cc:00:00:11", "aa:bb:cc:00:00:12"):
                    on_packet(Ether(src=mac) / ARP(
                        op=2, hwsrc=mac, psrc="192.168.0.120", pdst="192.168.0.120"))
            return ""

        scanner = scan.Scanner(sniff_fn=sniff_fn, scan_fn=lambda i, c: [],
                               probe_fn=FakeProbe(),
                               iface_fn=lambda name: fake_iface(name))
        scanner.start({"iface": "en7", "passive": True, "active": False,
                       "probe": False, "duration": 1})
        snap = self.wait_done(scanner)
        hit = snap["hits"][0]
        self.assertEqual(len(hit["alt_macs"]), 1)
        self.assertTrue(any("冲突" in e for e in hit["evidence"]))

    def test_cleanup_during_scan_stops_and_removes(self):
        calls = []

        def slow_sniff(iface_name, seconds, on_packet, stop):
            time.sleep(0.15)
            return ""

        def fake_add(iface_name, ip):
            calls.append(ip)
            return True

        scanner = scan.Scanner(sniff_fn=slow_sniff, scan_fn=lambda i, c: [],
                               probe_fn=FakeProbe(),
                               iface_fn=lambda name: fake_iface(name))
        with mock.patch.object(scan, "aliases_add", side_effect=fake_add):
            scanner.start({"iface": "en7", "passive": True, "active": False,
                           "probe": False, "duration": 30})
            time.sleep(0.1)
            removed = scanner.cleanup()      # 边跑边清
        self.assertEqual(removed, [])
        self.assertEqual(scanner.snapshot()["state"], "stopped")

    def test_snapshot_idle_shape(self):
        scanner = self.make()
        snap = scanner.snapshot()
        self.assertEqual(snap["state"], "idle")
        self.assertEqual(snap["hits"], [])


class TestIfaceAlias(unittest.TestCase):
    """ifconfig 参数位置各版本不同，加完必须回读确认。"""

    def test_add_alias_verifies_by_readback(self):
        with mock.patch.object(I, "run", return_value=(0, "", "")) as run_mock, \
                mock.patch.object(I, "addresses", return_value=["10.0.0.1"]):
            self.assertFalse(I.add_alias("en7", "192.168.0.254"))
        # 三种写法都试过了
        self.assertEqual(run_mock.call_count, 3)

    def test_add_alias_succeeds_when_address_present(self):
        calls = []

        def fake_run(cmd, check=False):
            calls.append(cmd)
            return 0, "", ""

        with mock.patch.object(I, "run", side_effect=fake_run), \
                mock.patch.object(I, "addresses", return_value=["192.168.0.254"]):
            self.assertTrue(I.add_alias("en7", "192.168.0.254", "255.255.255.0"))
        self.assertEqual(len(calls), 1)
        self.assertIn("alias", calls[0])

    def test_remove_alias_checks_result(self):
        with mock.patch.object(I, "run", return_value=(0, "", "")), \
                mock.patch.object(I, "addresses", return_value=["192.168.0.254"]):
            self.assertFalse(I.remove_alias("en7", "192.168.0.254"))
        with mock.patch.object(I, "run", return_value=(0, "", "")), \
                mock.patch.object(I, "addresses", return_value=["10.0.0.1"]):
            self.assertTrue(I.remove_alias("en7", "192.168.0.254"))

    def test_alias_empty_args(self):
        self.assertFalse(I.add_alias("", "192.168.0.254"))
        self.assertFalse(I.remove_alias("en7", ""))


class TestAliasRegistry(unittest.TestCase):
    def test_cleanup_removes_only_registered(self):
        scan.aliases_cleanup()
        with mock.patch.object(I, "add_alias", return_value=True), \
                mock.patch.object(I, "remove_alias", return_value=True) as rm:
            self.assertTrue(scan.aliases_add("en7", "192.168.0.254"))
            self.assertTrue(scan.aliases_add("en7", "192.168.0.253"))
            self.assertEqual(scan.aliases_live(),
                             [("en7", "192.168.0.254"), ("en7", "192.168.0.253")])
            removed = scan.aliases_cleanup()
        self.assertEqual(len(removed), 2)
        self.assertEqual(rm.call_count, 2)
        self.assertEqual(scan.aliases_live(), [])

    def test_add_failure_not_registered(self):
        scan.aliases_cleanup()
        with mock.patch.object(I, "add_alias", return_value=False):
            self.assertFalse(scan.aliases_add("en7", "192.168.0.250"))
        self.assertEqual(scan.aliases_live(), [])


class TestDefaults(unittest.TestCase):
    def test_default_cidrs_include_own_subnet_first(self):
        iface = I.Interface(name="en7", ipv4="10.99.0.1", netmask="255.255.255.0")
        cidrs = scan.default_cidrs(iface)
        self.assertEqual(cidrs[0], "10.99.0.0/24")
        self.assertIn("192.168.0.0/24", cidrs)

    def test_default_cidrs_without_ip(self):
        cidrs = scan.default_cidrs(I.Interface(name="en7"))
        self.assertEqual(cidrs, list(scan.FACTORY_CIDRS))


class TestArpLookup(unittest.TestCase):
    """附录 D-2/D-4：arp 路径要按候选解析，查不到时不能静默返回空串。

    以前 discover.py 写死 "/sbin/arp"（macOS 上不存在），加上
    `except (OSError, SubprocessError): return ""`，结果 MAC 恒为空：
    IP 探测的 MAC 列、只回 ARP 的设备判定、sweep 兜底全失效，而且日志里
    一个字都没有。
    """

    @staticmethod
    def _system_arp() -> str:
        return shutil.which("arp") or ""

    def _system_table(self):
        """系统 arp 表：{(ip, mac)}。故意用另一套解析，不用被测代码的正则。"""
        arp = self._system_arp()
        if not arp:
            return {}
        out = subprocess.run([arp, "-n", "-a"], capture_output=True, text=True,
                             timeout=15).stdout
        table = {}
        for line in out.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line)
            if m:
                table[m.group(1)] = m.group(2).lower()
        return table

    def test_arp_binary_resolves_to_a_real_executable(self):
        binary = discover.arp_binary()
        self.assertTrue(binary, "arp_binary() 返回空：候选和 PATH 都没有 arp")
        self.assertTrue(os.path.isabs(binary), binary)
        self.assertTrue(os.path.isfile(binary), binary)
        self.assertTrue(os.access(binary, os.X_OK), binary)
        # 不再写死 /sbin/arp：解析结果要么是候选之一，要么来自 PATH
        self.assertTrue(binary in discover.ARP_CANDIDATES
                        or binary == shutil.which("arp"), binary)
        self.assertNotEqual(os.path.basename(binary), "", binary)

    def test_arp_lookup_matches_system_arp_output(self):
        """真跑一次 arp，拿系统自己的输出交叉断言（不 mock 路径、不 mock 函数）。"""
        if not self._system_arp():
            self.skipTest("本机没有 arp 命令")
        table = self._system_table()
        if not table:
            self.skipTest("ARP 表是空的（没有同网段邻居），无法交叉断言")
        ip = "192.168.10.1" if "192.168.10.1" in table else sorted(table)[0]
        want = table[ip]
        self.assertEqual(discover.arp_lookup(ip), want)
        res = discover.arp_lookup_ex(ip)
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.mac, want)
        self.assertEqual(res.command, discover.arp_binary())

    def test_arp_lookup_without_binary_exposes_reason(self):
        with mock.patch.object(discover, "ARP", ""), \
                mock.patch.object(discover, "arp_binary", return_value=""):
            res = discover.arp_lookup_ex("192.168.10.1")
            self.assertFalse(res.ok)
            self.assertEqual(res.mac, "")
            self.assertIn("找不到 arp", res.error)
            self.assertIn("找不到 arp", res.describe())
            self.assertEqual(discover.arp_lookup("192.168.10.1"), "")
            diag = discover.arp_diag()
        self.assertFalse(diag["available"])
        self.assertIn("找不到 arp", diag["last_error"])
        self.assertIn("192.168.10.1", diag["last_ip"])

    def test_arp_lookup_command_failure_exposes_reason(self):
        fake = mock.Mock(returncode=1, stdout="",
                         stderr="arp: 192.168.10.1: Operation not permitted")
        with mock.patch.object(discover, "ARP", "/usr/sbin/arp"), \
                mock.patch.object(discover.subprocess, "run", return_value=fake):
            res = discover.arp_lookup_ex("192.168.10.1")
        self.assertFalse(res.ok)
        self.assertIn("返回码 1", res.error)
        self.assertIn("Operation not permitted", res.error)
        self.assertEqual(discover.arp_diag()["last_error"], res.error)

    def test_arp_lookup_timeout_is_reported(self):
        with mock.patch.object(discover, "ARP", "/usr/sbin/arp"), \
                mock.patch.object(discover.subprocess, "run",
                                  side_effect=subprocess.TimeoutExpired("arp", 10)):
            res = discover.arp_lookup_ex("192.168.10.1")
        self.assertFalse(res.ok)
        self.assertIn("10 秒没返回", res.error)

    def test_arp_lookup_parses_dashed_mac(self):
        """Windows / 某些 arp 实现输出 aa-bb-cc-dd-ee-ff，也要认。"""
        fake = mock.Mock(returncode=0, stdout="  10.0.0.9  aa-bb-cc-dd-ee-ff  dynamic\n",
                         stderr="")
        with mock.patch.object(discover, "ARP", "/usr/sbin/arp"), \
                mock.patch.object(discover.subprocess, "run", return_value=fake):
            res = discover.arp_lookup_ex("10.0.0.9")
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.mac, "aa:bb:cc:dd:ee:ff")

    def test_arp_lookup_empty_table_is_success_not_error(self):
        fake = mock.Mock(returncode=0, stdout="? (10.0.0.9) at (incomplete)\n", stderr="")
        with mock.patch.object(discover, "ARP", "/usr/sbin/arp"), \
                mock.patch.object(discover.subprocess, "run", return_value=fake):
            res = discover.arp_lookup_ex("10.0.0.9")
        self.assertTrue(res.ok)
        self.assertEqual(res.mac, "")
        self.assertIn("ARP 表里没有", res.describe())

    def test_arp_table_scan_uses_resolved_binary(self):
        if not discover.ARP:
            self.skipTest("本机没有 arp 命令")
        seen = {}

        def fake_run(args, **kwargs):
            seen["argv"] = list(args)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(discover.subprocess, "run", fake_run):
            rows = discover._arp_table_scan(ipaddress.IPv4Network("10.99.0.0/24"))
        self.assertEqual(rows, [])
        self.assertEqual(seen["argv"][0], discover.ARP)
        self.assertTrue(os.path.isabs(seen["argv"][0]), seen["argv"][0])
        self.assertEqual(discover.LAST_ARP_TABLE_ERROR, "")

    def test_arp_table_scan_failure_is_visible(self):
        with mock.patch.object(discover, "ARP", "/usr/sbin/arp"), \
                mock.patch.object(discover.subprocess, "run",
                                  side_effect=OSError("boom")):
            rows = discover._arp_table_scan(ipaddress.IPv4Network("10.99.0.0/24"))
        self.assertEqual(rows, [])
        self.assertIn("arp -a 执行失败", discover.LAST_ARP_TABLE_ERROR)
        self.assertIn("boom", discover.arp_diag()["table_error"])

    def test_probe_keeps_arp_error_on_fingerprint(self):
        """arp_error 留在自己的字段里，不混进 summary（t14-F3）。"""
        bad = discover.ArpResult(ip="127.0.0.1", error="找不到 arp 命令")
        with mock.patch.object(discover, "arp_lookup_ex", return_value=bad), \
                mock.patch.object(discover, "scan_ports", return_value=[]), \
                mock.patch.object(discover, "rmcp_ping", return_value=(False, "")):
            fp = discover.probe("127.0.0.1", timeout=0.05, deep=False)
        self.assertEqual(fp.mac, "")
        self.assertEqual(fp.arp_error, "找不到 arp 命令")
        self.assertNotIn("ARP 查不了", fp.summary())
        self.assertEqual(fp.summary(), "无响应")

    def test_summary_normal_path_unchanged(self):
        only_mac = discover.Fingerprint(ip="10.0.0.9", mac="aa:bb:cc:dd:ee:ff")
        self.assertEqual(only_mac.summary(), "只回 ARP，无管理端口")
        nothing = discover.Fingerprint(ip="10.0.0.9")
        self.assertEqual(nothing.summary(), "无响应")
        self.assertEqual(nothing.arp_error, "")


class TestArpNoEntryAndVisibility(unittest.TestCase):
    """t10-F1/F2/F3：「表里没有」不许当错误；失败要在调用链上看得见。

    真机输出（macOS，/usr/sbin/arp -n 10.255.255.77）：
        10.255.255.77 (10.255.255.77) -- no entry      rc=1
    以前这里判成「arp 返回码 1：…」，probe 一台不在表里的设备就显示「ARP 查不了」，
    sweep 一个 /24 会刷一两百行假错误。
    """

    # 真机原样输出，不要改写成 mock 出来的形状
    NO_ENTRY_STDOUT = "10.255.255.77 (10.255.255.77) -- no entry\n"

    def setUp(self):
        for patcher in (
            mock.patch.object(discover, "_ARP_WARNED", {}),
            mock.patch.object(discover, "LAST_ARP_TABLE_ERROR", ""),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(mock.patch.stopall)

    def _run_rc(self, rc, stdout="", stderr=""):
        proc = mock.Mock(returncode=rc, stdout=stdout, stderr=stderr)
        return mock.patch.object(discover, "ARP", "/usr/sbin/arp"), \
            mock.patch.object(discover.subprocess, "run", return_value=proc)

    def test_arp_no_entry_is_a_result_not_an_error(self):
        p1, p2 = self._run_rc(1, self.NO_ENTRY_STDOUT)
        stderr = io.StringIO()
        with p1, p2, contextlib.redirect_stderr(stderr):
            res = discover.arp_lookup_ex("10.255.255.77")
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.mac, "")
        self.assertEqual(res.error, "")
        self.assertEqual(stderr.getvalue(), "")          # 查无此项绝不进 stderr
        self.assertEqual(discover.arp_lookup("10.255.255.77"), "")
        # 探测结果应该是「无响应」，不是「ARP 查不了」
        fp = discover.Fingerprint(ip="10.255.255.77", mac="", arp_error=res.error)
        self.assertEqual(fp.summary(), "无响应")

    def test_arp_incomplete_entry_is_a_result_not_an_error(self):
        """BSD/Linux 的 (incomplete) 是同一类语义。"""
        p1, p2 = self._run_rc(0, "? (10.0.0.9) at (incomplete) on en0 [ethernet]\n")
        with p1, p2:
            res = discover.arp_lookup_ex("10.0.0.9")
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.mac, "")

    def test_arp_real_failure_still_reported(self):
        """真正的故障（没权限 / 命令坏了）不许被「查无此项」的逻辑吃掉。"""
        p1, p2 = self._run_rc(1, "", "arp: 10.0.0.9: Operation not permitted\n")
        with p1, p2:
            res = discover.arp_lookup_ex("10.0.0.9")
        self.assertFalse(res.ok)
        self.assertIn("Operation not permitted", res.error)

    def test_arp_warn_dedupes_by_category(self):
        """同类错误只打一行 —— 按含 IP 的整串去重等于不去重。"""
        stderr = io.StringIO()
        p1, p2 = self._run_rc(1, "", "arp: Operation not permitted\n")
        with p1, p2, contextlib.redirect_stderr(stderr):
            for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
                self.assertFalse(discover.arp_lookup_ex(ip).ok)
        lines = [line for line in stderr.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, stderr.getvalue())
        warned = discover.arp_diag()["warned"]
        self.assertEqual(list(warned.values()), [3], warned)   # 计数照样记得

    def test_arp_missing_binary_warns_once_and_counts(self):
        """「找不到 arp 命令」以前是唯一哑掉的分支：连查两个 IP 一行日志都没有。"""
        stderr = io.StringIO()
        with mock.patch.object(discover, "ARP", ""), \
                mock.patch.object(discover, "arp_binary", lambda: ""), \
                contextlib.redirect_stderr(stderr):
            first = discover.arp_lookup_ex("10.0.0.1")
            second = discover.arp_lookup_ex("10.0.0.2")
        self.assertFalse(first.ok)
        self.assertFalse(second.ok)
        lines = [line for line in stderr.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, stderr.getvalue())
        self.assertIn("找不到 arp 命令", lines[0])
        warned = discover.arp_diag()["warned"]
        self.assertEqual(len(warned), 1, warned)               # 只有这一类别
        self.assertEqual(list(warned.values()), [2], warned)   # 两次都计进去了

    def test_arp_missing_binary_goes_through_common_exit(self):
        """负向对照：这条分支必须走统一出口，自己 return 就会绕过告警。"""
        calls = []
        real_finish = discover._finish_arp

        def spy(res):
            calls.append(res)
            return real_finish(res)

        with mock.patch.object(discover, "ARP", ""), \
                mock.patch.object(discover, "arp_binary", lambda: ""), \
                mock.patch.object(discover, "_finish_arp", side_effect=spy):
            res = discover.arp_lookup_ex("10.0.0.1")
        self.assertEqual(len(calls), 1, "找不到 arp 命令的分支没有走 _finish_arp（会静默）")
        self.assertIs(calls[0], res)
        self.assertIn("找不到 arp 命令", res.error)

    def test_table_scan_failure_warns_once_and_is_diagnosable(self):
        stderr = io.StringIO()
        with mock.patch.object(discover, "ARP", "/usr/sbin/arp"), \
                mock.patch.object(discover.subprocess, "run",
                                  side_effect=OSError("boom")), \
                contextlib.redirect_stderr(stderr):
            rows1 = discover._arp_table_scan(ipaddress.IPv4Network("10.9.9.0/24"))
            rows2 = discover._arp_table_scan(ipaddress.IPv4Network("10.9.9.0/24"))
        self.assertEqual(rows1, [])
        self.assertEqual(rows2, [])
        self.assertIn("arp -a 执行失败", discover.LAST_ARP_TABLE_ERROR)
        lines = [line for line in stderr.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, stderr.getvalue())
        self.assertIn("ARP 表读不出来", lines[0])
        self.assertIn("table:arp -a 执行失败", discover.arp_diag()["warned"])

    def test_cli_find_static_warns_when_arp_table_unreadable(self):
        """端到端：扫表读不出来时，CLI 不能只印「0 台」了事。"""
        import argparse

        iface = I.Interface(name="en9", mac="aa:bb:cc:dd:ee:ff",
                            ipv4="", netmask="255.255.255.0", link="active")
        args = argparse.Namespace(no_color=True, iface="en9", timeout=0.05,
                                  subnets=["10.9.9.0/30"])
        out = io.StringIO()
        with mock.patch.object(I, "is_root", return_value=True), \
                mock.patch.object(I, "find_by_name", lambda name: iface), \
                mock.patch.object(I, "add_alias", lambda *a, **k: True), \
                mock.patch.object(I, "remove_alias", lambda *a, **k: True), \
                mock.patch.object(discover, "_scapy_arp_sweep", lambda *a, **k: []), \
                mock.patch.object(discover, "ping_alive", lambda *a, **k: False), \
                mock.patch.object(discover.subprocess, "run",
                                  side_effect=OSError("boom")), \
                contextlib.redirect_stdout(out):
            code = cli.cmd_find_static(args)
        text = out.getvalue()
        self.assertEqual(code, 1, text)
        self.assertIn("ARP 表读不出来", text)
        self.assertIn("arp -a 执行失败", text)
        self.assertIn("这一轮的结果不作数", text)

    def test_index_html_surfaces_arp_error_separately(self):
        """UI：arp_error 单独一行告警，不混进 summary。"""
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "src", "bmcdhcp", "ui", "index.html")
        with open(path, encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("h.arp_error", html)
        self.assertIn("⚠ ARP 查不了：", html)
        self.assertIn('if (r.arp_error) rows.push(row("ARP"', html)

    def test_scan_hit_carries_arp_error(self):
        """命中行要能把 arp_error 带到前端（Hit.to_dict）。"""
        hit = scan.Hit(ip="10.0.0.9")
        self.assertEqual(hit.to_dict()["arp_error"], "")
        hit.arp_error = "找不到 arp 命令"
        self.assertEqual(hit.to_dict()["arp_error"], "找不到 arp 命令")

    def test_scan_apply_copies_arp_error_from_fingerprint(self):
        scanner = scan.Scanner()
        hit = scan.Hit(ip="10.0.0.9")
        fp = discover.Fingerprint(ip="10.0.0.9", mac="", arp_error="arp 命令 10 秒没返回")
        scanner._apply(mock.Mock(hits={}, lock=threading.RLock()), hit, fp)
        self.assertEqual(hit.arp_error, "arp 命令 10 秒没返回")


if __name__ == "__main__":
    unittest.main()
