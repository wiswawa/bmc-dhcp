"""Windows 层的纯函数测试：在 mac 上也能跑（不碰 ctypes、不碰注册表）。

真正只能在 Windows 上验的东西（netsh 是否真的改到网卡、SendARP、Npcap 抓包）
没法在这里测，所以这一层的策略是：**把所有「解析 / 拼命令」拆成纯函数，
在这里钉死**，Windows 上只剩「执行」这一步。
"""

from __future__ import annotations

import ctypes
import os
import socket
import struct
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from bmcdhcp import winnet as W  # noqa: E402
from bmcdhcp import iface as I  # noqa: E402


class TestMasks(unittest.TestCase):
    def test_prefix_to_mask(self):
        self.assertEqual(W.mask_from_prefix(24), "255.255.255.0")
        self.assertEqual(W.mask_from_prefix(16), "255.255.0.0")
        self.assertEqual(W.mask_from_prefix(32), "255.255.255.255")
        self.assertEqual(W.mask_from_prefix(0), "0.0.0.0")

    def test_prefix_bad_input(self):
        self.assertEqual(W.mask_from_prefix(None), "255.255.255.0")
        self.assertEqual(W.mask_from_prefix("abc"), "255.255.255.0")
        self.assertEqual(W.mask_from_prefix(99), "255.255.255.0")

    def test_mask_to_prefix(self):
        self.assertEqual(W.prefix_from_mask("255.255.255.0"), 24)
        self.assertEqual(W.prefix_from_mask("255.255.0.0"), 16)
        self.assertEqual(W.prefix_from_mask("nope", default=24), 24)

    def test_norm_mac(self):
        self.assertEqual(W.norm_mac("B0-83-FE-11-22-33"), "b0:83:fe:11:22:33")
        self.assertEqual(W.norm_mac("b0:83:fe:11:22:33"), "b0:83:fe:11:22:33")
        self.assertEqual(W.norm_mac(""), "")
        self.assertEqual(W.norm_mac("无"), "")


class TestRecordsFromJson(unittest.TestCase):
    def test_single_object(self):
        data = {"n": "以太网 2", "d": "Realtek USB GbE", "m": "B0-83-FE-11-22-33",
                "s": "Up", "i": 12, "dhcp": True,
                "ips": [{"ip": "192.168.0.10", "p": 24}]}
        recs = W.records_from_json(data)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec.name, "以太网 2")
        self.assertEqual(rec.mac, "b0:83:fe:11:22:33")
        self.assertEqual(rec.ip, "192.168.0.10")
        self.assertEqual(rec.mask, "255.255.255.0")
        self.assertTrue(rec.dhcp)
        self.assertTrue(rec.is_up)
        self.assertFalse(rec.is_loopback)

    def test_list_and_missing_fields(self):
        recs = W.records_from_json([
            {"n": "WLAN", "s": "Disconnected", "ips": []},
            {"n": "", "ips": []},                       # 没名字的直接丢
            "垃圾",
        ])
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].name, "WLAN")
        self.assertFalse(recs[0].is_up)
        self.assertEqual(recs[0].mask, "")

    def test_ips_as_single_object(self):
        recs = W.records_from_json({"n": "Ethernet", "ips": {"ip": "10.0.0.5", "p": 8}})
        self.assertEqual(recs[0].ip, "10.0.0.5")
        self.assertEqual(recs[0].mask, "255.0.0.0")

    def test_dhcp_as_string(self):
        recs = W.records_from_json({"n": "X", "dhcp": "True", "ips": []})
        self.assertTrue(recs[0].dhcp)
        recs = W.records_from_json({"n": "X", "dhcp": "false", "ips": []})
        self.assertFalse(recs[0].dhcp)

    def test_link_local_preferred_skipped(self):
        recs = W.records_from_json({"n": "X", "ips": [
            {"ip": "169.254.5.6", "p": 16},
            {"ip": "192.168.1.20", "p": 24},
        ]})
        self.assertEqual(recs[0].ip, "192.168.1.20")

    def test_only_link_local_kept(self):
        recs = W.records_from_json({"n": "X", "ips": [{"ip": "169.254.5.6", "p": 16}]})
        self.assertEqual(recs[0].ip, "169.254.5.6")

    def test_loopback_detected(self):
        recs = W.records_from_json({"n": "Loopback Pseudo-Interface 1",
                                    "ips": [{"ip": "127.0.0.1", "p": 8}], "s": "Up"})
        self.assertTrue(recs[0].is_loopback)

    def test_garbage(self):
        self.assertEqual(W.records_from_json(None), [])
        self.assertEqual(W.records_from_json("x"), [])


IPCONFIG_ZH = """
Windows IP 配置

以太网适配器 以太网 2:

   连接特定的 DNS 后缀 . . . . . . . :
   描述. . . . . . . . . . . . . . . : Realtek USB GbE Family Controller
   物理地址. . . . . . . . . . . . . : B0-83-FE-11-22-33
   DHCP 已启用 . . . . . . . . . . . : 是
   自动配置已启用. . . . . . . . . . : 是
   IPv4 地址 . . . . . . . . . . . . : 192.168.0.10(首选)
   子网掩码  . . . . . . . . . . . . : 255.255.255.0
   默认网关. . . . . . . . . . . . . : 192.168.0.1

无线局域网适配器 WLAN:

   描述. . . . . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX201
   物理地址. . . . . . . . . . . . . : AA-BB-CC-DD-EE-FF
   自动配置已启用. . . . . . . . . . : 是
   媒体状态  . . . . . . . . . . . . : 媒体已断开连接
"""

IPCONFIG_EN = """
Windows IP Configuration

Ethernet adapter Ethernet 2:

   Description . . . . . . . . . . . : Realtek USB GbE Family Controller
   Physical Address. . . . . . . . . : B0-83-FE-11-22-33
   DHCP Enabled. . . . . . . . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.20.30.40(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
"""


class TestIpconfigFallback(unittest.TestCase):
    def test_chinese_output(self):
        recs = W.records_from_ipconfig(IPCONFIG_ZH)
        by_name = {r.name: r for r in recs}
        self.assertIn("以太网适配器 以太网 2", by_name)
        rec = by_name["以太网适配器 以太网 2"]
        self.assertEqual(rec.mac, "b0:83:fe:11:22:33")
        self.assertEqual(rec.ip, "192.168.0.10")
        self.assertEqual(rec.mask, "255.255.255.0")

    def test_english_output(self):
        recs = W.records_from_ipconfig(IPCONFIG_EN)
        rec = recs[0]
        self.assertEqual(rec.mac, "b0:83:fe:11:22:33")
        self.assertEqual(rec.ip, "10.20.30.40")
        self.assertEqual(rec.mask, "255.255.0.0")

    def test_empty(self):
        self.assertEqual(W.records_from_ipconfig(""), [])


class TestLinkState(unittest.TestCase):
    """链路状态不能只看 Status 字符串：那是会被本地化的。"""

    def rec(self, **kw):
        return W.AdapterRecord(**kw)

    def test_media_state_wins(self):
        # 状态字符串读不懂，但数字枚举说连上了
        self.assertTrue(self.rec(name="X", status="已連線到網路", media_state=1).is_up)
        self.assertFalse(self.rec(name="X", status="up", media_state=2).is_up)

    def test_localized_status_without_media_state(self):
        self.assertFalse(self.rec(name="X", status="媒体已断开连接").is_up)
        self.assertFalse(self.rec(name="X", status="Disconnected").is_up)
        self.assertTrue(self.rec(name="X", status="已连接").is_up)

    def test_unknown_status_does_not_block(self):
        """认不出来时不能挡路：宁可多列一个口，也别让能用的网卡消失。"""
        self.assertTrue(self.rec(name="X", status="某种没见过的词").is_up)
        self.assertTrue(self.rec(name="X", status="").is_up)

    def test_mcs_parsed(self):
        recs = W.records_from_json({"n": "X", "mcs": 2, "ips": []})
        self.assertEqual(recs[0].media_state, 2)
        self.assertFalse(recs[0].is_up)
        recs = W.records_from_json({"n": "X", "mcs": "1", "ips": []})
        self.assertEqual(recs[0].media_state, 1)
        self.assertTrue(recs[0].is_up)
        recs = W.records_from_json({"n": "X", "ips": []})
        self.assertEqual(recs[0].media_state, 0)


class TestReadback(unittest.TestCase):
    """改完地址要回读，而且要容忍查询滞后。"""

    def test_immediate(self):
        with mock.patch.object(W, "addresses", return_value=["1.2.3.4"]):
            self.assertTrue(W._readback("X", "1.2.3.4"))

    def test_lagging_then_ok(self):
        calls = []

        def flaky(name):
            calls.append(name)
            return ["1.2.3.4"] if len(calls) >= 3 else ["9.9.9.9"]

        with mock.patch.object(W, "addresses", side_effect=flaky), \
                mock.patch.object(W.time, "sleep", return_value=None):
            self.assertTrue(W._readback("X", "1.2.3.4", tries=5))

    def test_never_appears(self):
        with mock.patch.object(W, "addresses", return_value=["9.9.9.9"]), \
                mock.patch.object(W.time, "sleep", return_value=None):
            self.assertFalse(W._readback("X", "1.2.3.4", tries=3))
            self.assertTrue(W._readback("X", "1.2.3.4", present=False, tries=2))

    def test_set_static_uses_readback(self):
        with mock.patch.object(W, "run", return_value=(0, "", "")), \
                mock.patch.object(W, "addresses", return_value=[]):
            self.assertFalse(W.set_static("X", "10.0.0.2", "255.255.255.0"))
        with mock.patch.object(W, "run", return_value=(0, "", "")), \
                mock.patch.object(W, "addresses", return_value=["10.0.0.2"]):
            self.assertTrue(W.set_static("X", "10.0.0.2", "255.255.255.0"))

    def test_set_static_fails_when_netsh_fails(self):
        with mock.patch.object(W, "run", return_value=(1, "", "denied")), \
                mock.patch.object(W, "addresses", return_value=["10.0.0.2"]):
            self.assertFalse(W.set_static("X", "10.0.0.2", "255.255.255.0"))


class TestNetshCommands(unittest.TestCase):
    def test_set_static_quotes_name(self):
        cmd = W.netsh_set_static("以太网 2", "10.99.0.1", "255.255.255.0")
        self.assertEqual(cmd[1:6], ["interface", "ipv4", "set", "address", 'name="以太网 2"'])
        self.assertIn("source=static", cmd)
        self.assertIn("address=10.99.0.1", cmd)
        self.assertIn("mask=255.255.255.0", cmd)
        self.assertIn("gateway=none", cmd)

    def test_set_static_with_gateway(self):
        cmd = W.netsh_set_static("Ethernet", "10.0.0.2", "255.0.0.0", "10.0.0.1")
        self.assertIn("gateway=10.0.0.1", cmd)
        self.assertNotIn("gateway=none", cmd)

    def test_set_dhcp(self):
        cmd = W.netsh_set_dhcp("Ethernet 2")
        self.assertEqual(cmd[1:], ["interface", "ipv4", "set", "address",
                                   'name="Ethernet 2"', "source=dhcp"])

    def test_alias_add_remove(self):
        add = W.netsh_add_address("以太网 2", "192.168.0.254", "255.255.255.0")
        self.assertEqual(add[3], "add")
        self.assertIn("address=192.168.0.254", add)
        # 必须 store=active：否则重启后临时地址还留在网卡上
        self.assertIn("store=active", add)
        rm = W.netsh_delete_address("以太网 2", "192.168.0.254")
        self.assertEqual(rm[3], "delete")
        self.assertIn("address=192.168.0.254", rm)
        self.assertIn("store=active", rm)

    def test_alias_can_drop_store(self):
        add = W.netsh_add_address("Ethernet", "10.0.0.9", "255.0.0.0", store="")
        self.assertFalse(any(x.startswith("store=") for x in add))


ARP_WIN = """
接口: 192.168.0.10 --- 0xc
  Internet 地址         物理地址              类型
  192.168.0.1           b4-2e-99-11-22-33     动态
  192.168.0.120         b0-83-fe-aa-bb-cc     动态
  192.168.0.255         ff-ff-ff-ff-ff-ff     静态
  224.0.0.22            01-00-5e-00-00-16     静态
"""

ARP_WIN_EN = """
Interface: 10.0.0.5 --- 0x5
  Internet Address      Physical Address      Type
  10.0.0.1              00-1f-5b-11-22-33     dynamic
"""


class TestArpTable(unittest.TestCase):
    def test_chinese(self):
        rows = W.arp_table(ARP_WIN)
        ips = [ip for ip, _ in rows]
        self.assertIn("192.168.0.1", ips)
        self.assertIn("192.168.0.120", ips)
        self.assertNotIn("192.168.0.255", ips)     # 广播丢掉
        self.assertNotIn("224.0.0.22", ips)        # 组播丢掉
        self.assertEqual(dict(rows)["192.168.0.120"], "b0:83:fe:aa:bb:cc")

    def test_english(self):
        rows = W.arp_table(ARP_WIN_EN)
        self.assertEqual(rows, [("10.0.0.1", "00:1f:5b:11:22:33")])

    def test_garbage(self):
        self.assertEqual(W.arp_table(""), [])
        self.assertEqual(W.arp_table("nothing here"), [])


NETSTAT = """
活动连接

  协议  本地地址          外部地址        状态           PID
  UDP    0.0.0.0:500        *:*                                    1180
  UDP    0.0.0.0:67         *:*                                    4321
  UDP    0.0.0.0:3702       *:*                                    2216
  UDP    [::]:67            *:*                                    4321
  UDP    192.168.0.10:138   *:*                                    4
"""


class TestPortOwners(unittest.TestCase):
    def test_parse_netstat(self):
        with mock.patch.object(W, "run", return_value=(0, NETSTAT, "")):
            self.assertEqual(W.udp_port_owners(67), [4321])

    def test_no_match(self):
        with mock.patch.object(W, "run", return_value=(0, "", "")):
            self.assertEqual(W.udp_port_owners(67), [])

    def test_process_name(self):
        with mock.patch.object(W, "run",
                               return_value=(0, '"dnsmasq.exe","4321","Console","1","10,000 K"\n', "")):
            self.assertEqual(W.process_name(4321), "dnsmasq.exe")

    def test_process_name_missing(self):
        with mock.patch.object(W, "run", return_value=(0, 'INFO: No tasks are running\n', "")):
            self.assertEqual(W.process_name(999), "")


class TestNonWindowsBehaviour(unittest.TestCase):
    """在 mac 上跑这些函数不能炸、也不能真的去调 Windows 命令。"""

    def test_is_admin_false(self):
        self.assertFalse(W.is_admin())

    def test_send_arp_noop(self):
        self.assertEqual(W.send_arp("192.168.0.1"), "")

    def test_message_box_noop(self):
        W.message_box("x")          # 不该抛

    def test_scapy_iface_identity_on_mac(self):
        self.assertEqual(W.scapy_iface("en0"), "en0")
        self.assertEqual(I.scapy_iface("en0"), "en0")

    def test_has_npcap_false_on_mac(self):
        self.assertFalse(W.has_npcap())

    def test_ps_quote(self):
        self.assertEqual(W.ps_quote("it's"), "'it''s'")

    def test_arp_sweep_bad_cidr(self):
        self.assertEqual(W.arp_sweep("不是网段"), [])

    def test_arp_sweep_accepts_plain_ip_list(self):
        """猜出厂地址时传的是一串具体 IP，不是 CIDR。"""
        asked = []

        def fake_send_arp(ip):
            asked.append(ip)
            return "aa:bb:cc:00:00:01" if ip == "192.168.0.120" else ""

        with mock.patch.object(W, "send_arp", fake_send_arp):
            got = W.arp_sweep(["192.168.0.120", "10.0.0.100", "不是IP"])
        self.assertIn(("192.168.0.120", "aa:bb:cc:00:00:01"), got)
        self.assertNotIn("不是IP", asked)

    def test_arp_sweep_does_not_silently_cap_at_1024(self):
        """/16 会被上层切批，但即使一口气丢进来也不能只问前 1024 个。"""
        asked = []

        def fake_send_arp(ip):
            asked.append(ip)
            return ""

        targets = ["10.%d.%d.1" % (i // 200, i % 200) for i in range(2000)]
        with mock.patch.object(W, "send_arp", fake_send_arp):
            W.arp_sweep(targets)
        self.assertEqual(len(asked), 2000)
        self.assertGreater(len(asked), 1024, "不能再回到「只问前 1024 个」")

    def test_arp_sweep_hard_ceiling_is_explicit(self):
        asked = []
        with mock.patch.object(W, "send_arp", lambda ip: asked.append(ip) or ""):
            W.arp_sweep(["10.0.%d.%d" % (i // 250, i % 250 + 1)
                         for i in range(W.ARP_MAX_TARGETS + 500)])
        self.assertEqual(len(asked), W.ARP_MAX_TARGETS)


class TestAdapterSource(unittest.TestCase):
    """枚举网卡的「来源」和「失败原因」必须能报出来（界面靠它解释空列表）。"""

    def setUp(self):
        W._PS_CACHE.clear()
        self.addCleanup(W._PS_CACHE.clear)

    def test_reports_powershell(self):
        rec = W.AdapterRecord(name="以太网", mac="aa:bb:cc:dd:ee:01")
        with mock.patch.object(W, "powershell_json_ex",
                               lambda *a, **k: ([{"n": "以太网"}], "")), \
             mock.patch.object(W, "records_from_json", lambda d: [rec]):
            got = W.adapter_records(force=True)
        self.assertEqual(len(got), 1)
        self.assertEqual(W.adapter_source()["source"], "powershell")
        self.assertEqual(W.adapter_source()["error"], "")

    def test_falls_back_to_ipconfig(self):
        rec = W.AdapterRecord(name="以太网 2", mac="aa:bb:cc:dd:ee:02")
        with mock.patch.object(W, "powershell_json_ex", lambda *a, **k: (None, "PS 不可用")), \
             mock.patch.object(W, "run", lambda *a, **k: (0, "ipconfig 输出", "")), \
             mock.patch.object(W, "records_from_ipconfig", lambda out: [rec]):
            got = W.adapter_records(force=True)
        self.assertEqual([r.name for r in got], ["以太网 2"])
        self.assertEqual(W.adapter_source()["source"], "ipconfig")

    def test_reports_why_both_sources_failed(self):
        with mock.patch.object(W, "powershell_json_ex", lambda *a, **k: (None, "被组策略拦了")), \
             mock.patch.object(W, "run", lambda *a, **k: (1, "", "找不到 ipconfig")), \
             mock.patch.object(W, "records_from_ipconfig", lambda out: []):
            got = W.adapter_records(force=True)
        self.assertEqual(got, [])
        info = W.adapter_source()
        self.assertEqual(info["source"], "")
        self.assertIn("被组策略拦了", info["error"])
        self.assertIn("ipconfig", info["error"])

    def test_cache_does_not_hide_error(self):
        with mock.patch.object(W, "powershell_json_ex", lambda *a, **k: (None, "boom")), \
             mock.patch.object(W, "run", lambda *a, **k: (0, "", "")), \
             mock.patch.object(W, "records_from_ipconfig", lambda out: []):
            W.adapter_records(force=True)
        # 再读一次（走缓存）也要能拿到同样的原因
        self.assertIn("boom", W.adapter_source()["error"])


class TestIfacePlatform(unittest.TestCase):
    def test_not_windows_here(self):
        if os.name == "nt":
            self.skipTest("这条用例是给 mac/linux 用的")
        self.assertFalse(I.IS_WINDOWS)

    def test_windows_interfaces_from_records(self):
        """把 Windows 的记录喂进网卡层，验证字段映射（不依赖真机）。"""
        recs = [
            W.AdapterRecord(name="以太网 2", desc="Realtek USB GbE", mac="b0:83:fe:11:22:33",
                            status="Up", index=12, dhcp=True, ip="192.168.0.10", prefix=24),
            W.AdapterRecord(name="WLAN", desc="Intel(R) Wi-Fi 6", mac="aa:bb:cc:dd:ee:ff",
                            status="Disconnected", index=5, dhcp=True),
            W.AdapterRecord(name="vEthernet (Default Switch)",
                            desc="Hyper-V Virtual Ethernet Adapter", status="Up", index=20,
                            ip="172.20.0.1", prefix=20),
            W.AdapterRecord(name="Loopback Pseudo-Interface 1", status="Up", index=1,
                            ip="127.0.0.1", prefix=8),
        ]
        with mock.patch.object(W, "adapter_records", return_value=recs), \
                mock.patch.object(I, "_windows_interfaces",
                                  wraps=I._windows_interfaces):
            ifaces = I._windows_interfaces()
        by_name = {i.name: i for i in ifaces}
        eth = by_name["以太网 2"]
        self.assertEqual(eth.ipv4, "192.168.0.10")
        self.assertEqual(eth.netmask, "255.255.255.0")
        self.assertEqual(eth.service, "以太网 2")     # netsh 就用这个名字
        self.assertTrue(eth.has_link)
        self.assertFalse(eth.is_wifi)
        self.assertFalse(eth.virtual)
        self.assertTrue(by_name["WLAN"].is_wifi)
        self.assertFalse(by_name["WLAN"].has_link)
        self.assertTrue(by_name["vEthernet (Default Switch)"].virtual)
        self.assertTrue(by_name["Loopback Pseudo-Interface 1"].loopback)


# ----------------------------------------------------------------------
# GetAdaptersAddresses（ctypes 枚举源）
# ----------------------------------------------------------------------

def _sockaddr_bytes(ip: str) -> bytes:
    """造 sockaddr 原始字节：IPv4 用小端 family=2 + 4 字节地址，IPv6 用 family=23。"""
    if ":" in ip:                                   # AF_INET6
        return (struct.pack("<H", 23) + struct.pack(">H", 0) + b"\x00" * 4
                + socket.inet_pton(socket.AF_INET6, ip) + b"\x00" * 4)
    return struct.pack("<H", 2) + struct.pack(">H", 0) + socket.inet_aton(ip) + b"\x00" * 8


def _unicast_array(items):
    """[(ip, prefix), ...] -> (unicast 数组, 需要保持引用的 sockaddr 缓冲区列表)"""
    arr = (W._IP_ADAPTER_UNICAST_ADDRESS * max(1, len(items)))()
    keep = []
    for idx, (ip, prefix) in enumerate(items):
        raw = _sockaddr_bytes(ip)
        buf = ctypes.create_string_buffer(raw, len(raw))
        keep.append(buf)
        arr[idx].Length = ctypes.sizeof(W._IP_ADAPTER_UNICAST_ADDRESS)
        arr[idx].OnLinkPrefixLength = prefix
        arr[idx].Address.lpSockaddr = ctypes.cast(buf, ctypes.c_void_p)
        arr[idx].Address.iSockaddrLength = len(raw)
        if idx + 1 < len(items):
            arr[idx].Next = ctypes.pointer(arr[idx + 1])
    return arr, keep


def _adapters_array(specs):
    """specs: [{...}] -> IP_ADAPTER_ADDRESSES 数组（含 Next 链）。"""
    arr = (W.IP_ADAPTER_ADDRESSES * len(specs))()
    keep = []
    for idx, spec in enumerate(specs):
        entry = arr[idx]
        entry.IfIndex = spec.get("index", idx + 1)
        entry.FriendlyName = spec.get("name", "")
        entry.Description = spec.get("desc", "")
        entry.IfType = spec.get("if_type", W.IF_TYPE_ETHERNET_CSMACD)
        entry.OperStatus = spec.get("oper", W.OPER_STATUS_UP)
        entry.Flags = spec.get("flags", 0)
        entry.AdapterName = spec.get("guid", b"")
        mac = spec.get("mac", b"")
        entry.PhysicalAddressLength = len(mac)
        for i, byte in enumerate(mac[:8]):
            entry.PhysicalAddress[i] = byte
        ips = spec.get("ips") or []
        if ips:
            ua, bufs = _unicast_array(ips)
            keep.extend(bufs)
            entry.FirstUnicastAddress = ctypes.cast(
                ua, ctypes.POINTER(W._IP_ADAPTER_UNICAST_ADDRESS))
            keep.append(ua)
        if idx + 1 < len(specs):
            entry.Next = ctypes.pointer(arr[idx + 1])
    return arr, keep


class TestGetAdaptersAddresses(unittest.TestCase):
    """ctypes 源的纯函数层：结构偏移、字段解析、缓冲溢出重试、非 Windows 降级。"""

    def setUp(self):
        W._PS_CACHE.clear()
        W._ROUTE_CACHE.clear()
        W._IPHLPAPI.clear()
        self.addCleanup(W._PS_CACHE.clear)
        self.addCleanup(W._IPHLPAPI.clear)

    def test_adapter_struct_offsets_match_windows_x64(self):
        """x64 偏移必须和真实 ABI 一致；用 c_uint32 定义才做得到。"""
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            self.skipTest("只在 64 位平台上校验 x64 偏移")
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.Length.offset, 0)
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.IfIndex.offset, 4)
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.Next.offset, 8)
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.AdapterName.offset, 16)
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.FirstUnicastAddress.offset, 24)
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.DnsSuffix.offset, 56)
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.Description.offset, 64)
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.FriendlyName.offset, 72)
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.PhysicalAddress.offset, 80)
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.PhysicalAddressLength.offset, 88)
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.Flags.offset, 92)
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.Mtu.offset, 96)
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.IfType.offset, 100)
        self.assertEqual(W.IP_ADAPTER_ADDRESSES.OperStatus.offset, 104)
        self.assertEqual(W._IP_ADAPTER_UNICAST_ADDRESS.Address.offset, 16)
        self.assertEqual(W._IP_ADAPTER_UNICAST_ADDRESS.OnLinkPrefixLength.offset, 56)
        self.assertEqual(ctypes.sizeof(W._IP_ADAPTER_UNICAST_ADDRESS), 64)

    def test_adapter_parses_friendly_name_mac_ip_prefix_type_status(self):
        arr, keep = _adapters_array([
            {"name": "以太网 2", "desc": "Realtek USB GbE", "index": 12,
             "mac": bytes.fromhex("b083fe112233"), "if_type": W.IF_TYPE_ETHERNET_CSMACD,
             "oper": W.OPER_STATUS_UP, "flags": 0x0004,
             "guid": b"{AAAA}", "ips": [("192.168.0.10", 24)]},
            {"name": "WLAN", "desc": "Intel(R) Wi-Fi 6", "index": 5,
             "mac": bytes.fromhex("aabbccddeeff"), "if_type": W.IF_TYPE_IEEE80211,
             "oper": W.OPER_STATUS_DOWN,
             "ips": [("169.254.5.6", 16)]},
        ])
        records = W.records_from_adapters_addresses(arr)
        self.assertEqual(len(records), 2)
        eth, wifi = records
        self.assertEqual(eth.name, "以太网 2")
        self.assertEqual(eth.desc, "Realtek USB GbE")
        self.assertEqual(eth.mac, "b0:83:fe:11:22:33")
        self.assertEqual(eth.index, 12)
        self.assertEqual(eth.ip, "192.168.0.10")
        self.assertEqual(eth.prefix, 24)
        self.assertEqual(eth.mask, "255.255.255.0")
        self.assertTrue(eth.dhcp)
        self.assertEqual(eth.if_type, W.IF_TYPE_ETHERNET_CSMACD)
        self.assertEqual(eth.media_state, W._MEDIA_CONNECTED)
        self.assertTrue(eth.is_up)
        self.assertEqual(eth.source, "ctypes")
        self.assertEqual(eth.guid, "{AAAA}")          # PCHAR 要按 ASCII 解，不能留 "b'...'"
        self.assertEqual(wifi.name, "WLAN")
        self.assertEqual(wifi.media_state, W._MEDIA_DISCONNECTED)
        self.assertFalse(wifi.is_up)
        self.assertEqual(wifi.if_type, W.IF_TYPE_IEEE80211)
        # 只有 link-local 时也要留着地址（BMC 直连常见）
        self.assertEqual(wifi.ip, "169.254.5.6")
        # 保持 keep 引用到断言之后，避免 ctypes 缓冲区被回收
        self.assertTrue(keep)

    def test_adapter_tunnel_has_no_fake_mac(self):
        arr, _keep = _adapters_array([
            {"name": "isatap.{1111}", "desc": "Microsoft ISATAP Adapter",
             "if_type": W.IF_TYPE_TUNNEL, "mac": b"\x00\x00\x00\x00\x00\x00\x00\x01"},
        ])
        rec = W.records_from_adapters_addresses(arr)[0]
        self.assertTrue(rec.tunnel)
        self.assertEqual(rec.mac, "")          # 8 字节 EUI-64 不是以太网 MAC
        self.assertEqual(rec.ip, "")

    def test_adapter_without_ipv4_is_still_listed(self):
        """只有 IPv6 地址（或还没有地址）的网卡也必须在列表里 —— 那正是刚插上的 BMC 口。"""
        arr, _keep = _adapters_array([
            {"name": "以太网 3", "desc": "Realtek USB GbE", "index": 30,
             "mac": bytes.fromhex("001122334466"), "oper": W.OPER_STATUS_UP,
             "ips": [("fe80::1144", 64)]},
        ])
        records = W.records_from_adapters_addresses(arr)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].name, "以太网 3")
        self.assertEqual(records[0].ip, "")           # IPv6 不算 IPv4 地址
        self.assertEqual(records[0].prefix, 0)
        self.assertTrue(records[0].is_up)             # 链路是通的（OperStatus=Up）

    def test_adapter_empty_and_garbage(self):
        self.assertEqual(W.records_from_adapters_addresses(None), [])
        self.assertEqual(W.records_from_adapters_addresses(b""), [])

    def test_adapter_non_windows_returns_reason_without_raising(self):
        with mock.patch.object(W, "IS_WIN", False):
            records, error = W.adapters_ctypes()
        self.assertEqual(records, [])
        self.assertIn("非 Windows", error)

    def test_adapter_buffer_overflow_retries_with_bigger_buffer(self):
        arr, _keep = _adapters_array([
            {"name": "以太网", "desc": "Intel I219", "index": 9,
             "mac": bytes.fromhex("001122334455"), "ips": [("10.0.0.5", 24)]},
        ])
        calls = []

        def fake_call(size):
            calls.append(size)
            if len(calls) == 1:
                return W.ERROR_BUFFER_OVERFLOW, 40000, None
            return 0, size, arr

        with mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "_iphlpapi", lambda: object()), \
                mock.patch.object(W, "_gaa_call", side_effect=fake_call):
            records, error = W.adapters_ctypes()
        self.assertEqual(error, "")
        self.assertEqual(len(records), 1)
        self.assertEqual(len(calls), 2)
        self.assertGreaterEqual(calls[1], 40000)   # 按 API 回填的大小扩容

    def test_adapter_buffer_overflow_gives_up_with_reason(self):
        with mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "_iphlpapi", lambda: object()), \
                mock.patch.object(W, "_gaa_call",
                                  side_effect=lambda size: (W.ERROR_BUFFER_OVERFLOW, 10 ** 9, None)):
            records, error = W.adapters_ctypes()
        self.assertEqual(records, [])
        self.assertIn("上限", error)

    def test_adapter_no_data_is_empty_not_failure(self):
        with mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "_iphlpapi", lambda: object()), \
                mock.patch.object(W, "_gaa_call",
                                  side_effect=lambda size: (W.ERROR_NO_DATA, 0, None)):
            records, error = W.adapters_ctypes()
        self.assertEqual(records, [])
        self.assertIn("ERROR_NO_DATA", error)

    def test_adapter_api_failure_reports_error_code(self):
        with mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "_iphlpapi", lambda: object()), \
                mock.patch.object(W, "_gaa_call",
                                  side_effect=lambda size: (87, 0, None)):
            records, error = W.adapters_ctypes()
        self.assertEqual(records, [])
        self.assertIn("87", error)


class TestSubprocessHygiene(unittest.TestCase):
    """run() 必须给每个子进程 DEVNULL stdin，并按命令族解码。"""

    class _FakeProc(object):
        def __init__(self, rc, out, err):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    def test_run_passes_devnull_stdin(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = list(cmd)
            captured.update(kwargs)
            return self._FakeProc(0, b"ok", b"")

        with mock.patch.object(W.subprocess, "run", side_effect=fake_run):
            rc, out, _err = W.run(["ipconfig", "/all"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "ok")
        self.assertIs(captured["stdin"], subprocess.DEVNULL)

    def test_powershell_also_goes_through_run_with_devnull(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs)
            return self._FakeProc(0, b"[]", b"")

        with mock.patch.object(W.subprocess, "run", side_effect=fake_run), \
                mock.patch.object(W, "powershell_path", lambda: "powershell.exe"):
            W.powershell("Get-NetAdapter")
        self.assertIs(captured["stdin"], subprocess.DEVNULL)

    def test_powershell_decodes_as_utf8_not_native(self):
        with mock.patch.object(W, "powershell_path", lambda: "powershell.exe"), \
                mock.patch.object(W, "run", return_value=(0, "", "")) as run_mock:
            W.powershell("Get-NetAdapter")
        _args, kwargs = run_mock.call_args
        self.assertFalse(kwargs.get("native"))     # PowerShell 走 UTF-8 解码

    def test_decode_native_cp936(self):
        self.assertEqual(W._decode_text("以太网 2".encode("gbk"), native=True), "以太网 2")

    def test_run_decodes_cp936_and_ipconfig_name_survives(self):
        """整条链：cp936 字节 → run() 解码 → ipconfig 解析 → 真实接口名。"""
        fake = self._FakeProc(0, IPCONFIG_ZH.encode("gbk"), b"")
        with mock.patch.object(W.subprocess, "run", return_value=fake):
            rc, out, _err = W.run(["ipconfig", "/all"])
        self.assertEqual(rc, 0)
        self.assertIn("以太网适配器 以太网 2", out)      # 不再是 U+FFFD
        recs = W.records_from_ipconfig(out)
        self.assertEqual(recs[0].friendly, "以太网 2")

    def test_decode_utf8(self):
        self.assertEqual(W._decode_text("以太网 2".encode("utf-8")), "以太网 2")

    def test_decode_never_raises(self):
        self.assertIsInstance(W._decode_text(b"\xff\xfe\x00\x81", native=True), str)

    def test_powershell_json_keeps_stderr_when_rc0_without_stdout(self):
        with mock.patch.object(W, "powershell",
                               lambda *a, **k: (0, "", "Get-NetAdapter : 拒绝访问")):
            data, err = W.powershell_json_ex("x")
        self.assertIsNone(data)
        self.assertIn("拒绝访问", err)

    def test_powershell_json_keeps_stderr_on_rc_error(self):
        with mock.patch.object(W, "powershell",
                               lambda *a, **k: (3, "", "BMCD_PS_ERROR: 被组策略拦了")):
            data, err = W.powershell_json_ex("x")
        self.assertIsNone(data)
        self.assertIn("被组策略拦了", err)
        self.assertIn("退出码 3", err)

    def test_powershell_json_reports_stderr_on_bad_json(self):
        with mock.patch.object(W, "powershell",
                               lambda *a, **k: (0, "not json", "warning: x")):
            data, err = W.powershell_json_ex("x")
        self.assertIsNone(data)
        self.assertIn("不是 JSON", err)
        self.assertIn("warning", err)


class TestIpconfigWiring(unittest.TestCase):
    """F2/F3：ipconfig 兜底的真实接线（run → _names_by_mac → records_from_ipconfig）。

    注意：这里 patch 的是 `W.subprocess.run`（给**原始 cp936 字节**），而不是
    `W.run` —— 因为 run() 的契约是「已经解码好的 str」，跳过解码就测不到
    cp936 → str 那一步。整条链（解码、反查、区块标题兜底）都走真函数。
    """

    def setUp(self):
        W._PS_CACHE.clear()
        W.LAST_NAME_ERROR = ""
        self.addCleanup(W._PS_CACHE.clear)

    @staticmethod
    def _proc(text, rc=0):
        return mock.Mock(returncode=rc, stdout=text.encode("cp936"), stderr=b"")

    def test_names_from_ctypes_source_become_friendly(self):
        with mock.patch.object(W.subprocess, "run", return_value=self._proc(IPCONFIG_ZH)), \
                mock.patch.object(W, "_names_by_mac",
                                  return_value={"b0:83:fe:11:22:33": "USB 网卡"}):
            records, err = W._records_from_ipconfig()
        self.assertGreaterEqual(len(records), 2)
        rec = [r for r in records if r.mac == "b0:83:fe:11:22:33"][0]
        self.assertEqual(rec.friendly, "USB 网卡")
        self.assertEqual(rec.best_name, "USB 网卡")
        self.assertEqual(err, "")            # 反查成功，这一级没有降级

    def test_without_names_falls_back_to_block_title(self):
        with mock.patch.object(W.subprocess, "run", return_value=self._proc(IPCONFIG_ZH)), \
                mock.patch.object(W, "_names_by_mac", return_value={}):
            records, err = W._records_from_ipconfig()
        self.assertGreaterEqual(len(records), 2)
        rec = [r for r in records if r.mac == "b0:83:fe:11:22:33"][0]
        self.assertEqual(rec.name, "以太网适配器 以太网 2")   # 原始区块标题
        self.assertEqual(rec.friendly, "以太网 2")            # 剥出来的真名
        self.assertEqual(err, "")

    def test_name_lookup_failure_is_visible_in_adapter_error(self):
        """反查失败不许静默：ipconfig 仍出网卡，但原因要能进 adapter_report。"""
        with mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "adapters_ctypes",
                                  side_effect=RuntimeError("ctypes 炸了")), \
                mock.patch.object(W, "_records_from_powershell",
                                  lambda: ([], "PS 被拦")), \
                mock.patch.object(W.subprocess, "run", return_value=self._proc(IPCONFIG_ZH)):
            records = W.adapter_records(force=True)
        self.assertTrue(records)                       # ipconfig 兜住了
        info = W.adapter_source()
        self.assertIn("FriendlyName 反查失败", info["error"])
        self.assertIn("ctypes 源异常", info["error"])   # 单源异常不拖垮整条链
        self.assertIn("PS 被拦", info["error"])
        report = W.adapter_report()
        ipc = [a for a in report["sources"] if a["source"] == "ipconfig"][0]
        self.assertTrue(ipc["ok"])
        self.assertIn("FriendlyName 反查失败", ipc["warning"])


class TestIpconfigNameRecovery(unittest.TestCase):
    """ipconfig 兜底：名字要能变成 netsh 认的那个，链路状态别恒 True。"""

    def test_section_title_stripped_to_friendly(self):
        recs = W.records_from_ipconfig(IPCONFIG_ZH)
        by_name = {r.name: r for r in recs}
        rec = by_name["以太网适配器 以太网 2"]
        self.assertEqual(rec.friendly, "以太网 2")
        self.assertEqual(rec.best_name, "以太网 2")
        self.assertEqual(rec.source, "ipconfig")

    def test_mac_name_map_wins_over_prefix_stripping(self):
        recs = W.records_from_ipconfig(
            IPCONFIG_ZH, {"b0:83:fe:11:22:33": "USB 网卡"})
        rec = [r for r in recs if r.mac == "b0:83:fe:11:22:33"][0]
        self.assertEqual(rec.friendly, "USB 网卡")

    def test_media_state_disconnected_is_not_up(self):
        recs = W.records_from_ipconfig(IPCONFIG_ZH)
        wifi = [r for r in recs if "WLAN" in r.name][0]
        self.assertEqual(wifi.media_state, W._MEDIA_DISCONNECTED)
        self.assertFalse(wifi.is_up)
        self.assertEqual(wifi.status, "disconnected")

    def test_tunnel_flagged(self):
        sample = IPCONFIG_ZH + """
隧道适配器 isatap.{AAAA-BBBB}:

   媒体状态  . . . . . . . . . . . . : 媒体已断开连接
   连接特定的 DNS 后缀 . . . . . . . :
"""
        recs = W.records_from_ipconfig(sample)
        tunnel = [r for r in recs if "isatap" in r.name][0]
        self.assertTrue(tunnel.tunnel)
        self.assertEqual(tunnel.friendly, "isatap.{AAAA-BBBB}")
        self.assertFalse(tunnel.is_up)

    def test_english_section(self):
        recs = W.records_from_ipconfig(IPCONFIG_EN)
        self.assertEqual(recs[0].friendly, "Ethernet 2")


class TestPowerShellScript(unittest.TestCase):
    """枚举脚本自己不能再「静默失败」：错误必须走 stderr + 非零退出码。"""

    def test_no_silently_continue(self):
        self.assertNotIn("SilentlyContinue", W.PS_ADAPTERS)
        self.assertIn("-ErrorAction Stop", W.PS_ADAPTERS)

    def test_errors_go_to_stderr_and_nonzero_exit(self):
        self.assertIn("[Console]::Error.WriteLine", W.PS_ADAPTERS)
        self.assertIn("exit 3", W.PS_ADAPTERS)

    def test_default_route_script_also_reports_errors(self):
        self.assertNotIn("SilentlyContinue", W.PS_DEFAULT_ALIAS)
        self.assertIn("[Console]::Error.WriteLine", W.PS_DEFAULT_ALIAS)


class TestMultiSourceFallback(unittest.TestCase):
    """三源降级：ctypes → powershell → ipconfig，逐级留原因。"""

    def setUp(self):
        W._PS_CACHE.clear()
        W._ROUTE_CACHE.clear()
        self.addCleanup(W._PS_CACHE.clear)

    def test_ctypes_first_and_no_powershell_spawn(self):
        rec = W.AdapterRecord(name="以太网", mac="aa:bb:cc:dd:ee:01", source="ctypes")
        with mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "adapters_ctypes", lambda: ([rec], "")), \
                mock.patch.object(W, "_records_from_powershell") as ps, \
                mock.patch.object(W, "_records_from_ipconfig") as ipc:
            got = W.adapter_records(force=True)
        self.assertEqual([r.name for r in got], ["以太网"])
        ps.assert_not_called()
        ipc.assert_not_called()
        self.assertEqual(W.adapter_source()["source"], "ctypes")
        self.assertEqual(W.adapter_source()["error"], "")

    def test_ctypes_covers_when_powershell_is_broken(self):
        """PowerShell 不可用（找不到 exe / 超时 / 非 JSON）时，ctypes 源必须兜住。"""
        rec = W.AdapterRecord(name="以太网 2", mac="aa:bb:cc:dd:ee:02", source="ctypes")
        with mock.patch.dict(os.environ, {"BMCD_IFACE_SOURCE": "powershell,ctypes"}), \
                mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "_records_from_powershell",
                                  return_value=([], "PowerShell 退出码 1：找不到 powershell.exe")), \
                mock.patch.object(W, "adapters_ctypes", return_value=([rec], "")):
            got = W.adapter_records(force=True)
        self.assertEqual([r.name for r in got], ["以太网 2"])
        info = W.adapter_source()
        self.assertEqual(info["source"], "ctypes")
        self.assertIn("powershell", info["error"])     # 失败那一级的原因照样留着
        self.assertIn("找不到 powershell.exe", info["error"])

    def test_powershell_used_when_ctypes_fails(self):
        rec = W.AdapterRecord(name="WLAN", source="powershell")
        with mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "adapters_ctypes", lambda: ([], "ctypes 崩了")), \
                mock.patch.object(W, "_records_from_powershell", lambda: ([rec], "")), \
                mock.patch.object(W, "_records_from_ipconfig") as ipc:
            got = W.adapter_records(force=True)
        self.assertEqual([r.name for r in got], ["WLAN"])
        ipc.assert_not_called()
        info = W.adapter_source()
        self.assertEqual(info["source"], "powershell")
        # 前面那一级失败的原因必须留下，不能因为后面成功就吞掉
        self.assertIn("ctypes 崩了", info["error"])
        self.assertIn("ctypes", info["error"])

    def test_ipconfig_is_last_resort(self):
        recs = W.records_from_ipconfig(IPCONFIG_ZH)
        with mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "adapters_ctypes", lambda: ([], "没有 ctypes")), \
                mock.patch.object(W, "_records_from_powershell", lambda: ([], "PS 被拦")), \
                mock.patch.object(W, "_records_from_ipconfig", lambda: (recs, "")):
            got = W.adapter_records(force=True)
        self.assertEqual(len(got), 2)          # 这份样本有两块（以太网 + WLAN）
        info = W.adapter_source()
        self.assertEqual(info["source"], "ipconfig")
        self.assertIn("PS 被拦", info["error"])
        self.assertIn("没有 ctypes", info["error"])

    def test_all_sources_failed_error_mentions_each(self):
        with mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "adapters_ctypes", lambda: ([], "GAA 炸了")), \
                mock.patch.object(W, "_records_from_powershell", lambda: ([], "PS 被拦")), \
                mock.patch.object(W, "_records_from_ipconfig", lambda: ([], "ipconfig 空")):
            got = W.adapter_records(force=True)
        self.assertEqual(got, [])
        info = W.adapter_source()
        self.assertEqual(info["source"], "")
        for needle in ("ctypes", "GAA 炸了", "powershell", "PS 被拦", "ipconfig 空"):
            self.assertIn(needle, info["error"])
        report = W.adapter_report()
        self.assertEqual(len(report["sources"]), 3)
        self.assertTrue(all(item["ok"] is False for item in report["sources"]))
        self.assertTrue(all("ms" in item for item in report["sources"]))

    def test_source_order_can_be_overridden(self):
        recs = W.records_from_ipconfig(IPCONFIG_ZH)
        with mock.patch.dict(os.environ, {"BMCD_IFACE_SOURCE": "ipconfig"}), \
                mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "adapters_ctypes") as ctypes_src, \
                mock.patch.object(W, "_records_from_powershell") as ps, \
                mock.patch.object(W, "_records_from_ipconfig", lambda: (recs, "")):
            got = W.adapter_records(force=True)
        self.assertEqual(len(got), 2)
        ctypes_src.assert_not_called()
        ps.assert_not_called()

    def test_adapter_cache_marks_cached_when_request_reuses_cache(self):
        """上一次请求读完报告之后，这次请求没真枚举 —— 那才是 cached=true。"""
        rec = W.AdapterRecord(name="以太网", source="ctypes")
        with mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "adapters_ctypes", lambda: ([rec], "")):
            W.adapter_records(force=True)
            W.adapter_report()                  # 读走报告 = 上一次请求结束
            again = W.adapter_records()         # 这次请求复用缓存
        self.assertEqual([r.name for r in again], ["以太网"])
        self.assertTrue(W.adapter_report()["cached"])

    def test_adapter_fresh_enumeration_stays_uncached(self):
        """本次请求自己枚举过就是 cached=false，内部再复用一次也不许改口。"""
        rec = W.AdapterRecord(name="以太网", source="ctypes")
        with mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "adapters_ctypes", lambda: ([rec], "")):
            _records, fresh_flag = W.adapter_records_with_flag(force=True)
            self.assertFalse(fresh_flag)
            _same, hit_flag = W.adapter_records_with_flag()
            self.assertTrue(hit_flag)           # 内部确实吃了一发缓存
            self.assertFalse(W.adapter_report()["cached"])

    def test_adapter_budget_consumed_by_powershell_enum(self):
        """枚举自己花掉了那一次 powershell.exe，默认路由不许再 spawn。"""
        rec = W.AdapterRecord(name="以太网 2", source="powershell")
        spawned = {"ps": 0}

        def fake_ps(*args, **kwargs):
            spawned["ps"] += 1
            return 0, "以太网 2", ""

        with mock.patch.object(W, "IS_WIN", True), \
                mock.patch.object(W, "adapters_ctypes", lambda: ([], "没有 ctypes")), \
                mock.patch.object(W, "powershell_json_ex", return_value=({}, "")), \
                mock.patch.object(W, "records_from_json", lambda data: [rec]), \
                mock.patch.object(W, "powershell", side_effect=fake_ps), \
                mock.patch.object(W, "best_interface_index", lambda dest="8.8.8.8": 0):
            got = W.adapter_records(force=True)
            self.assertIs(W._PS_CACHE.get(W.PS_BUDGET_KEY), True)
            W.default_route_iface()
        self.assertEqual([r.name for r in got], ["以太网 2"])
        self.assertEqual(spawned["ps"], 0)



if __name__ == "__main__":
    unittest.main()
