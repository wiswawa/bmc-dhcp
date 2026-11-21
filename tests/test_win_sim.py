"""「假装这是 Windows」的集成测试。

我们没法在这个 mac 上真的跑 netsh/SendARP，但可以把平台开关翻过来、
把执行层换成假的，然后验证**分支逻辑**：枚举 → 选网卡 → 配地址 → 加临时地址
→ 选引擎 → IP 探测。这样 Windows 那边只剩「命令本身能不能执行」这一件事
需要在真机上确认，其余逻辑都在这里钉死了。
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from bmcdhcp import discover, engines, scan, webapp  # noqa: E402
from bmcdhcp import iface as I  # noqa: E402
from bmcdhcp import session as S  # noqa: E402
from bmcdhcp import winnet  # noqa: E402

RECS = [
    winnet.AdapterRecord(name="以太网 2", desc="Realtek USB GbE Family Controller",
                         mac="b0:83:fe:11:22:33", status="Up", index=12, dhcp=True,
                         ip="192.168.0.10", prefix=24),
    winnet.AdapterRecord(name="WLAN", desc="Intel(R) Wi-Fi 6 AX201",
                         mac="aa:bb:cc:dd:ee:ff", status="Disconnected", index=5,
                         dhcp=True),
    winnet.AdapterRecord(name="vEthernet (Default Switch)",
                         desc="Hyper-V Virtual Ethernet Adapter", mac="00:15:5d:00:00:01",
                         status="Up", index=20, dhcp=False, ip="172.20.0.1", prefix=20),
    winnet.AdapterRecord(name="Loopback Pseudo-Interface 1", desc="Software Loopback",
                         mac="", status="Up", index=1, dhcp=False,
                         ip="127.0.0.1", prefix=8),
]


class WinSim(unittest.TestCase):
    """把平台开关翻到 Windows，执行层全部换成假的。"""

    def setUp(self):
        self.addresses: list = ["192.168.0.10"]
        self.calls: list = []
        patches = [
            mock.patch.object(winnet, "IS_WIN", True),
            mock.patch.object(I, "IS_WINDOWS", True),
            mock.patch.object(engines, "IS_WINDOWS", True),
            mock.patch.object(discover, "IS_WINDOWS", True),
            mock.patch.object(winnet, "adapter_records",
                              side_effect=lambda force=False: list(RECS)),
            mock.patch.object(winnet, "default_route_iface", return_value="以太网 2"),
            mock.patch.object(winnet, "is_admin", return_value=True),
            mock.patch.object(winnet, "has_npcap", return_value=False),
            mock.patch.object(winnet, "addresses",
                              side_effect=lambda name: list(self.addresses)),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    # ---------- 枚举 ----------

    def test_enumerate_all(self):
        ifaces = {i.name: i for i in I.enumerate_all()}
        self.assertEqual(set(ifaces), {"以太网 2", "WLAN", "vEthernet (Default Switch)",
                                       "Loopback Pseudo-Interface 1"})
        eth = ifaces["以太网 2"]
        self.assertEqual(eth.ipv4, "192.168.0.10")
        self.assertEqual(eth.netmask, "255.255.255.0")
        self.assertEqual(eth.mac, "b0:83:fe:11:22:33")
        self.assertEqual(eth.service, "以太网 2")       # netsh 就用这个名字
        self.assertTrue(eth.has_link)
        self.assertTrue(eth.is_default_route)
        self.assertFalse(eth.loopback)
        self.assertFalse(eth.is_wifi)
        self.assertTrue(ifaces["WLAN"].is_wifi)
        self.assertFalse(ifaces["WLAN"].has_link)
        self.assertTrue(ifaces["vEthernet (Default Switch)"].virtual)
        self.assertTrue(ifaces["Loopback Pseudo-Interface 1"].loopback)

    def test_candidates_pick_physical_nic(self):
        names = [i.name for i in I.ethernet_candidates()]
        self.assertEqual(names[0], "以太网 2")
        self.assertNotIn("WLAN", names)
        self.assertNotIn("vEthernet (Default Switch)", names)
        self.assertNotIn("Loopback Pseudo-Interface 1", names)

    def test_ifaces_payload(self):
        rows = {r["name"]: r for r in webapp._iface_list()}
        eth = rows["以太网 2"]
        self.assertEqual(eth["service"], "以太网 2")
        self.assertIn("loopback", eth)
        self.assertIn("virtual", eth)
        self.assertTrue(eth["scan_cidrs"])
        self.assertIn("192.168.0.0/24", eth["scan_cidrs"])
        self.assertTrue(rows["Loopback Pseudo-Interface 1"]["loopback"])

    def test_capabilities_report_windows(self):
        sess = S.Session(S.SessionConfig(iface="以太网 2", configure=False, state_path=""),
                         log=lambda *a: None)
        caps = sess.capabilities()
        self.assertEqual(caps["platform"], "windows")
        self.assertTrue(caps["root"])          # is_admin 被 patch 成 True
        self.assertFalse(caps["bpf"])          # 没有 Npcap
        self.assertFalse(caps["npcap"])

    # ---------- 配置 ----------

    def test_describe_config_uses_winnet(self):
        with mock.patch.object(winnet, "describe_config",
                               return_value={"mode": "dhcp", "ip": "192.168.0.10",
                                             "mask": "255.255.255.0",
                                             "router": "192.168.0.1"}) as dc, \
                mock.patch.object(winnet, "gateway_of", return_value="192.168.0.1"):
            cfg = I.describe_config("以太网 2")
        dc.assert_called_once_with("以太网 2")
        self.assertEqual(cfg.mode, "dhcp")
        self.assertEqual(cfg.ip, "192.168.0.10")
        self.assertEqual(cfg.router, "192.168.0.1")

    def test_set_static_routes_to_netsh(self):
        iface = I.Interface(name="以太网 2", service="以太网 2")
        with mock.patch.object(winnet, "set_static", return_value=True) as st:
            self.assertTrue(I.set_static(iface, "10.99.0.1", "255.255.255.0"))
        st.assert_called_once_with("以太网 2", "10.99.0.1", "255.255.255.0")

    def test_set_dhcp_routes_to_netsh(self):
        iface = I.Interface(name="以太网 2", service="以太网 2")
        with mock.patch.object(winnet, "set_dhcp", return_value=True) as sd:
            self.assertTrue(I.set_dhcp(iface))
        sd.assert_called_once_with("以太网 2")

    def test_restore_config(self):
        saved = I.SavedConfig(iface="以太网 2", service="以太网 2", mode="dhcp")
        with mock.patch.object(winnet, "set_dhcp", return_value=True) as sd:
            self.assertTrue(I.restore_config(saved))
        sd.assert_called_once_with("以太网 2")

        saved = I.SavedConfig(iface="以太网 2", service="以太网 2", mode="manual",
                              ip="192.168.5.9", mask="255.255.255.0",
                              router="192.168.5.1")
        with mock.patch.object(winnet, "set_static", return_value=True) as st:
            self.assertTrue(I.restore_config(saved))
        st.assert_called_once_with("以太网 2", "192.168.5.9", "255.255.255.0",
                                   "192.168.5.1")

    def test_alias_routes_to_netsh(self):
        with mock.patch.object(winnet, "add_alias", return_value=True) as add:
            self.assertTrue(I.add_alias("以太网 2", "192.168.0.254", "255.255.255.0"))
        add.assert_called_once_with("以太网 2", "192.168.0.254", "255.255.255.0")
        with mock.patch.object(winnet, "remove_alias", return_value=True) as rm:
            self.assertTrue(I.remove_alias("以太网 2", "192.168.0.254"))
        rm.assert_called_once_with("以太网 2", "192.168.0.254")

    def test_port_owner(self):
        with mock.patch.object(winnet, "udp_port_owners", return_value=[4321]), \
                mock.patch.object(winnet, "process_name", return_value="dnsmasq.exe"):
            owners = I.dhcp_port_owner(exclude_pid=0)
        self.assertEqual(owners, ["dnsmasq.exe(pid 4321)"])
        with mock.patch.object(winnet, "udp_port_owners", return_value=[4321]):
            self.assertEqual(I.dhcp_port_owner(exclude_pid=4321), [])

    def test_scapy_iface_translation(self):
        with mock.patch.object(winnet, "scapy_iface",
                               side_effect=lambda n: r"\Device\NPF_{GUID}" if n == "以太网 2" else n):
            self.assertEqual(I.scapy_iface("以太网 2"), r"\Device\NPF_{GUID}")

    # ---------- 引擎 ----------

    def test_auto_engine_without_npcap_is_udp(self):
        iface = I.Interface(name="以太网 2", mac="b0:83:fe:11:22:33",
                            ipv4="10.99.0.1", netmask="255.255.255.0")
        core = mock.Mock()
        with mock.patch.object(engines, "has_scapy", return_value=True):
            engine = engines.make_engine("auto", iface, core, lambda *a: None)
        self.assertEqual(engine.kind, "udp")

    def test_auto_engine_with_npcap_is_raw(self):
        iface = I.Interface(name="以太网 2", mac="b0:83:fe:11:22:33",
                            ipv4="10.99.0.1", netmask="255.255.255.0")
        with mock.patch.object(engines, "has_scapy", return_value=True), \
                mock.patch.object(winnet, "has_npcap", return_value=True), \
                mock.patch.object(engines, "RawEngine") as raw:
            raw.return_value.kind = "raw"
            engine = engines.make_engine("auto", iface, mock.Mock(), lambda *a: None)
        self.assertEqual(engine.kind, "raw")

    def test_raw_preflight_without_npcap(self):
        iface = I.Interface(name="以太网 2", mac="b0:83:fe:11:22:33")
        eng = engines.RawEngine(iface, mock.Mock(), lambda *a: None)
        with self.assertRaises(engines.EngineUnavailable) as ctx:
            eng.start()
        self.assertIn("Npcap", str(ctx.exception))

    # ---------- 探测 ----------

    def test_arp_sweep_falls_back_to_sendarp(self):
        with mock.patch.object(discover, "_scapy_arp_sweep", return_value=[]), \
                mock.patch.object(winnet, "arp_sweep",
                                  return_value=[("192.168.0.120", "b0:83:fe:aa:bb:cc")]):
            found = discover.arp_sweep("以太网 2", "192.168.0.0/24")
        self.assertEqual(found, [("192.168.0.120", "b0:83:fe:aa:bb:cc")])

    def test_sweep_uses_sendarp(self):
        with mock.patch.object(discover, "_scapy_arp_sweep", return_value=[]), \
                mock.patch.object(winnet, "arp_sweep",
                                  return_value=[("10.0.0.5", "aa:bb:cc:dd:ee:ff")]):
            found = discover.sweep("10.0.0.0/24", iface="以太网 2")
        self.assertEqual(found, [("10.0.0.5", "aa:bb:cc:dd:ee:ff")])

    def test_scan_without_npcap_degrades_passive(self):
        """没 Npcap 时被动侦听自动跳过，扫网段照常，并留下说明。"""
        task_holder = {}

        def scan_fn(iface_name, cidr):
            return [("10.0.0.50", "b0:83:fe:aa:bb:cc")]

        def probe_fn(ip, timeout=1.0):
            from bmcdhcp import discover as D

            fp = D.Fingerprint(ip=ip, mac="b0:83:fe:aa:bb:cc", alive=True,
                               ports=[443, 623], tls_cn="idrac-abc")
            fp.identity = mock.Mock(known=True, vendor="Dell iDRAC", confidence="高",
                                    creds=["root/calvin"], evidence=[])
            return fp

        scanner = scan.Scanner(probe_fn=probe_fn, sniff_fn=lambda *a: "不该被调用",
                               scan_fn=scan_fn,
                               iface_fn=lambda n: I.find_by_name(n))
        # 网卡本身在 192.168.0.0/24，扫的是另一个网段 → 应该加临时地址
        with mock.patch.object(winnet, "add_alias", return_value=True) as add:
            scanner.start({"iface": "以太网 2", "cidrs": "10.0.0.0/24",
                           "passive": True, "active": True, "probe": True,
                           "duration": 1})
            deadline = time.time() + 8
            snap = scanner.snapshot()
            while time.time() < deadline and snap["state"] == "running":
                time.sleep(0.02)
                snap = scanner.snapshot()
        task_holder["snap"] = snap
        self.assertEqual(snap["state"], "done", snap)
        self.assertFalse(snap["passive"])                 # 被自动关掉
        self.assertTrue(any("Npcap" in e for e in snap["errors"]), snap["errors"])
        self.assertEqual(len(snap["hits"]), 1)
        self.assertEqual(snap["hits"][0]["ip"], "10.0.0.50")
        self.assertEqual(snap["aliases"][0]["ip"], "10.0.0.254")
        self.assertEqual(snap["aliases"][0]["cidr"], "10.0.0.0/24")
        add.assert_called_once_with("以太网 2", "10.0.0.254", "255.255.255.0")

    def test_scan_same_subnet_needs_no_alias(self):
        """网卡已经在这个网段里：连得上，不该乱加地址。"""
        scanner = scan.Scanner(
            probe_fn=lambda ip, timeout=1.0: mock.Mock(ports=[], alive=True, mac="",
                                                      identity=None, url="", http=None,
                                                      summary=lambda: "x", tls_cn=""),
            sniff_fn=lambda *a: "", scan_fn=lambda i, c: [("192.168.0.120", "aa:bb:cc:dd:ee:ff")],
            iface_fn=lambda n: I.find_by_name(n))
        with mock.patch.object(winnet, "add_alias", return_value=True) as add:
            scanner.start({"iface": "以太网 2", "cidrs": "192.168.0.0/24",
                           "passive": False, "active": True, "probe": True, "duration": 1})
            deadline = time.time() + 8
            snap = scanner.snapshot()
            while time.time() < deadline and snap["state"] == "running":
                time.sleep(0.02)
                snap = scanner.snapshot()
        self.assertEqual(snap["state"], "done", snap)
        self.assertEqual(snap["aliases"], [])
        add.assert_not_called()

    def test_scan_requires_admin(self):
        scanner = scan.Scanner(iface_fn=lambda n: I.find_by_name(n),
                               sniff_fn=lambda *a: "", scan_fn=lambda i, c: [])
        with mock.patch.object(winnet, "is_admin", return_value=False):
            with self.assertRaises(scan.ScanError) as ctx:
                scanner.start({"iface": "以太网 2"})
        self.assertIn("管理员权限", str(ctx.exception))


_REAL_ADAPTER_RECORDS = winnet.adapter_records      # setUp 里会被替换，留着给「真跑一遍」的用例
_REAL_DEFAULT_ROUTE = winnet.default_route_iface    # 同上：验证 spawn 预算时要跑真的

JSON_RECORDS = [
    {"n": "以太网 2", "d": "Realtek USB GbE Family Controller", "m": "B0-83-FE-11-22-33",
     "s": "Up", "i": 12, "dhcp": True, "mcs": 1,
     "ips": [{"ip": "192.168.0.10", "p": 24}]},
    {"n": "WLAN", "d": "Intel(R) Wi-Fi 6 AX201", "m": "AA-BB-CC-DD-EE-FF",
     "s": "Disconnected", "i": 5, "dhcp": True, "mcs": 2, "ips": []},
    {"n": "vEthernet (Default Switch)", "d": "Hyper-V Virtual Ethernet Adapter",
     "m": "00-15-5D-00-00-01", "s": "Up", "i": 20, "dhcp": False, "mcs": 1,
     "ips": [{"ip": "172.20.0.1", "p": 20}]},
]

IPCONFIG_ZH_SIM = """
以太网适配器 以太网 2:

   描述. . . . . . . . . . . . . . . : Realtek USB GbE Family Controller
   物理地址. . . . . . . . . . . . . : B0-83-FE-11-22-33
   媒体状态  . . . . . . . . . . . . : 已连接
   IPv4 地址 . . . . . . . . . . . . : 192.168.0.10(首选)
   子网掩码  . . . . . . . . . . . . : 255.255.255.0

隧道适配器 isatap.{AAAA-BBBB}:

   媒体状态  . . . . . . . . . . . . : 媒体已断开连接

无线局域网适配器 WLAN:

   描述. . . . . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX201
   物理地址. . . . . . . . . . . . . : AA-BB-CC-DD-EE-FF
   媒体状态  . . . . . . . . . . . . : 媒体已断开连接
"""


class TestIfacePayloadV2(unittest.TestCase):
    """/api/ifaces 的返回契约 + 枚举收敛（Windows 仿真）。"""

    def setUp(self):
        winnet._PS_CACHE.clear()
        winnet._ROUTE_CACHE.clear()
        self.addCleanup(winnet._PS_CACHE.clear)
        self.addCleanup(winnet._ROUTE_CACHE.clear)
        for patcher in (
            mock.patch.object(winnet, "IS_WIN", True),
            mock.patch.object(I, "IS_WINDOWS", True),
            mock.patch.object(winnet, "adapter_records",
                              side_effect=lambda force=False: winnet.records_from_json(JSON_RECORDS)),
            mock.patch.object(winnet, "default_route_iface", lambda: "以太网 2"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_payload_shape(self):
        payload = webapp._iface_enum()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["platform"], "windows")
        self.assertEqual(len(payload["ifaces"]), 3)
        self.assertIn("以太网 2", payload["candidates"])
        self.assertNotIn("WLAN", payload["candidates"])
        self.assertEqual(payload["error"], "")
        self.assertIsInstance(payload["enum"]["ms"], int)
        self.assertIn("sources", payload["enum"])
        row = [i for i in payload["ifaces"] if i["name"] == "以太网 2"][0]
        for key in ("service", "mac", "ipv4", "netmask", "link", "has_link",
                    "wifi", "default_route", "loopback", "virtual", "tunnel",
                    "source", "scan_cidrs"):
            self.assertIn(key, row)
        self.assertTrue(row["default_route"])

    def test_payload_marks_failure_when_no_ifaces(self):
        report = {"source": "", "error": "ctypes：GAA 炸了；powershell：被拦；ipconfig：空",
                  "sources": [{"source": "ctypes", "ok": False, "count": 0, "ms": 1,
                               "error": "GAA 炸了", "skipped": False}],
                  "cached": False}
        with mock.patch.object(winnet, "adapter_records", lambda force=False: []), \
                mock.patch.object(winnet, "adapter_report", lambda: report):
            payload = webapp._iface_enum()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["ifaces"], [])
        self.assertIn("GAA 炸了", payload["error"])
        self.assertEqual(payload["source"], "")

    def test_payload_survives_enum_exception(self):
        with mock.patch.object(I, "enumerate_all", side_effect=RuntimeError("枚举炸了")):
            payload = webapp._iface_enum()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["ifaces"], [])
        self.assertIn("枚举炸了", payload["error"])

    def test_single_enumeration_and_at_most_one_spawn(self):
        calls = {"ps": 0, "ps_json": 0, "ctypes": 0, "wifi": 0}

        def fake_ps(*a, **k):
            calls["ps"] += 1
            return 0, "", ""

        def fake_ps_json(*a, **k):
            calls["ps_json"] += 1
            return JSON_RECORDS, ""

        def fake_ctypes():
            calls["ctypes"] += 1
            return [], "ctypes 不可用"

        def fake_wifi():
            calls["wifi"] += 1
            return set()

        with mock.patch.object(winnet, "adapter_records", _REAL_ADAPTER_RECORDS), \
                mock.patch.object(winnet, "powershell", side_effect=fake_ps), \
                mock.patch.object(winnet, "powershell_json_ex", side_effect=fake_ps_json), \
                mock.patch.object(winnet, "adapters_ctypes", side_effect=fake_ctypes), \
                mock.patch.object(winnet, "best_interface_index", lambda dest="8.8.8.8": 12), \
                mock.patch.object(I, "wifi_devices", side_effect=fake_wifi):
            payload = webapp._iface_enum()
        self.assertTrue(payload["ok"])
        self.assertEqual(calls["ctypes"], 1)          # 一次请求只枚举一次
        self.assertEqual(calls["ps_json"], 1)
        self.assertLessEqual(calls["ps"], 1)          # powershell.exe 最多 1 次
        self.assertEqual(calls["wifi"], 0)            # is_wifi 不再触发二次枚举
        self.assertEqual(payload["source"], "powershell")

    def test_adapter_budget_survives_slow_powershell(self):
        """PowerShell 慢过 2 秒，一次请求仍然只能 spawn 一个 powershell.exe。

        以前用「ps_ts 距现在 < 2 秒」近似判断预算：PS 冷启 2.1s 时窗口早就过期，
        默认路由那次查询又 spawn 一个 —— 首屏要多等一整轮冷启动。现在是请求级
        预算位，跟耗时无关。这个用例在时间窗实现下必然红（ps 会被 spawn 一次）。
        """
        calls = {"ps": 0, "ps_json": 0}

        def slow_ps_json(*a, **k):
            calls["ps_json"] += 1
            time.sleep(2.1)                 # 模拟 PS 冷启动比 2 秒窗口还慢
            return JSON_RECORDS, ""

        def fake_ps(*a, **k):
            calls["ps"] += 1
            return 0, "以太网 2", ""

        with mock.patch.object(winnet, "adapter_records", _REAL_ADAPTER_RECORDS), \
                mock.patch.object(winnet, "default_route_iface", _REAL_DEFAULT_ROUTE), \
                mock.patch.object(winnet, "powershell", side_effect=fake_ps), \
                mock.patch.object(winnet, "powershell_json_ex", side_effect=slow_ps_json), \
                mock.patch.object(winnet, "adapters_ctypes", lambda: ([], "ctypes 不可用")), \
                mock.patch.object(winnet, "best_interface_index", lambda dest="8.8.8.8": 0), \
                mock.patch.object(I, "wifi_devices", return_value=set()):
            payload = webapp._iface_enum()
        self.assertTrue(payload["ok"])
        self.assertEqual(calls["ps_json"], 1)          # 枚举本身：1 次
        self.assertEqual(calls["ps"], 0)               # PS 慢不该让预算失效
        self.assertIs(winnet._PS_CACHE.get("ps_budget"), True)   # 预算已被消费

    def test_adapter_fresh_enumeration_is_not_cached(self):
        """本次请求自己枚举过，就是 cached=false —— 后面的内部调用不许改这个结论。"""
        records = winnet.records_from_json(JSON_RECORDS)
        with mock.patch.object(winnet, "adapter_records", _REAL_ADAPTER_RECORDS), \
                mock.patch.object(winnet, "adapters_ctypes", lambda: (records, "")), \
                mock.patch.object(I, "wifi_devices", return_value=set()):
            payload = webapp._iface_enum(force=True)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["source"], "ctypes")
        self.assertFalse(payload["enum"]["cached"])

    def test_at_most_one_spawn_even_when_ctypes_fails(self):
        """ctypes 挂了 → PowerShell 枚举一次；默认路由**不能再** spawn 第二个。"""
        calls = {"ps": 0, "ps_json": 0}

        def fake_ps(*a, **k):
            calls["ps"] += 1
            return 0, "", ""

        def fake_ps_json(*a, **k):
            calls["ps_json"] += 1
            return JSON_RECORDS, ""

        with mock.patch.object(winnet, "adapter_records", _REAL_ADAPTER_RECORDS), \
                mock.patch.object(winnet, "default_route_iface", _REAL_DEFAULT_ROUTE), \
                mock.patch.object(winnet, "powershell", side_effect=fake_ps), \
                mock.patch.object(winnet, "powershell_json_ex", side_effect=fake_ps_json), \
                mock.patch.object(winnet, "adapters_ctypes", lambda: ([], "ctypes 不可用")), \
                mock.patch.object(winnet, "best_interface_index", lambda dest="8.8.8.8": 0), \
                mock.patch.object(I, "wifi_devices", return_value=set()):
            payload = webapp._iface_enum()
        self.assertTrue(payload["ok"])
        self.assertEqual(calls["ps_json"], 1)          # 枚举：1 次
        self.assertEqual(calls["ps"], 0)               # 默认路由查询被预算挡住
        self.assertEqual(payload["source"], "powershell")

    def test_wifi_flag_comes_from_record_not_extra_enumeration(self):
        def boom(*a, **k):
            raise AssertionError("is_wifi 不该触发 wifi_devices()")

        with mock.patch.object(I, "wifi_devices", side_effect=boom):
            payload = webapp._iface_enum()
        rows = {i["name"]: i for i in payload["ifaces"]}
        self.assertTrue(rows["WLAN"]["wifi"])
        self.assertFalse(rows["以太网 2"]["wifi"])

    def test_tunnel_record_not_in_candidates(self):
        records = winnet.records_from_json(JSON_RECORDS) + [
            winnet.AdapterRecord(name="isatap.{AAAA}", desc="Microsoft ISATAP Adapter",
                                 status="Up", ip="", media_state=1, tunnel=True)]
        with mock.patch.object(winnet, "adapter_records", lambda force=False: records):
            payload = webapp._iface_enum()
        self.assertIn("以太网 2", payload["candidates"])
        self.assertNotIn("isatap.{AAAA}", payload["candidates"])
        tunnel_row = [i for i in payload["ifaces"] if i["name"] == "isatap.{AAAA}"][0]
        self.assertTrue(tunnel_row["tunnel"])

    def test_ipconfig_records_expose_friendly_names(self):
        records = winnet.records_from_ipconfig(IPCONFIG_ZH_SIM)
        with mock.patch.object(winnet, "adapter_records", lambda force=False: records):
            payload = webapp._iface_enum()
        names = [i["name"] for i in payload["ifaces"]]
        self.assertIn("以太网 2", names)              # 不是「以太网适配器 以太网 2」
        self.assertNotIn("以太网适配器 以太网 2", names)
        wifi_row = [i for i in payload["ifaces"] if i["name"] == "WLAN"][0]
        self.assertFalse(wifi_row["has_link"])        # 媒体已断开 → 不再恒 True
        self.assertIn("以太网 2", payload["candidates"])

    def test_diag_enum_summary_has_sources(self):
        webapp._iface_enum()                          # 先让枚举报告就位
        summary = webapp._iface_enum_summary()
        self.assertEqual(summary["platform"], "windows")
        self.assertIn("sources", summary)


if __name__ == "__main__":
    unittest.main()
