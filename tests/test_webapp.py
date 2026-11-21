"""Web API 测试：真起 HTTP 服务、真发请求，但引擎是假的（不碰 67 端口）。"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))


# ---------------------------------------------------------------------------
# 测试隔离：BMCD_HOME 必须在 import bmcdhcp.webapp 之前钉到临时目录，
# 因为 webapp.SESSION_FILE = user_home()/.bmcd/web.json 是 import 期算出来的，
# _write_session_to 还会顺手 makedirs —— 不隔离就会在真实家目录建 ~/.bmcd。
# ---------------------------------------------------------------------------
def _isolate_test_home() -> str:
    home = os.environ.get("BMCD_TEST_HOME") or tempfile.mkdtemp(prefix="bmcd-test-home-")
    os.environ["BMCD_HOME"] = home
    os.environ["BMCD_TEST_HOME"] = home
    return home


TEST_HOME = _isolate_test_home()

from bmcdhcp import discover  # noqa: E402
from bmcdhcp import scan as S  # noqa: E402
from bmcdhcp import iface as I  # noqa: E402
from bmcdhcp.session import Session, SessionConfig  # noqa: E402
from bmcdhcp import webapp  # noqa: E402
from bmcdhcp.webapp import App  # noqa: E402

TOKEN = "test-token-123"


class FakeEngine:
    kind = "fake"
    started = 0
    stopped = 0

    def __init__(self, iface, core, log):
        self._stop = threading.Event()

    def start(self, on_ready=None):
        FakeEngine.started += 1
        if on_ready:
            on_ready()
        while not self._stop.wait(0.02):
            pass

    def stop(self):
        FakeEngine.stopped += 1
        self._stop.set()


def fake_probe(ip, timeout=1.0):
    return discover.Fingerprint(ip=ip, alive=True, mac="aa:bb:cc:dd:ee:ff",
                                ports=[443, 623], tls_cn="idrac-TEST")


class WebAppTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = SessionConfig(iface="lo0", configure=False, state_path="", engine="udp")
        cls.session = Session(
            cfg,
            log=lambda *a: None,
            engine_factory=lambda kind, iface, core, log: FakeEngine(iface, core, log),
            probe_fn=fake_probe,
        )
        cls.app = App(cls.session, token=TOKEN)
        cls.host, cls.port = cls.app.start("127.0.0.1", 0)
        cls.base = "http://127.0.0.1:%d" % cls.port

    @classmethod
    def tearDownClass(cls):
        cls.app.stop()

    # ---------------- helpers ----------------

    def request(self, path, method="GET", body=None, headers=None, timeout=8):
        data = None
        hdrs = {"X-BMCD-Token": TOKEN}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(self.base + path, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                return resp.status, raw
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read()
            finally:
                exc.close()
            return exc.code, body

    def json_of(self, path, **kwargs):
        status, raw = self.request(path, **kwargs)
        return status, json.loads(raw.decode("utf-8"))

    # ---------------- tests ----------------

    def test_index_html(self):
        status, raw = self.request("/")
        self.assertEqual(status, 200)
        text = raw.decode("utf-8")
        self.assertIn("BMC DHCP", text)
        self.assertIn("</html>", text)

    def test_index_html_has_iface_failure_ui(self):
        """界面必须能显示「读不到网卡」和 loading 态，而不是留一个空白下拉框。"""
        status, raw = self.request("/")
        self.assertEqual(status, 200)
        text = raw.decode("utf-8")
        for needle in ("正在读取网卡…", "读不到网卡列表", "读取网卡失败：",
                       "没有读到网卡（可在下面手填网卡名）", "API_TIMEOUT_GET",
                       "AbortController", "renderIfaceError", "ifaceManualRow"):
            self.assertIn(needle, text)

    def test_state_without_token_says_which_problem(self):
        """附录 D-4：403 的文案要说明是令牌问题，而不是「后台服务已断开」。"""
        status, raw = self.request("/api/state", headers={"X-BMCD-Token": ""})
        self.assertEqual(status, 403)
        text = json.loads(raw.decode("utf-8"))["error"]
        self.assertIn("访问令牌", text)
        self.assertIn("App", text)

    def test_index_html_has_token_banner(self):
        status, raw = self.request("/")
        self.assertEqual(status, 200)
        text = raw.decode("utf-8")
        for needle in ("缺少访问令牌", "需令牌", "err.auth",
                       "resp.status === 401 || resp.status === 403",
                       "从 App 里点「打开界面」进入"):
            self.assertIn(needle, text)

    def test_index_html_has_no_dead_readonly_branch(self):
        """/api/state 要令牌，没令牌根本走不到那条分支 —— 死代码，删掉。"""
        status, raw = self.request("/")
        self.assertEqual(status, 200)
        text = raw.decode("utf-8")
        for needle in ("S.readOnly", "readOnly:", "只读模式"):
            self.assertNotIn(needle, text)

    def test_ping(self):
        status, data = self.json_of("/api/ping")
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertIn("version", data)

    def test_state_shape(self):
        status, data = self.json_of("/api/state")
        self.assertEqual(status, 200)
        for key in ("state", "leases", "logs", "stats", "capabilities", "cursor", "config"):
            self.assertIn(key, data)
        self.assertIsInstance(data["leases"], list)

    def test_ifaces(self):
        status, data = self.json_of("/api/ifaces")
        self.assertEqual(status, 200)
        self.assertIsInstance(data["ifaces"], list)
        self.assertIsInstance(data["candidates"], list)
        self.assertTrue(any(i["name"] == "lo0" for i in data["ifaces"]))

    def test_diag(self):
        status, data = self.json_of("/api/diag")
        self.assertEqual(status, 200)
        self.assertIn("capabilities", data)
        self.assertIn("port67_free", data)

    def test_ifaces_contract(self):
        """/api/ifaces 的返回体必须能区分「没网卡」和「读不到网卡」。"""
        status, data = self.json_of("/api/ifaces")
        self.assertEqual(status, 200)
        for key in ("ok", "platform", "ifaces", "candidates", "source", "error", "enum"):
            self.assertIn(key, data)
        self.assertEqual(data["ok"], bool(data["ifaces"]))
        self.assertTrue(data["error"]) if not data["ok"] else self.assertEqual(data["error"], "")
        self.assertIsInstance(data["enum"]["ms"], int)
        self.assertIn("sources", data["enum"])

    def test_ifaces_returns_200_when_enum_raises(self):
        """枚举炸了也不能 500：500 会让前端直接空白，连原因都拿不到。"""
        with mock.patch.object(I, "enumerate_all", side_effect=RuntimeError("枚举炸了")):
            status, data = self.json_of("/api/ifaces")
        self.assertEqual(status, 200)
        self.assertFalse(data["ok"])
        self.assertEqual(data["ifaces"], [])
        self.assertEqual(data["candidates"], [])
        self.assertIn("枚举炸了", data["error"])

    def test_diag_includes_iface_enum(self):
        status, data = self.json_of("/api/diag")
        self.assertEqual(status, 200)
        self.assertIn("iface_enum", data)
        self.assertIn("sources", data["iface_enum"])
        self.assertIn("platform", data["iface_enum"])

    def test_diag_iface_enum_is_not_stuck_pending_on_mac(self):
        """macOS 不走多源枚举，诊断不能永远显示「枚举中」。"""
        from bmcdhcp import iface as I
        if I.IS_WINDOWS:
            self.skipTest("这条专测非 Windows 的 skipped 语义")
        status, data = self.json_of("/api/diag")
        self.assertEqual(status, 200)
        enum = data["iface_enum"]
        self.assertEqual(enum["platform"], "macos")
        self.assertIs(enum["pending"], False)
        self.assertEqual(enum["sources"], [])
        self.assertTrue(enum["skipped"], "非 Windows 要给出 skipped 原因")

    def test_start_with_unknown_manual_iface_reports_reason(self):
        """前端手填的网卡名原样透传，后端给出明确原因（而不是空错误）。"""
        status, data = self.json_of("/api/start", method="POST", body={
            "iface": "绝对不存在的网卡", "configure": False,
        })
        self.assertEqual(status, 400)
        self.assertIn("找不到网卡", data["error"])
        self.assertIn("绝对不存在的网卡", data["error"])
        self.json_of("/api/stop", method="POST", body={})

    def test_state_requires_token(self):
        status, _ = self.request("/api/state", headers={"X-BMCD-Token": ""})
        self.assertEqual(status, 403)
        status, _ = self.request("/api/diag", headers={"X-BMCD-Token": "bad"})
        self.assertEqual(status, 403)
        status, _ = self.request("/api/ping", headers={"X-BMCD-Token": ""})
        self.assertEqual(status, 200)

    def test_origin_host_boundary(self):
        for bad in ("http://127.0.0.1.evil.com", "http://localhost.evil.tld",
                    "http://127.0.0.1:1", "https://127.0.0.1"):
            status, _ = self.request("/api/stop", method="POST", body={},
                                     headers={"Origin": bad})
            self.assertEqual(status, 403, bad)

    def test_unknown_path(self):
        status, _ = self.request("/nope")
        self.assertEqual(status, 404)

    def test_missing_ui_serves_readable_page(self):
        """界面文件丢了不能回一坨 JSON —— 要给一页能看懂的中文说明。"""
        import bmcdhcp.webapp as W

        with mock.patch.object(W, "UI_DIR", "/nonexistent/bmcdhcp/ui"):
            status, raw = self.request("/")
        self.assertEqual(status, 200)
        text = raw.decode("utf-8")
        self.assertIn("包没解压完整", text)
        self.assertIn("index.html", text)
        self.assertIn("bmcd.cmd verify", text)
        self.assertNotIn('"error"', text)

    def test_diag_reports_missing_ui(self):
        import bmcdhcp.webapp as W

        with mock.patch.object(W, "UI_DIR", "/nonexistent/bmcdhcp/ui"):
            status, data = self.json_of("/api/diag")
        self.assertEqual(status, 200)
        self.assertEqual(data["ui_missing"], ["index.html"])
        self.assertIn("ui_dir", data)

    def test_bad_host_header_rejected(self):
        status, _ = self.request("/api/state", headers={"Host": "evil.example.com"})
        self.assertEqual(status, 403)

    def test_host_header_variants(self):
        # 带端口的 Host 头是浏览器常态；IPv6 的 [::1]:port 也要认
        for host in ("127.0.0.1:%d" % self.port, "localhost:%d" % self.port,
                     "[::1]:%d" % self.port):
            status, _ = self.request("/api/state", headers={"Host": host})
            self.assertEqual(status, 200, host)

    def test_cross_origin_post_rejected(self):
        status, _ = self.request("/api/stop", method="POST", body={},
                                 headers={"Origin": "http://evil.example.com"})
        self.assertEqual(status, 403)

    def test_start_requires_token(self):
        status, raw = self.request("/api/start", method="POST", body={},
                                   headers={"X-BMCD-Token": "wrong"})
        self.assertEqual(status, 403)
        self.assertIn("令牌", json.loads(raw.decode())["error"])

    def test_bad_json_body(self):
        req = urllib.request.Request(
            self.base + "/api/start", data=b"{oops",
            headers={"Content-Type": "application/json", "X-BMCD-Token": TOKEN}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
        self.assertEqual(status, 400)

    def test_start_stop_cycle(self):
        before = FakeEngine.started
        status, data = self.json_of("/api/start", method="POST", body={
            "iface": "lo0", "subnet": "10.99.0.0/24", "pool": ".100-.110",
            "lease_seconds": 120, "configure": False, "engine": "udp", "state_path": "",
        })
        self.assertEqual(status, 200, data)
        self.assertEqual(data["state"], "running")
        self.assertGreater(FakeEngine.started, before)

        status, data = self.json_of("/api/state")
        self.assertTrue(data["running"])
        self.assertEqual(data["config"]["pool_start"], "10.99.0.100")

        status, data = self.json_of("/api/stop", method="POST", body={})
        self.assertEqual(status, 200)
        self.assertEqual(data["state"], "idle")

    def test_start_with_bad_config_returns_400(self):
        status, data = self.json_of("/api/start", method="POST", body={
            "iface": "lo0", "subnet": "10.99.0.0/24", "pool": "192.168.9.1-192.168.9.5",
            "configure": False,
        })
        self.assertEqual(status, 400)
        self.assertIn("不在子网", data["error"])

    def test_stop_when_idle_is_ok(self):
        status, data = self.json_of("/api/stop", method="POST", body={})
        self.assertEqual(status, 200)
        self.assertEqual(data["state"], "idle")

    def test_start_twice_second_rejected(self):
        status, _ = self.json_of("/api/start", method="POST", body={
            "iface": "lo0", "subnet": "10.99.0.0/24", "configure": False, "state_path": "",
        })
        self.assertEqual(status, 200)
        status, data = self.json_of("/api/start", method="POST", body={
            "iface": "lo0", "subnet": "10.99.0.0/24", "configure": False, "state_path": "",
        })
        self.assertEqual(status, 400)
        self.assertIn("正在运行", data["error"])
        self.json_of("/api/stop", method="POST", body={})

    def test_lease_seconds_clamped(self):
        status, _ = self.json_of("/api/start", method="POST", body={
            "iface": "lo0", "subnet": "10.99.0.0/24", "lease_seconds": 1,
            "configure": False, "state_path": "",
        })
        self.assertEqual(status, 200)
        status, data = self.json_of("/api/state")
        self.assertEqual(data["config"]["lease"], 30)
        self.json_of("/api/stop", method="POST", body={})

    def test_probe_endpoint(self):
        status, data = self.json_of("/api/probe", method="POST", body={"ip": "10.99.0.100"})
        self.assertEqual(status, 200)
        self.assertEqual(data["ip"], "10.99.0.100")
        self.assertTrue(data["alive"])
        self.assertEqual(data["tls_cn"], "idrac-TEST")
        # t14-F3：ARP 查询失败的原因要一路透到 /api/probe，界面才能单独显示成告警
        self.assertIn("arp_error", data)
        self.assertEqual(data["arp_error"], "")

    def test_probe_endpoint_reports_arp_error(self):
        """ARP 查不了的时候，/api/probe 必须把原因带出来（界面单独显示成告警）。"""
        def bad_probe(ip, timeout=1.0):
            return discover.Fingerprint(ip=ip, alive=False, mac="",
                                        arp_error="找不到 arp 命令")

        with mock.patch.object(self.session, "_probe_fn", bad_probe):
            status, data = self.json_of("/api/probe", method="POST",
                                        body={"ip": "10.99.0.100"})
        self.assertEqual(status, 200)
        self.assertEqual(data["arp_error"], "找不到 arp 命令")
        self.assertNotIn("ARP 查不了", data.get("summary", ""))   # 不混进 summary

    def test_probe_requires_ip(self):
        status, data = self.json_of("/api/probe", method="POST", body={})
        self.assertEqual(status, 400)

    def test_heartbeat_requires_token(self):
        status, _ = self.request("/api/heartbeat", method="POST", body={"auto_stop": False},
                                 headers={"X-BMCD-Token": "bad"})
        self.assertEqual(status, 403)

    def test_heartbeat(self):
        self.app.last_heartbeat = 0
        status, data = self.json_of("/api/heartbeat", method="POST",
                                    body={"auto_stop": False})
        self.assertEqual(status, 200)
        self.assertGreater(self.app.last_heartbeat, 0)
        self.assertFalse(self.app.auto_stop)
        self.app.auto_stop = True

    def test_concurrent_reads(self):
        errors = []

        def worker():
            try:
                status, _ = self.request("/api/state")
                if status != 200:
                    errors.append(status)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        self.assertEqual(errors, [])

    def test_keepalive_survives_rejected_post(self):
        """403 之后同一条长连接还能用：请求体必须被读干净。"""
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        try:
            conn.request("POST", "/api/stop", body=json.dumps({"x": 1}),
                         headers={"Content-Type": "application/json", "X-BMCD-Token": "bad"})
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 403)

            conn.request("GET", "/api/state", headers={"X-BMCD-Token": TOKEN})
            resp = conn.getresponse()
            payload = resp.read()
            self.assertEqual(resp.status, 200)
            self.assertIn("leases", json.loads(payload.decode()))
        finally:
            conn.close()

    def test_chunked_body_rejected(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        try:
            conn.putrequest("POST", "/api/stop")
            conn.putheader("Transfer-Encoding", "chunked")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("X-BMCD-Token", TOKEN)
            conn.endheaders()
            conn.send(b"2\r\n{}\r\n0\r\n\r\n")
            resp = conn.getresponse()
            body = resp.read()
            self.assertEqual(resp.status, 400)
            self.assertIn("分块", json.loads(body.decode())["error"])
        finally:
            conn.close()

    # ---------------- IP 探测 ----------------

    def test_scan_in_snapshot(self):
        status, data = self.json_of("/api/state")
        self.assertEqual(status, 200)
        self.assertIn("scan", data)
        self.assertEqual(data["scan"]["state"], "idle")
        self.assertEqual(data["scan"]["hits"], [])

    def test_scan_endpoint_requires_token(self):
        status, _ = self.request("/api/scan", headers={"X-BMCD-Token": ""})
        self.assertEqual(status, 403)

    def test_scan_start_needs_root(self):
        with mock.patch.object(I, "is_root", return_value=False):
            status, data = self.json_of("/api/scan/start", method="POST",
                                        body={"iface": "lo0"})
        self.assertEqual(status, 400)
        self.assertIn("管理员权限", data["error"])

    def test_scan_start_rejects_bad_cidr(self):
        with mock.patch.object(I, "is_root", return_value=True):
            status, data = self.json_of("/api/scan/start", method="POST",
                                        body={"iface": "lo0", "cidrs": "10.0.0.0/8"})
        self.assertEqual(status, 400)
        self.assertIn("太大", data["error"])

    def test_scan_run_and_cleanup(self):
        fake_iface = I.Interface(name="scan0", mac="f0:18:98:00:00:01",
                                 ipv4="", netmask="255.255.255.0", link="active")
        probe = fake_probe

        def sniff_fn(iface_name, seconds, on_packet, stop):
            return ""

        def scan_fn(iface_name, cidr):
            return [("192.168.0.120", "aa:bb:cc:00:00:02")]

        previous = self.app.scanner
        scanner = S.Scanner(probe_fn=probe, sniff_fn=sniff_fn, scan_fn=scan_fn,
                            iface_fn=lambda name: fake_iface)
        self.app.scanner = scanner
        try:
            with mock.patch.object(I, "is_root", return_value=True), \
                    mock.patch.object(S, "aliases_add", return_value=True):
                status, data = self.json_of("/api/scan/start", method="POST", body={
                    "iface": "scan0", "cidrs": "192.168.0.0/24", "passive": False,
                    "active": True, "probe": True, "duration": 1,
                })
                self.assertEqual(status, 200, data)
                deadline = time.time() + 8
                snap = {}
                while time.time() < deadline:
                    status, snap = self.json_of("/api/scan")
                    if snap.get("state") != "running":
                        break
                    time.sleep(0.05)
            self.assertEqual(snap.get("state"), "done", snap)
            self.assertEqual(len(snap["hits"]), 1)
            self.assertEqual(snap["hits"][0]["ip"], "192.168.0.120")
            self.assertEqual(snap["aliases"][0]["cidr"], "192.168.0.0/24")

            status, data = self.json_of("/api/state")
            self.assertEqual(data["scan"]["state"], "done")

            with mock.patch.object(S, "aliases_cleanup", return_value=["scan0 192.168.0.254"]):
                status, data = self.json_of("/api/scan/cleanup", method="POST", body={})
            self.assertEqual(status, 200)
            self.assertTrue(data["ok"])
        finally:
            self.app.scanner = previous

    def test_scan_stop_endpoint(self):
        status, data = self.json_of("/api/scan/stop", method="POST", body={})
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])

    def test_quit_stops_app(self):
        # 用单独的 App 实例测，避免影响其他用例
        session = Session(SessionConfig(iface="lo0", configure=False, state_path=""),
                          log=lambda *a: None,
                          engine_factory=lambda k, i, c, l: FakeEngine(i, c, l),
                          probe_fn=fake_probe)
        app = App(session, token="t")
        host, port = app.start("127.0.0.1", 0)
        req = urllib.request.Request(
            "http://127.0.0.1:%d/api/quit" % port, data=b"{}",
            headers={"Content-Type": "application/json", "X-BMCD-Token": "t"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
        deadline = time.time() + 5
        while time.time() < deadline and not app.stop_event.is_set():
            time.sleep(0.05)
        self.assertTrue(app.stop_event.is_set())


    def test_index_html_pins_timeout_and_retry_chain(self):
        """超时/重试链不能只断言符号名 —— 把关键值和文案钉成具体文本。

        改了 API_TIMEOUT_GET、把重试条件改掉、或者丢掉 ?refresh=1，
        这里都会直接红。
        """
        status, raw = self.request("/")
        self.assertEqual(status, 200)
        text = raw.decode("utf-8")
        for needle in (
            "const API_TIMEOUT_GET = 8000;",
            "cfg.retry !== false",
            '"/api/ifaces?refresh=1"',
            "— 读不到网卡列表 —",
            "读取网卡失败：",
            "手填网卡名",
            "AbortController",
        ):
            self.assertIn(needle, text)

    def test_force_refresh_failure_is_visible(self):
        """点「刷新」时预热枚举炸了，返回体 error 里必须写出来（以前是 pass）。"""
        with mock.patch.object(I, "IS_WINDOWS", True), \
                mock.patch.object(I.winnet, "adapter_records",
                                  side_effect=RuntimeError("PS 冷启动失败")), \
                mock.patch.object(I.winnet, "adapter_report",
                                  return_value={"source": "", "error": "",
                                                "sources": [], "cached": False}), \
                mock.patch.object(I, "enumerate_all", return_value=[]):
            payload = webapp._iface_enum(force=True)
        self.assertFalse(payload["ok"])
        self.assertIn("刷新枚举失败", payload["error"])
        self.assertIn("PS 冷启动失败", payload["error"])

    def test_enum_exception_and_source_reasons_are_concatenated(self):
        """enumerate_all 抛异常 + 三级源全失败：两类原因都要出现在 error 里。"""
        report = {"source": "", "cached": False,
                  "error": "ctypes：GAA 炸了；powershell：被策略拦；ipconfig：空",
                  "sources": []}
        with mock.patch.object(I, "IS_WINDOWS", True), \
                mock.patch.object(I.winnet, "adapter_records",
                                  side_effect=RuntimeError("刷新炸了")), \
                mock.patch.object(I.winnet, "adapter_report", return_value=report), \
                mock.patch.object(I, "enumerate_all",
                                  side_effect=RuntimeError("枚举炸了")):
            payload = webapp._iface_enum(force=True)
        self.assertFalse(payload["ok"])
        for needle in ("刷新枚举失败", "网卡枚举异常", "枚举炸了",
                       "ctypes：GAA 炸了", "powershell：被策略拦", "ipconfig：空"):
            self.assertIn(needle, payload["error"])


class SessionFileTest(unittest.TestCase):
    """会话文件：路径由启动器指定，写失败必须能看出来（以前是静默 pass）。"""

    def setUp(self):
        import shutil
        import tempfile

        self.tmp = tempfile.mkdtemp(prefix="bmcd-sess-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_override_path_is_used(self):
        import bmcdhcp.webapp as W

        target = os.path.join(self.tmp, "web.json")
        with mock.patch.dict(os.environ, {"BMCD_SESSION_FILE": target}):
            self.assertEqual(W.session_path(), target)
            ok = W.write_session_file(1234, "tok", "http://127.0.0.1:1234/?t=tok")
        self.assertTrue(ok)
        with open(target, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["token"], "tok")
        self.assertEqual(data["port"], 1234)

    def test_write_failure_is_reported(self):
        import bmcdhcp.webapp as W

        blocker = os.path.join(self.tmp, "blocker")
        with open(blocker, "w", encoding="utf-8"):
            pass
        target = os.path.join(blocker, "web.json")     # 父目录是个文件
        # 现在还有「备用路径 + 默认路径」会兜底，所以要让它只剩下这个坏路径，
        # 才能验证「全都写不进去」时确实返回 False（而不是静默成功）
        with mock.patch.object(W, "session_candidates", lambda: [target]):
            self.assertFalse(W.write_session_file(1, "t", "http://127.0.0.1:1/?t=t"))

    def test_fallback_candidate_used_when_primary_fails(self):
        """主路径写不进去时，紧挨 backend.log 的备用路径要接住。"""
        import bmcdhcp.webapp as W

        blocker = os.path.join(self.tmp, "blocker")
        with open(blocker, "w", encoding="utf-8"):
            pass
        bad = os.path.join(blocker, "web.json")          # 父路径是文件 → 写不了
        good = os.path.join(self.tmp, "bmcd", "web.json")
        env = {"BMCD_SESSION_FILE": bad, "BMCD_SESSION_FALLBACK": good}
        with mock.patch.dict(os.environ, env):
            self.assertTrue(W.write_session_file(4321, "tok2", "http://127.0.0.1:4321/?t=tok2"))
            self.assertEqual(W.read_session_file()["token"], "tok2")
        self.assertFalse(os.path.exists(bad))
        with open(good, "r", encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["port"], 4321)

    def test_default_path_without_override(self):
        import bmcdhcp.webapp as W

        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BMCD_SESSION_FILE", None)
            self.assertTrue(W.session_path().endswith(os.path.join(".bmcd", "web.json")))


class TestUiSmokeHarness(unittest.TestCase):
    """界面冒烟：运行时从 index.html 抽真函数跑（tools/ui_smoke.mjs）。

    node 不在就跳过 —— 但跳过会打印原因，别静默当通过。
    """

    def test_ui_smoke_harness_passes(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("没装 node，跳过 tools/ui_smoke.mjs 界面冒烟")
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        script = os.path.join(root, "tools", "ui_smoke.mjs")
        self.assertTrue(os.path.isfile(script), script)
        proc = subprocess.run([node, script, "--quiet"], capture_output=True,
                              text=True, timeout=180)
        self.assertEqual(proc.returncode, 0, (proc.stdout or "") + (proc.stderr or ""))
        m = re.search(r"UI smoke: (\d+)/(\d+) passed", proc.stdout or "")
        self.assertIsNotNone(m, proc.stdout)
        passed, total = int(m.group(1)), int(m.group(2))
        self.assertEqual(passed, total)
        self.assertGreaterEqual(total, 29, "界面冒烟的断言太少了：%d" % total)


class TestSessionFileSandbox(unittest.TestCase):
    """附录 D-5：webapp 的 session 文件写入必须落在 BMCD_HOME 里。"""

    def test_session_file_is_under_test_home(self):
        self.assertTrue(TEST_HOME, "测试没有把 BMCD_HOME 钉到临时目录")
        self.assertTrue(webapp.SESSION_FILE.startswith(TEST_HOME), webapp.SESSION_FILE)

    def test_write_session_file_lands_in_test_home(self):
        """_write_session_to 会 makedirs —— 只允许在 BMCD_HOME 里建目录。

        只断言路径关系，不去比真实 ~/.bmcd 的目录列表：这台机器上可能同时
        跑着真的 App（它会正常写 ~/.bmcd/web.json），比列表会假红。
        """
        real_dir = os.path.realpath(os.path.join(os.path.expanduser("~"), ".bmcd"))
        path = os.path.join(TEST_HOME, ".bmcd", "web.json")
        ok = webapp._write_session_to(path, {"url": "http://127.0.0.1:8899/?t=x",
                                             "port": 8899, "token": "x",
                                             "pid": os.getpid(), "ts": time.time()})
        self.assertTrue(ok)
        self.assertTrue(os.path.isfile(path))
        self.assertNotEqual(os.path.realpath(os.path.dirname(path)), real_dir)
        self.assertTrue(webapp.SESSION_FILE.startswith(TEST_HOME), webapp.SESSION_FILE)
        self.assertNotEqual(os.path.realpath(os.path.dirname(webapp.SESSION_FILE)), real_dir)


if __name__ == "__main__":
    unittest.main()
