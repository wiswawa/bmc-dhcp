"""Session 生命周期测试：全程不打真实网卡、不绑定 67 端口。"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))


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

from bmcdhcp import discover  # noqa: E402
from bmcdhcp import iface as I  # noqa: E402
from bmcdhcp.leases import LeaseManager  # noqa: E402
from bmcdhcp.session import (  # noqa: E402
    Session,
    SessionConfig,
    SessionError,
    DaemonPool,
    DEFAULT_STATE,
    user_home,
)


class FakeEngine:
    """最小可用的引擎：start 里等 stop，不做任何 IO。"""

    kind = "fake"
    instances: list = []

    def __init__(self, iface, core, log, fail=None):
        self.iface = iface
        self.core = core
        self.log = log
        self.fail = fail
        self.started = False
        self.stopped = False
        self._stop = threading.Event()
        FakeEngine.instances.append(self)

    def start(self, on_ready=None):
        if self.fail:
            raise self.fail
        self.started = True
        if on_ready:
            on_ready()
        while not self._stop.wait(0.02):
            pass

    def stop(self):
        self.stopped = True
        self._stop.set()


def factory(**kwargs):
    def make(kind, iface, core, log):
        return FakeEngine(iface, core, log, **kwargs)
    return make


def fake_iface(name="en9", ip="", netmask="255.255.255.0"):
    return I.Interface(name=name, mac="aa:bb:cc:dd:ee:ff", ipv4=ip, netmask=netmask,
                       link="active", service="USB LAN")


class SessionTestBase(unittest.TestCase):
    def setUp(self):
        FakeEngine.instances = []
        self.addCleanup(mock.patch.stopall)
        # 网卡地址会“真的”变过去，避免 _prepare_iface 里的等待循环拖慢测试
        self.iface_ip = {"value": ""}

        def find_by_name(name):
            return fake_iface(name, ip=self.iface_ip["value"])

        def set_static(iface, ip, mask="255.255.255.0"):
            self.iface_ip["value"] = ip
            return True

        mock.patch.object(I, "find_by_name", find_by_name).start()
        mock.patch.object(I, "ethernet_candidates", lambda: [fake_iface()]).start()
        mock.patch.object(I, "describe_config", lambda service: I.SavedConfig(
            iface="en9", service=service, mode="dhcp")).start()
        self.set_static = mock.patch.object(I, "set_static", side_effect=set_static).start()
        self.restore = mock.patch.object(I, "restore_config", return_value=True).start()
        mock.patch.object(I, "dhcp_port_owner", return_value=[]).start()
        mock.patch.object(I, "is_root", return_value=True).start()

    def make_session(self, **cfg_kwargs):
        cfg_kwargs.setdefault("iface", "en9")
        cfg_kwargs.setdefault("subnet", "10.99.0.0/24")
        cfg_kwargs.setdefault("configure", False)
        cfg_kwargs.setdefault("state_path", "")
        cfg = SessionConfig(**cfg_kwargs)
        logs = []
        session = Session(
            cfg,
            log=lambda level, text: logs.append((level, text)),
            engine_factory=factory(),
            probe_fn=lambda ip, timeout=1.0: discover.Fingerprint(ip=ip),
        )
        session.logs = logs
        return session


class TestLifecycle(SessionTestBase):
    def test_start_stop(self):
        s = self.make_session()
        self.assertEqual(s.state, "idle")
        s.start()
        self.assertEqual(s.state, "running")
        self.assertEqual(s.engine_kind, "fake")
        snap = s.snapshot(0)
        self.assertTrue(snap["running"])
        self.assertEqual(snap["config"]["server_ip"], "10.99.0.1")
        self.assertEqual(snap["config"]["pool_start"], "10.99.0.100")

        s.stop()
        self.assertEqual(s.state, "idle")
        self.assertTrue(FakeEngine.instances[-1].stopped)

    def test_double_start_rejected(self):
        s = self.make_session()
        s.start()
        with self.assertRaises(SessionError):
            s.start()
        s.stop()

    def test_stop_when_idle_is_noop(self):
        s = self.make_session()
        s.stop()
        self.assertEqual(s.state, "idle")

    def test_restart(self):
        s = self.make_session()
        s.start()
        s.stop()
        s.start()
        self.assertEqual(s.state, "running")
        s.stop()

    def test_logs_are_captured(self):
        s = self.make_session()
        s.start()
        logs, cursor = s.logs_since(0)
        self.assertTrue(logs)
        self.assertGreaterEqual(cursor, len(logs))
        self.assertTrue(any("服务已启动" in e["text"] for e in logs))
        s.stop()
        logs2, cursor2 = s.logs_since(cursor)
        self.assertTrue(all(e["i"] >= cursor for e in logs2))
        self.assertGreaterEqual(cursor2, cursor)

    def test_logs_cursor_out_of_range(self):
        s = self.make_session()
        s.start()
        logs, cursor = s.logs_since(999999)      # 服务重启后的旧游标
        self.assertTrue(logs)
        self.assertEqual(cursor, len(logs))
        s.stop()

    def test_snapshot_serializable(self):
        import json

        s = self.make_session()
        s.start()
        payload = json.dumps(s.snapshot(0), ensure_ascii=False)
        self.assertIn("capabilities", payload)
        s.stop()


class TestValidation(SessionTestBase):
    def _expect(self, fragment, **cfg):
        s = self.make_session(**cfg)
        with self.assertRaises(SessionError) as ctx:
            s.start()
        self.assertIn(fragment, str(ctx.exception))
        self.assertEqual(s.state, "error")
        return s

    def test_garbage_subnet(self):
        s = self.make_session()
        s.cfg.subnet = "abc"
        with self.assertRaises(SessionError) as ctx:
            s.start()
        self.assertIn("子网格式", str(ctx.exception))

    def test_garbage_router(self):
        s = self.make_session(routers=["999.1.1.1"])
        with self.assertRaises(SessionError) as ctx:
            s.start()
        self.assertIn("网关地址不合法", str(ctx.exception))

    def test_bad_subnet(self):
        self._expect("子网", subnet="10.99.0.0/31")

    def test_server_ip_outside(self):
        self._expect("不在子网", server_ip="192.168.1.1")

    def test_bad_pool(self):
        self._expect("不在子网", pool="192.168.1.10-192.168.1.20")

    def test_pool_reversed(self):
        self._expect("起点比终点大", pool=".200-.100")

    def test_bad_dns(self):
        self._expect("DNS", dns=["abc"])

    def test_bad_router(self):
        self._expect("网关", routers=["192.168.9.1"])

    def test_unknown_iface(self):
        with mock.patch.object(I, "find_by_name", lambda name: None):
            s = self.make_session(iface="enXX")
            with self.assertRaises(SessionError) as ctx:
                s.start()
            self.assertIn("找不到网卡", str(ctx.exception))

    def test_error_state_allows_retry(self):
        s = self.make_session(subnet="10.99.0.0/31")
        with self.assertRaises(SessionError):
            s.start()
        self.assertEqual(s.state, "error")
        s.cfg.subnet = "10.99.0.0/24"
        s.start()
        self.assertEqual(s.state, "running")
        s.stop()


class TestFailurePaths(SessionTestBase):
    def test_engine_crash_then_retry(self):
        cfg = SessionConfig(iface="en9", subnet="10.99.0.0/24", configure=False,
                            state_path="", engine="raw")
        failing = {"on": True}
        made = {"n": 0}

        def fact(kind, iface, core, log):
            made["n"] += 1
            return FakeEngine(iface, core, log,
                              fail=RuntimeError("boom") if failing["on"] else None)

        s = Session(cfg, log=lambda *a: None, engine_factory=fact)
        with self.assertRaises(SessionError):
            s.start()
        self.assertEqual(s.state, "error")
        failing["on"] = False
        s.start()
        self.assertEqual(s.state, "running")
        s.stop()
        self.assertEqual(made["n"], 2)

    def test_engine_permission_error(self):
        cfg = SessionConfig(iface="en9", subnet="10.99.0.0/24", configure=False,
                            state_path="", engine="raw")
        s = Session(cfg, log=lambda *a: None,
                    engine_factory=factory(fail=PermissionError("nope")))
        with self.assertRaises(SessionError) as ctx:
            s.start()
        self.assertIn("权限", str(ctx.exception))
        self.assertEqual(s.state, "error")

    def test_iface_config_failure_restores(self):
        mock.patch.object(I, "set_static", return_value=False).start()
        s = self.make_session(configure=True)
        with self.assertRaises(SessionError) as ctx:
            s.start()
        self.assertIn("设置网卡地址失败", str(ctx.exception))
        self.assertEqual(s.state, "error")
        self.assertTrue(self.restore.called)

    def test_iface_config_failure_without_root_says_how(self):
        mock.patch.object(I, "set_static", return_value=False).start()
        mock.patch.object(I, "is_root", return_value=False).start()
        s = self.make_session(configure=True)
        with self.assertRaises(SessionError) as ctx:
            s.start()
        self.assertIn("管理员", str(ctx.exception))

    def test_restore_called_on_stop(self):
        s = self.make_session(configure=True)
        s.start()
        self.assertTrue(self.set_static.called)
        self.iface_ip["value"] = ""
        self.restore.reset_mock()
        s.stop()
        self.assertTrue(self.restore.called)

    def test_restart_reconfigures_iface(self):
        """停一次之后网卡配置已经还原，再启动必须重新设一遍地址。"""
        s = self.make_session(configure=True)
        s.start()
        self.assertEqual(self.set_static.call_count, 1)
        s.stop()
        # 还原之后网卡回到“没地址”的状态
        self.iface_ip["value"] = ""
        s.start()
        self.assertEqual(self.set_static.call_count, 2)
        s.stop()

    def test_restart_clears_probe_memory(self):
        s = self.make_session()
        s.start()
        s._probed.add("10.99.0.100")
        s.stop()
        s.start()
        self.assertEqual(s._probed, set())
        s.stop()

    def test_ifconfig_fallback_address_is_removed(self):
        """没有网络服务可改时用 ifconfig 加的地址，停止时要自己摘掉。"""
        mock.patch.object(I, "describe_config", lambda service: I.SavedConfig(
            iface="en9", service=service, mode="unknown")).start()
        calls = []
        mock.patch.object(I, "run", lambda cmd, check=False: (calls.append(cmd), (0, "", ""))[1]).start()
        s = self.make_session(configure=True)
        s.start()
        s.stop()
        joined = " ".join(" ".join(c) for c in calls)
        self.assertIn("inet", joined)
        self.assertIn("delete", joined)
        self.assertIn("10.99.0.1", joined)

    def test_dnsmasq_engine_gets_lease_callback(self):
        seen = {}

        def fact(kind, iface, core, log, on_lease=None):
            seen["cb"] = on_lease
            return FakeEngine(iface, core, log)

        s = Session(self.make_session().cfg, log=lambda *a: None, engine_factory=fact,
                    probe_fn=lambda ip, timeout=1.0: discover.Fingerprint(ip=ip))
        s.start()
        self.assertTrue(callable(seen.get("cb")))
        seen["cb"]("aa:bb:cc:00:00:07", "10.99.0.100", "idrac-x")
        leases = s.snapshot(0)["leases"]
        self.assertEqual(leases[0]["mac"], "aa:bb:cc:00:00:07")
        self.assertTrue(leases[0]["bound"])
        s.stop()

    def test_no_restore_flag(self):
        s = self.make_session(configure=True, restore=False)
        s.start()
        self.restore.reset_mock()
        s.stop()
        self.assertFalse(self.restore.called)


class TestPool(SessionTestBase):
    def test_pool_forms(self):
        import ipaddress

        net = ipaddress.IPv4Network("10.99.0.0/24")
        self.assertEqual(Session.parse_pool(".100-.110", net), ("10.99.0.100", "10.99.0.110"))
        self.assertEqual(Session.parse_pool("100-110", net), ("10.99.0.100", "10.99.0.110"))
        self.assertEqual(
            Session.parse_pool("10.99.0.5-10.99.0.9", net), ("10.99.0.5", "10.99.0.9")
        )

    def test_pool_rejects_network_and_broadcast(self):
        import ipaddress

        net = ipaddress.IPv4Network("10.99.0.0/24")
        with self.assertRaises(SessionError):
            Session.parse_pool("10.99.0.0", net)
        with self.assertRaises(SessionError):
            Session.parse_pool("10.99.0.255", net)


class TestConfigParsing(unittest.TestCase):
    def test_from_dict_coerces(self):
        cfg = SessionConfig.from_dict({
            "iface": "en7",
            "lease_seconds": "600",
            "dns": "1.1.1.1, 8.8.8.8",
            "routers": [],
            "configure": 0,
            "probe_retry": "3.5",
            "unknown": "x",
        })
        self.assertEqual(cfg.iface, "en7")
        self.assertEqual(cfg.lease_seconds, 600)
        self.assertEqual(cfg.dns, ["1.1.1.1", "8.8.8.8"])
        self.assertFalse(cfg.configure)
        self.assertEqual(cfg.probe_retry, 3.5)
        self.assertFalse(hasattr(cfg, "unknown"))

    def test_from_dict_clamps(self):
        cfg = SessionConfig.from_dict({"lease_seconds": "999999", "probe_retry": "-5"})
        self.assertEqual(cfg.lease_seconds, 86400)
        self.assertEqual(cfg.probe_retry, 0.0)

    def test_from_dict_garbage(self):
        cfg = SessionConfig.from_dict({"lease_seconds": "abc", "dns": None, "iface": None})
        self.assertEqual(cfg.lease_seconds, 300)
        self.assertEqual(cfg.dns, [])
        self.assertEqual(cfg.iface, "")

    def test_from_dict_rejects_unknown_engine(self):
        cfg = SessionConfig.from_dict({"engine": "hack"})
        self.assertEqual(cfg.engine, "auto")

    def test_from_dict_empty_subnet(self):
        cfg = SessionConfig.from_dict({"subnet": "  "})
        self.assertEqual(cfg.subnet, "10.99.0.0/24")


class TestConcurrency(SessionTestBase):
    def test_stop_during_start_waits_and_ends_idle(self):
        slow = {"delay": 0.4}

        def fact(kind, iface, core, log):
            eng = FakeEngine(iface, core, log)
            original = eng.start

            def start(on_ready=None):
                time.sleep(slow["delay"])
                return original(on_ready)

            eng.start = start
            return eng

        s = Session(self.make_session(configure=True).cfg, log=lambda *a: None,
                    engine_factory=fact,
                    probe_fn=lambda ip, timeout=1.0: discover.Fingerprint(ip=ip))
        errors = []

        def run_start():
            try:
                s.start()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        t = threading.Thread(target=run_start)
        t.start()
        time.sleep(0.1)
        s.stop()          # 必须等 start 跑完再停
        t.join(timeout=10)
        self.assertEqual(errors, [])
        self.assertEqual(s.state, "idle")
        self.assertTrue(self.restore.called)


class TestStateFile(unittest.TestCase):
    def test_corrupt_state_files_are_ignored(self):
        import json
        import tempfile

        shapes = [
            ["a"], {"leases": ["x"]}, {"leases": {"10.99.0.100": {}}},
            {"sticky": [], "leases": 5}, {"sticky": {"aa:bb:cc:00:00:01": 5}},
            {"leases": [{"ip": 1, "mac": 2}]}, {"leases": [None]},
        ]
        for shape in shapes:
            path = os.path.join(tempfile.mkdtemp(), "state.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(shape, fh)
            lm = LeaseManager("10.99.0.1", "10.99.0.0/24", "10.99.0.100", "10.99.0.110",
                              lease_seconds=60, state_path=path)
            self.assertEqual(lm.sticky, {}, repr(shape))
            self.assertEqual(lm.leases, {}, repr(shape))
            # 还能正常分配
            self.assertIsNotNone(lm.offer("aa:bb:cc:00:00:09"))


class TestIfaceBackup(SessionTestBase):
    """改网卡前落盘、停止后清掉、被强杀后下次启动补还原。"""

    def setUp(self):
        super().setUp()
        import shutil
        import tempfile

        self.tmp = tempfile.mkdtemp(prefix="bmcd-backup-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = os.path.join(self.tmp, "state.json")
        self.backup = os.path.join(self.tmp, "iface-backup.json")

    def _write_backup(self, **kw):
        import json

        payload = {"iface": "en9", "mode": "dhcp", "ip": "192.168.1.5",
                   "mask": "255.255.255.0", "router": "192.168.1.1",
                   "service": "USB LAN", "applied_ip": "10.99.0.1"}
        payload.update(kw)
        with open(self.backup, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

    def test_backup_written_then_removed_after_restore(self):
        import json

        s = self.make_session(configure=True, state_path=self.state)
        s.start()
        self.assertTrue(os.path.exists(self.backup))
        with open(self.backup, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["applied_ip"], "10.99.0.1")
        self.assertEqual(data["mode"], "dhcp")
        s.stop()
        self.assertFalse(os.path.exists(self.backup))
        self.assertTrue(self.restore.called)

    def test_recover_restores_leftover(self):
        self.iface_ip["value"] = "10.99.0.1"       # 网卡上还挂着我们设的地址
        self._write_backup()
        s = self.make_session(configure=True, state_path=self.state)
        msg = s.recover_backup()
        self.assertIn("补还原", msg)
        self.assertTrue(self.restore.called)
        self.assertFalse(os.path.exists(self.backup))

    def test_recover_skips_when_address_is_not_ours(self):
        self.iface_ip["value"] = "172.16.9.9"      # 用户自己改过
        self._write_backup()
        s = self.make_session(configure=True, state_path=self.state)
        msg = s.recover_backup()
        self.assertIn("不动它", msg)
        self.assertFalse(self.restore.called)
        self.assertFalse(os.path.exists(self.backup))

    def test_recover_drops_record_for_missing_iface(self):
        self._write_backup()
        mock.patch.object(I, "find_by_name", lambda name: None).start()
        s = self.make_session(configure=True, state_path=self.state)
        msg = s.recover_backup()
        self.assertIn("已经不在", msg)
        self.assertFalse(os.path.exists(self.backup))

    def test_recover_handles_corrupt_file(self):
        with open(self.backup, "w", encoding="utf-8") as fh:
            fh.write("{ 这不是 json")
        s = self.make_session(configure=True, state_path=self.state)
        self.assertEqual(s.recover_backup(), "")

    def test_serviceless_iface_has_no_false_restore_warning(self):
        mock.patch.object(I, "describe_config", lambda service: I.SavedConfig(
            iface="en9", service="", mode="none")).start()
        mock.patch.object(I, "run", lambda *a, **k: (0, "", "")).start()
        s = self.make_session(configure=True, state_path=self.state)
        s.start()
        self.assertTrue(os.path.exists(self.backup))
        s.stop()
        self.assertFalse(os.path.exists(self.backup))
        text = " ".join(t for _, t in s.logs)
        self.assertNotIn("还原 en9 的原配置失败", text)
        self.assertFalse(self.restore.called)


class TestDaemonPool(unittest.TestCase):
    def test_runs_tasks(self):
        pool = DaemonPool(workers=2)
        seen = []
        for i in range(6):
            pool.submit(lambda x: seen.append(x), i)
        deadline = time.time() + 3
        while len(seen) < 6 and time.time() < deadline:
            time.sleep(0.02)
        self.assertEqual(sorted(seen), list(range(6)))
        pool.shutdown()

    def test_swallows_errors(self):
        pool = DaemonPool(workers=1)
        seen = []
        pool.submit(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        pool.submit(lambda: seen.append(1))
        deadline = time.time() + 3
        while not seen and time.time() < deadline:
            time.sleep(0.02)
        self.assertEqual(seen, [1])
        pool.shutdown()


class TestIfaceService(SessionTestBase):
    """附录 D-3：UI 提交的 iface_service 以前被 SessionConfig 丢掉。

    index.html 的启动请求体里一直带 iface_service（下拉选的是「网络服务名」），
    SessionConfig 里没有这个字段，from_dict 就把它扔了 —— 用户在下拉里选的网卡
    实际没生效，而且日志里一个字都不提。
    """

    def test_from_dict_parses_iface_service(self):
        cfg = SessionConfig.from_dict({"iface": "", "iface_service": "  AX88179A "})
        self.assertEqual(cfg.iface_service, "AX88179A")
        self.assertEqual(SessionConfig.from_dict({"iface": "en9"}).iface_service, "")
        self.assertEqual(SessionConfig.from_dict({"iface_service": None}).iface_service, "")

    def test_service_only_resolves_to_real_device(self):
        mock.patch.object(I, "service_device",
                          lambda name: "en7" if name == "AX88179A" else "").start()
        s = self.make_session(iface="", iface_service="AX88179A")
        s.start()
        self.assertEqual(s.iface.name, "en7")
        s.stop()
        self.assertTrue(any("AX88179A" in text for _level, text in s.logs))

    def test_service_only_unknown_service_says_so(self):
        mock.patch.object(I, "service_device", lambda name: "").start()
        s = self.make_session(iface="", iface_service="没有这块网卡")
        with self.assertRaises(SessionError) as ctx:
            s.start()
        self.assertIn("找不到网络服务", str(ctx.exception))
        self.assertIn("没有这块网卡", str(ctx.exception))
        self.assertEqual(s.state, "error")

    def test_service_known_but_device_missing_says_so(self):
        mock.patch.object(I, "service_device", lambda name: "en7").start()
        mock.patch.object(I, "find_by_name", lambda name: None).start()
        s = self.make_session(iface="", iface_service="AX88179A")
        with self.assertRaises(SessionError) as ctx:
            s.start()
        self.assertIn("对应的网卡 en7 现在不存在", str(ctx.exception))

    def test_iface_wins_when_both_given(self):
        def boom(name):
            raise AssertionError("iface 有值时不该再去查服务名：%s" % name)

        mock.patch.object(I, "service_device", boom).start()
        s = self.make_session(iface="en9", iface_service="AX88179A")
        s.start()
        self.assertEqual(s.iface.name, "en9")
        s.stop()

    def test_neither_given_falls_back_to_first_candidate(self):
        s = self.make_session(iface="", iface_service="")
        s.start()
        self.assertEqual(s.iface.name, "en9")     # base.setUp 里 ethernet_candidates 的返回值
        s.stop()

    def test_webapp_body_contract_reaches_session(self):
        """UI 真正发出去的 body 形状：iface 为空 + iface_service 有值。"""
        body = {"iface": "", "iface_service": "AX88179A", "subnet": "10.99.0.0/24",
                "configure": False, "state_path": ""}
        cfg = SessionConfig.from_dict(body)
        self.assertEqual(cfg.iface, "")
        self.assertEqual(cfg.iface_service, "AX88179A")
        self.assertFalse(cfg.configure)


class TestHomeIsolation(SessionTestBase):
    """附录 D-5：整套测试不许碰真实家目录。

    session.py / webapp.py 在 import 期就用 user_home() 算出 ~/.bmcd/... ，
    而 _backup_path() 在没有 state_path 时也会退回 user_home()/.bmcd ——
    以前跑一遍测试就会在真实家目录里建出一个空的 ~/.bmcd。
    """

    def test_user_home_is_sandboxed(self):
        real = os.path.realpath(os.path.expanduser("~"))
        home = os.path.realpath(user_home())
        self.assertNotEqual(home, real)
        self.assertTrue(home.startswith(os.path.realpath(TEST_HOME)), (home, TEST_HOME))
        self.assertTrue(DEFAULT_STATE.startswith(TEST_HOME), DEFAULT_STATE)

    def test_backup_path_is_inside_test_home(self):
        """state_path="" 时 _backup_path() 走 user_home()/.bmcd —— 必须落在沙箱里。

        只比路径不比目录列表：这台机器上可能同时有别的进程在写真实 ~/.bmcd
        （比如真跑着的 App），比列表会假红。
        """
        s = self.make_session(configure=True)      # state_path="" → 备份落默认位置
        path = s._backup_path()
        self.assertTrue(path.startswith(TEST_HOME), path)
        real_dir = os.path.realpath(os.path.join(os.path.expanduser("~"), ".bmcd"))
        self.assertNotEqual(os.path.realpath(os.path.dirname(path)), real_dir)
        s.start()
        s.stop()
        self.assertTrue(os.path.isdir(os.path.join(user_home(), ".bmcd")))
        self.assertFalse(os.path.exists(os.path.join(real_dir, "iface-backup.json")))


if __name__ == "__main__":
    unittest.main()
