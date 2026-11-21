"""Failure-path regressions for recovery, persistence and reserved DHCP addresses."""

from __future__ import annotations

import concurrent.futures
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from bmcdhcp import iface as I
from bmcdhcp import cli, dhcp as D, discover
from bmcdhcp.leases import LeaseManager
from bmcdhcp.session import Session, SessionConfig, SessionError
from bmcdhcp.stateio import atomic_write_json
from bmcdhcp.webapp import App
from test_session import SessionTestBase, FakeEngine


class AtomicPersistenceTest(unittest.TestCase):
    def test_failed_replace_preserves_previous_record_and_removes_temporary_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "recovery.json"
            atomic_write_json(path, {"original": True})
            with mock.patch("bmcdhcp.stateio.os.replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    atomic_write_json(path, {"original": False})
            self.assertEqual(json.loads(path.read_text()), {"original": True})
            self.assertEqual(list(Path(temp).iterdir()), [path])

    def test_non_serializable_data_does_not_truncate_previous_record(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state.json"
            atomic_write_json(path, {"old": 1})
            with self.assertRaises(ValueError):
                atomic_write_json(path, {"expiry": float("nan")})
            self.assertEqual(json.loads(path.read_text()), {"old": 1})

    @unittest.skipIf(os.name == "nt", "POSIX file permissions")
    def test_replacing_world_readable_record_makes_it_private(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "session.json"
            path.write_text("{}")
            path.chmod(0o644)
            atomic_write_json(path, {"token": "test-only"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class NetworkRecoveryFailureTest(SessionTestBase):
    def setUp(self):
        super().setUp()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "state.json")

    def test_unwritable_backup_prevents_all_network_changes(self):
        session = self.make_session(configure=True, state_path=self.path)
        with mock.patch("bmcdhcp.session.atomic_write_json", side_effect=PermissionError("read only")):
            with self.assertRaisesRegex(SessionError, "未修改网口"):
                session.start()
        self.set_static.assert_not_called()
        self.restore.assert_not_called()
        session.shutdown()

    def test_failed_restore_cannot_overwrite_original_backup_on_restart(self):
        session = self.make_session(configure=True, state_path=self.path)
        session.start()
        backup = Path(session._backup_path())
        original = backup.read_bytes()
        self.restore.return_value = False
        session.stop()
        with self.assertRaisesRegex(SessionError, "拒绝覆盖"):
            session.start()
        self.assertEqual(backup.read_bytes(), original)
        self.assertEqual(self.set_static.call_count, 1)
        self.restore.return_value = True
        session.shutdown()

    def test_alias_cleanup_failure_keeps_backup_and_can_be_retried(self):
        with mock.patch.object(I, "describe_config", return_value=I.SavedConfig(
                iface="en9", mode="none", service="")):
            session = self.make_session(configure=True, state_path=self.path)
            session.start()
        with mock.patch.object(I, "run", return_value=(1, "", "permission denied")):
            session.stop()
        self.assertTrue(Path(session._backup_path()).exists())
        self.assertEqual(session._ifconfig_added, "10.99.0.1")
        with mock.patch.object(I, "run", return_value=(0, "", "")):
            session.stop()
        self.assertFalse(Path(session._backup_path()).exists())
        self.assertIsNone(session._ifconfig_added)
        session.shutdown()


class ReservedAddressTest(unittest.TestCase):
    def manager(self, path=None):
        return LeaseManager("10.99.0.1", "10.99.0.0/24", "10.99.0.0", "10.99.0.3", state_path=path)

    def test_requested_server_or_network_address_is_never_offered(self):
        for requested in ("10.99.0.0", "10.99.0.1"):
            with self.subTest(requested=requested):
                manager = self.manager()
                self.assertEqual(manager.offer("02:00:00:00:00:01", hint=requested), "10.99.0.2")
                self.assertFalse(manager.is_free_for(requested, "02:00:00:00:00:01"))
                with self.assertRaises(ValueError):
                    manager.bind(requested, "02:00:00:00:00:01")
                self.assertEqual(manager.stats()["pool"], 2)

    def test_corrupt_sticky_mapping_to_server_is_ignored(self):
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp) / "state.json")
            atomic_write_json(path, {"sticky": {"02:00:00:00:00:01": "10.99.0.1"}})
            manager = self.manager(path)
            self.assertEqual(manager.offer("02:00:00:00:00:01"), "10.99.0.2")

    def test_expired_offer_is_reported_as_free_capacity(self):
        manager = self.manager()
        manager.offer("02:00:00:00:00:01", now=1)
        self.assertEqual(manager.stats()["offered"], 0)
        self.assertEqual(manager.stats()["free"], 2)


class LocalControlServerTest(unittest.TestCase):
    def test_api_cannot_redirect_privileged_lease_output(self):
        with tempfile.TemporaryDirectory() as temp:
            configured = Path(temp) / "configured.json"
            requested = Path(temp) / "client-controlled.json"
            session = Session(SessionConfig(iface="lo0", configure=False, state_path=str(configured)),
                              log=lambda *args: None,
                              engine_factory=lambda kind, iface, core, log: FakeEngine(iface, core, log),
                              probe_fn=lambda ip, **kwargs: discover.Fingerprint(ip=ip))
            app = App(session, token="test-only")
            _, port = app.start("127.0.0.1", 0)
            try:
                payload = {"iface": "lo0", "configure": False, "state_path": str(requested)}
                request = Request(f"http://127.0.0.1:{port}/api/start", method="POST",
                                  data=json.dumps(payload).encode(),
                                  headers={"Content-Type": "application/json", "X-BMCD-Token": "test-only"})
                with build_opener(ProxyHandler({})).open(request, timeout=5) as response:
                    self.assertEqual(response.status, 200)
                mac = "02:00:00:00:00:77"
                offer = session.core.handle(D.build_client_packet(D.DISCOVER, mac, 77), mac)[0]
                session.core.handle(D.build_client_packet(D.REQUEST, mac, 77,
                                                         requested_ip=offer.msg.yiaddr,
                                                         server_id=session.server_cfg.server_ip), mac)
                self.assertTrue(configured.is_file())
                self.assertFalse(requested.exists())
            finally:
                app.stop()

    def test_network_facing_bind_is_rejected_before_listening(self):
        session = Session(SessionConfig(configure=False, state_path=""), log=lambda *args: None)
        app = App(session)
        try:
            with self.assertRaisesRegex(ValueError, "环回"):
                app.start("0.0.0.0", 0)
            self.assertIsNone(app.server)
        finally:
            app.stop()

    def test_origin_without_port_does_not_match_another_local_port(self):
        session = Session(SessionConfig(configure=False, state_path=""), log=lambda *args: None)
        app = App(session, token="test-only")
        _, port = app.start("127.0.0.1", 0)
        try:
            req = Request(f"http://127.0.0.1:{port}/api/heartbeat", data=b"{}", method="POST",
                          headers={"Content-Type": "application/json", "X-BMCD-Token": "test-only",
                                   "Origin": "http://localhost"})
            with self.assertRaises(HTTPError) as error:
                build_opener(ProxyHandler({})).open(req, timeout=3)
            self.assertEqual(error.exception.code, 403)
            error.exception.close()
        finally:
            app.stop()


class ConcurrentSelftestTest(unittest.TestCase):
    def test_multiple_dora_selftests_do_not_share_fixed_ports(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: cli._loopback_dora(), range(3)))
        self.assertTrue(all(ok for ok, _ in results), results)


if __name__ == "__main__":
    unittest.main()
