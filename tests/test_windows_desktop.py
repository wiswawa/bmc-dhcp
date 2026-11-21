"""Frozen Windows launcher contracts plus an actual Windows UDP scope smoke test."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import app_win as launcher  # noqa: E402
from bmcdhcp import cli, engines, iface as I, webapp  # noqa: E402
from bmcdhcp.win_desktop import write_config, run_backend  # noqa: E402


class FrozenWindowsLauncherTest(unittest.TestCase):
    def test_frozen_launcher_uses_bundled_backend_without_venv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bmcd.exe").write_bytes(b"test executable")
            ui = root / "_internal/bmcdhcp/ui"
            ui.mkdir(parents=True)
            (ui / "index.html").write_text("test UI")
            with mock.patch.object(sys, "frozen", True, create=True), \
                    mock.patch.object(sys, "executable", str(root / "BMC DHCP.exe")), \
                    mock.patch.object(launcher, "HERE", str(root / "_internal")), \
                    mock.patch.object(launcher, "_capture") as capture:
                self.assertEqual(launcher.missing_package_files(), [])
                self.assertEqual(launcher.ensure_backend_python(), str(root / "bmcd.exe"))
                capture.assert_not_called()

    def test_backend_bootstrap_is_consumed_and_user_paths_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = write_config(str(root), token="test-token", home=str(root / "home"),
                                  session=str(root / "session.json"), fallback=str(root / "fallback.json"),
                                  log=str(root / "backend.log"))
            with mock.patch.dict(os.environ), mock.patch.object(webapp, "main", return_value=0) as main:
                self.assertEqual(run_backend(config), 0)
                self.assertEqual(os.environ["BMCD_HOME"], str(root / "home"))
                self.assertEqual(os.environ["BMCD_SESSION_FILE"], str(root / "session.json"))
                main.assert_called_once_with(host="127.0.0.1", port=0, token="test-token")
            self.assertFalse(Path(config).exists())

    def test_invalid_bootstrap_is_deleted_without_starting_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"
            path.write_text(json.dumps({"token": "test-token"}))
            with mock.patch.object(webapp, "main") as main:
                with self.assertRaises(ValueError):
                    run_backend(str(path))
                main.assert_not_called()
            self.assertFalse(path.exists())

    def test_loopback_session_selftest_needs_no_os_loopback_adapter_name(self):
        with mock.patch.object(I, "find_by_name", side_effect=AssertionError("must use virtual loopback")):
            ok, detail = cli._loopback_session_check()
        self.assertTrue(ok, detail)


class WindowsSocketIsolationTest(unittest.TestCase):
    def test_unindexed_interface_fails_before_wildcard_bind(self):
        interface = I.Interface(name="missing-index")
        engine = engines.UdpEngine(interface, mock.Mock(), lambda *args: None, bind_port=0)
        with mock.patch.object(engines, "IS_WINDOWS", True):
            with self.assertRaisesRegex(engines.EngineUnavailable, "网卡索引"):
                engine.start()

    @unittest.skipUnless(sys.platform == "win32", "requires the real Winsock implementation")
    def test_winsock_iflist_receives_only_the_selected_loopback_interface(self):
        interface = next(item for item in I.enumerate_all() if item.loopback and item.if_index)
        core = mock.Mock()
        core.handle.return_value = []
        engine = engines.UdpEngine(interface, core, lambda *args: None, bind_port=0)
        ready = threading.Event()
        thread = threading.Thread(target=engine.start, args=(ready.set,), daemon=True)
        thread.start()
        try:
            self.assertTrue(ready.wait(3))
            self.assertEqual(engine._recv.getsockopt(socket.IPPROTO_IP, 28), 1)
            port = engine._recv.getsockname()[1]
            from bmcdhcp import dhcp as D
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(D.build_client_packet(D.DISCOVER, "02:00:00:00:00:55", 55).pack(),
                              ("127.0.0.1", port))
            for _ in range(30):
                if core.handle.called:
                    break
                threading.Event().wait(0.05)
            self.assertTrue(core.handle.called)
        finally:
            engine.stop()
            thread.join(3)


if __name__ == "__main__":
    unittest.main()
