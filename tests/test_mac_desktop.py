"""Mac desktop regressions: real loopback DHCP, direct API and orderly shutdown.

No physical interface is configured and no privileged port is opened.
"""

from __future__ import annotations

import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import app as launcher  # noqa: E402
from bmcdhcp import dhcp as D, engines  # noqa: E402
from bmcdhcp.core import ServerConfig, ServerCore  # noqa: E402
from bmcdhcp.iface import Interface  # noqa: E402
from bmcdhcp import iface as I  # noqa: E402
from bmcdhcp.leases import LeaseManager  # noqa: E402
from bmcdhcp.session import Session, SessionConfig, SessionError  # noqa: E402
from bmcdhcp.webapp import App  # noqa: E402


class DesktopLauncherTest(unittest.TestCase):
    def test_frozen_command_uses_bundled_executable(self):
        with mock.patch.object(sys, "frozen", True, create=True), \
                mock.patch.object(sys, "executable", "/App/backend/bmcd-runtime"), \
                mock.patch.object(launcher, "ROOT", "/App/backend/_internal"):
            self.assertEqual(launcher.backend_command(launcher.ROOT, 12345),
                             ["/App/backend/bmcd-runtime", "--backend", "web", "--port", "12345"])
            self.assertEqual(launcher.backend_command("/stage/bundle", 12345)[0],
                             "/stage/bundle/bmcd-runtime")

    def test_staged_bundle_contains_runtime_and_is_versioned(self):
        with tempfile.TemporaryDirectory(prefix="bmcd-stage-") as temp:
            base = Path(temp)
            source = base / "original backend"
            source.mkdir()
            (source / "bmcd-runtime").write_bytes(b"example executable")
            internal = source / "_internal"
            internal.mkdir()
            (internal / "index.html").write_text("test UI")
            (internal / "linked.html").symlink_to("index.html")
            (source / "build-id.txt").write_text("build-one")
            with mock.patch.object(sys, "frozen", True, create=True), \
                    mock.patch.object(sys, "executable", str(source / "bmcd-runtime")), \
                    mock.patch.object(launcher, "RUNTIME_DIR", str(base / "staged")):
                first = Path(launcher.ensure_runtime())
                self.assertEqual((first / "_internal/index.html").read_text(), "test UI")
                self.assertTrue((first / "_internal/linked.html").is_symlink())
                self.assertEqual(str(first), launcher.ensure_runtime())
                (source / "build-id.txt").write_text("build-two")
                second = Path(launcher.ensure_runtime())
                self.assertNotEqual(first, second)
                self.assertTrue(first.exists(), "A live old runtime must not be overwritten")

    def test_loopback_handshake_bypasses_proxy_and_checks_token(self):
        session = Session(SessionConfig(iface="lo0", configure=False, state_path=""),
                          log=lambda *args: None)
        server = App(session, token="desktop-test-token")
        _, port = server.start("127.0.0.1", 0)
        try:
            with mock.patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:1", "no_proxy": ""}):
                self.assertTrue(launcher.ping(port)["ok"])
                self.assertTrue(launcher.token_valid(port, "desktop-test-token"))
                self.assertFalse(launcher.token_valid(port, "wrong-token"))
        finally:
            server.stop()


class ScopedUdpTest(unittest.TestCase):
    def test_dora_uses_server_source_port_and_selected_interface(self):
        loopback = "lo0" if sys.platform == "darwin" else "lo"
        iface = Interface(name=loopback, mac="02:00:00:00:00:01", ipv4="127.0.0.1",
                          netmask="255.0.0.0")
        cfg = ServerConfig(server_ip="10.99.0.1", network="10.99.0.0/24",
                           pool_start="10.99.0.100", pool_end="10.99.0.101")
        leases = LeaseManager(cfg.server_ip, cfg.network, cfg.pool_start, cfg.pool_end,
                              state_path=None)
        core = ServerCore(cfg, leases)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        client.settimeout(3)
        engine = engines.UdpEngine(iface, core, lambda *args: None,
                                   bind_ip="127.0.0.1", bind_port=0,
                                   reply_targets=[client.getsockname()])
        ready = threading.Event()
        thread = threading.Thread(target=engine.start, args=(ready.set,), daemon=True)
        thread.start()
        try:
            self.assertTrue(ready.wait(3))
            address = engine._recv.getsockname()
            if sys.platform == "darwin":
                self.assertEqual(engine._recv.getsockopt(socket.IPPROTO_IP, 25),
                                 socket.if_nametoindex(loopback))
            mac = "02:00:00:00:00:42"
            client.sendto(D.build_client_packet(D.DISCOVER, mac, 42).pack(), address)
            data, source = client.recvfrom(4096)
            offer = D.DHCPMessage.parse(data)
            self.assertEqual(offer.msg_type, D.OFFER)
            self.assertEqual(source[1], address[1], "OFFER must come from the server port")
            client.sendto(D.build_client_packet(D.REQUEST, mac, 42,
                                                requested_ip=offer.yiaddr,
                                                server_id=cfg.server_ip).pack(), address)
            data, source = client.recvfrom(4096)
            ack = D.DHCPMessage.parse(data)
            self.assertEqual(ack.msg_type, D.ACK)
            self.assertEqual(ack.yiaddr, offer.yiaddr)
            self.assertEqual(source[1], address[1], "ACK must come from the server port")
            self.assertTrue(leases.by_mac(mac).bound)
        finally:
            engine.stop()
            client.close()
            thread.join(3)
        self.assertFalse(thread.is_alive())

    @unittest.skipUnless(sys.platform == "darwin", "macOS IP_BOUND_IF")
    def test_missing_interface_cannot_fall_back_to_all_interfaces(self):
        iface = Interface(name="bmcd-missing-nic", mac="02:00:00:00:00:01")
        engine = engines.UdpEngine(iface, mock.Mock(), lambda *args: None,
                                   bind_ip="127.0.0.1", bind_port=0)
        with self.assertRaisesRegex(engines.EngineUnavailable, "绑定到网卡"):
            engine.start()


class MacNetworkConfigTest(unittest.TestCase):
    def test_static_config_supplies_required_router_without_creating_a_gateway(self):
        iface = Interface(name="en7", service="USB Ethernet")
        with mock.patch.object(I, "IS_WINDOWS", False), \
                mock.patch.object(I, "run", return_value=(0, "", "")) as run:
            self.assertTrue(I.set_static(iface, "10.99.0.1"))
            run.assert_called_once_with([I.NETWORKSETUP, "-setmanual", "USB Ethernet",
                                         "10.99.0.1", "255.255.255.0", "0.0.0.0"])

    def test_failed_network_service_config_does_not_silently_leave_dhcp_running(self):
        iface = Interface(name="en7", service="USB Ethernet")
        with mock.patch.object(I, "IS_WINDOWS", False), \
                mock.patch.object(I, "run", return_value=(1, "", "")) as run:
            self.assertFalse(I.set_static(iface, "10.99.0.1"))
            self.assertEqual(run.call_count, 1)

    def test_restoring_manual_config_without_router_is_a_complete_command(self):
        saved = I.SavedConfig(iface="en7", service="USB Ethernet", mode="manual",
                              ip="192.168.50.2", mask="255.255.255.0", router="")
        with mock.patch.object(I, "IS_WINDOWS", False), \
                mock.patch.object(I, "run", return_value=(0, "", "")) as run:
            self.assertTrue(I.restore_config(saved))
            self.assertEqual(run.call_args.args[0][-1], "0.0.0.0")

    def test_server_address_cannot_be_network_or_broadcast(self):
        for ip in ("10.99.0.0", "10.99.0.255"):
            with self.subTest(ip=ip):
                session = Session(SessionConfig(server_ip=ip, configure=False, state_path=""),
                                  log=lambda *args: None)
                try:
                    with self.assertRaisesRegex(SessionError, "网络地址或广播地址"):
                        session.start()
                finally:
                    session.shutdown()


class DesktopShutdownTest(unittest.TestCase):
    def test_two_shutdown_callers_both_wait_for_network_cleanup(self):
        session = mock.Mock()
        app = App(session, token="test")
        app.scanner = mock.Mock()
        app.scanner.cleanup.return_value = []
        entered = threading.Event()
        release = threading.Event()
        done = [threading.Event(), threading.Event()]

        def cleanup():
            entered.set()
            release.wait(3)

        session.shutdown.side_effect = cleanup

        def stop(index):
            app.stop()
            done[index].set()

        first = threading.Thread(target=stop, args=(0,))
        second = threading.Thread(target=stop, args=(1,))
        first.start()
        try:
            self.assertTrue(entered.wait(2))
            second.start()
            self.assertFalse(done[0].wait(0.05))
            self.assertFalse(done[1].wait(0.05))
        finally:
            release.set()
            first.join(3)
            if second.ident:
                second.join(3)
        self.assertTrue(all(event.is_set() for event in done))
        session.shutdown.assert_called_once()

    def test_idle_backend_also_exits_after_losing_ui(self):
        session = mock.Mock(state="idle")
        app = App(session, token="test")
        app.last_heartbeat = time.time() - 121
        with mock.patch.object(app.stop_event, "wait", return_value=False), \
                mock.patch.object(app, "stop") as stop:
            app._watch()
            stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
