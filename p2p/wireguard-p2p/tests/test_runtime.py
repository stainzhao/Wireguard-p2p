import base64
import importlib.util
import os
import pathlib
import tempfile
import time
import unittest
import uuid
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
LINUX = ROOT / "linux"
os.environ.setdefault("P2P_LISTEN_ADDRESS", "10.0.0.5")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


agent = load_module("p2p_agent_runtime", LINUX / "p2p_agent.py")
api = load_module("peers_api_runtime", ROOT / "vps" / "peers_api.py")
daemon = load_module("portmap_daemon_runtime", LINUX / "portmap_daemon.py")
candidates = load_module("candidates_runtime", LINUX / "candidates.py")
manager = load_module("manager_runtime", ROOT / "manage" / "wireguard-p2p.py")


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        agent.STATES = {}

    def _key(self):
        return base64.b64encode(b"x" * 32).decode()

    def _state(self, key, peer_ip="10.0.0.3"):
        session_id = str(uuid.uuid4())
        state = agent.new_peer_state(peer_ip, session_id, agent.time_ns())
        state["lease_expires"] = time.time() + 120
        agent.STATES[key] = state
        return state, session_id

    def _local(self, peer_ip="10.0.0.3"):
        return {
            "endpoint": "[2409:8a04::1234]:51820",
            "allowed_ips": [peer_ip + "/32"],
            "latest_handshake": int(time.time()),
            "keepalive": 25,
        }

    def test_release_and_resource_constants(self):
        self.assertEqual(agent.VERSION, "7.12.0")
        self.assertEqual(api.VERSION, "7.12.0")
        self.assertEqual(agent.DIRECT_MONITOR_INTERVAL, 30)
        self.assertEqual(agent.IDLE_MONITOR_INTERVAL, 60)
        self.assertEqual(agent.REFLEXIVE6_REFRESH_INTERVAL, 600)
        self.assertEqual(agent.REFLEXIVE6_TTL, 1800)
        self.assertEqual(api.SESSION_TTL, 180)
        self.assertEqual(api.OFFER_REFRESH, 120)
        self.assertEqual(api.ANNOUNCE_TTL, 300)
        self.assertEqual(agent.INITIATOR_SYNC_INTERVAL, 15)
        self.assertEqual(agent.INITIATOR_ONLINE_MAX_AGE, 180)

    def test_runtime_state_is_ram_backed(self):
        self.assertTrue(agent.STATE_FILE.startswith("/run/"))
        self.assertTrue(daemon.STATE_FILE.startswith("/run/"))
        self.assertTrue(candidates.PORTMAP_STATE_FILE.startswith("/run/"))
        self.assertEqual(daemon.POLL_INTERVAL, 60)

    def test_services_are_quiet_and_ram_backed(self):
        for name in (
            "wireguard-p2p-agent.service",
            "wireguard-p2p-portmap.service",
        ):
            text = (LINUX / name).read_text(encoding="utf-8")
            self.assertIn("RuntimeDirectory=wireguard-p2p", text)
            self.assertIn("RuntimeDirectoryMode=0700", text)
            self.assertIn("StandardOutput=null", text)
            self.assertIn("StandardError=journal", text)
            self.assertIn("LogRateLimitIntervalSec=5min", text)
            self.assertIn("LogRateLimitBurst=20", text)
            self.assertNotIn("StateDirectory=wireguard-p2p", text)
        portmap = (LINUX / "portmap_daemon.py").read_text(encoding="utf-8")
        self.assertNotIn("os.fsync", portmap)

    def test_direct_health_requires_fresh_handshake_and_overlay_route(self):
        local = self._local()
        self.assertTrue(agent.direct_peer_healthy(local, "10.0.0.3"))
        stale = dict(
            local,
            latest_handshake=int(time.time()) - agent.DIRECT_MAX_AGE - 1,
        )
        self.assertFalse(agent.direct_peer_healthy(stale, "10.0.0.3"))
        self.assertFalse(agent.direct_peer_healthy(dict(local, allowed_ips=[]), "10.0.0.3"))

    def test_expired_control_session_preserves_healthy_direct(self):
        key = self._key()
        state, session_id = self._state(key)
        state["mode"] = "direct"
        local = self._local()
        with mock.patch.object(agent, "local_wg_peers", return_value={key: local}), \
             mock.patch.object(agent, "wg_set") as wg_set, \
             mock.patch.object(agent, "save_state"):
            result = agent.handle_remove({
                "peer_key": key,
                "peer_ip": "10.0.0.3",
                "session_id": session_id,
                "reason": "expired",
            })
        self.assertFalse(result["removed"])
        self.assertTrue(result["preserved_direct"])
        self.assertTrue(agent.STATES[key]["control_expired"])
        wg_set.assert_not_called()

    def test_explicit_disconnect_removes_direct(self):
        key = self._key()
        _state, session_id = self._state(key)
        local = self._local()
        with mock.patch.object(agent, "local_wg_peers", return_value={key: local}), \
             mock.patch.object(agent, "wg_set") as wg_set, \
             mock.patch.object(agent, "save_state"):
            result = agent.handle_remove({
                "peer_key": key,
                "peer_ip": "10.0.0.3",
                "session_id": session_id,
                "reason": "disconnect",
            })
        self.assertTrue(result["removed"])
        self.assertNotIn(key, agent.STATES)
        wg_set.assert_called_once_with("peer", key, "remove")

    def test_vps_expiration_remove_is_non_destructive(self):
        session = {
            "session_id": str(uuid.uuid4()),
            "key": self._key(),
            "ip": "10.0.0.3",
        }
        with mock.patch.object(api, "signed_post", return_value={"ok": True}) as signed:
            api.push_remove(session, reason="expired")
        payloads = [call.args[2] for call in signed.call_args_list]
        self.assertEqual(len(payloads), len(api.server_ips()))
        self.assertTrue(all(item["reason"] == "expired" for item in payloads))


    def test_server_dual_capability_is_integrated_into_agent(self):
        source = (LINUX / "p2p_agent.py").read_text(encoding="utf-8")
        self.assertIn("def server_initiator_loop", source)
        self.assertIn("COORDINATOR_SYNC_URL", source)
        self.assertIn('controller="initiator"', source)
        self.assertNotIn("wireguard-p2p-initiator.service", source)

    def test_managed_update_distribution(self):
        self.assertEqual(api.update_asset_path("/updates/manifest.json").endswith("/manifest.json"), True)
        with self.assertRaises(ValueError):
            api.update_asset_path("/updates/../notify.key")
        manager = ROOT / "manage" / "wireguard-p2p.py"
        self.assertTrue(manager.exists())
        text = manager.read_text(encoding="utf-8")
        self.assertIn("sudo wireguard-p2p update", text if "sudo wireguard-p2p update" in text else "sudo wireguard-p2p update")


    def test_managed_installers_restart_existing_services(self):
        client_installer = (ROOT.parent / "wireguard-p2p-client" / "deploy" / "linux" / "install.sh").read_text(encoding="utf-8")
        server_installer = (LINUX / "install_server.sh").read_text(encoding="utf-8")
        vps_installer = (ROOT / "vps" / "install_vps.sh").read_text(encoding="utf-8")
        self.assertIn("systemctl restart wireguard-p2p-client.service", client_installer)
        self.assertIn("systemctl restart wireguard-p2p-agent.service", server_installer)
        self.assertIn("systemctl restart wireguard-p2p-portmap.service", server_installer)
        self.assertIn("disable --now wireguard-p2p-client.service", server_installer)
        manager_source = (ROOT / "manage" / "wireguard-p2p.py").read_text(encoding="utf-8")
        self.assertIn('systemctl("disable", "wireguard-p2p-client.service"', manager_source)
        self.assertIn("systemctl restart peers-api.service", vps_installer)

    def test_config_directory_is_traversable_by_service_account(self):
        server_installer = (LINUX / "install_server.sh").read_text(encoding="utf-8")
        vps_installer = (ROOT / "vps" / "install_vps.sh").read_text(encoding="utf-8")
        for installer in (server_installer, vps_installer):
            self.assertIn('install -d -o root -g "$SERVICE_USER" -m 0750 "$CONFIG_DIR"', installer)

    def test_server_bootstrap_does_not_require_executable_archive_mode(self):
        bootstrap = (ROOT / "bootstrap" / "bootstrap-linux-server.sh").read_text(encoding="utf-8")
        self.assertIn('sh "$TMP/pkg/install_server.sh" --interface "$WG_INTERFACE"', bootstrap)

    def test_python36_manager_compatibility(self):
        source = (ROOT / "manage" / "wireguard-p2p.py").read_text(encoding="utf-8")
        self.assertNotIn("missing_ok=True", source)
        self.assertNotIn("text=True", source)
        self.assertIn("universal_newlines=True", source)

    def test_python36_time_ns_fallback(self):
        agent_source = (LINUX / "p2p_agent.py").read_text(encoding="utf-8")
        api_source = (ROOT / "vps" / "peers_api.py").read_text(encoding="utf-8")
        self.assertNotIn("time.time_ns()", agent_source)
        self.assertNotIn("time.time_ns()", api_source)
        self.assertIsInstance(agent.time_ns(), int)
        self.assertIsInstance(api.time_ns(), int)

    def test_installers_verify_service_health_before_success(self):
        server_installer = (LINUX / "install_server.sh").read_text(encoding="utf-8")
        vps_installer = (ROOT / "vps" / "install_vps.sh").read_text(encoding="utf-8")
        self.assertIn("8898/health", server_installer)
        self.assertIn("systemctl is-active --quiet wireguard-p2p-agent.service", server_installer)
        self.assertIn("systemctl is-active --quiet wireguard-p2p-portmap.service", server_installer)
        self.assertIn("10.0.0.1:8899/health", vps_installer)
        self.assertIn("systemctl is-active --quiet peers-api.service", vps_installer)

    def test_manager_repairs_v7100_config_permissions(self):
        old_config = manager.CONFIG_DIR
        old_servers = manager.SERVER_REGISTRY_FILE
        old_relay = manager.RELAY_ONLY_REGISTRY_FILE
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / "wireguard-p2p"
            config.mkdir(mode=0o700)
            key = config / "notify.key"
            servers = config / "servers.conf"
            relay = config / "relay-only.conf"
            key.write_text("x" * 64, encoding="ascii")
            servers.write_text("10.0.0.2\n", encoding="ascii")
            relay.write_text("", encoding="ascii")
            os.chmod(key, 0o600)
            os.chmod(servers, 0o600)
            os.chmod(relay, 0o600)
            try:
                manager.CONFIG_DIR = config
                manager.SERVER_REGISTRY_FILE = servers
                manager.RELAY_ONLY_REGISTRY_FILE = relay
                with mock.patch.object(manager.shutil, "chown") as chown:
                    manager.repair_config_permissions("vps")
                self.assertEqual(config.stat().st_mode & 0o777, 0o750)
                self.assertEqual(key.stat().st_mode & 0o777, 0o400)
                self.assertEqual(servers.stat().st_mode & 0o777, 0o640)
                self.assertEqual(relay.stat().st_mode & 0o777, 0o640)
                chown.assert_any_call(config, user="root", group="wireguard-p2p")
                chown.assert_any_call(key, user="wireguard-p2p", group="wireguard-p2p")
                chown.assert_any_call(servers, user="root", group="wireguard-p2p")
            finally:
                manager.CONFIG_DIR = old_config
                manager.SERVER_REGISTRY_FILE = old_servers
                manager.RELAY_ONLY_REGISTRY_FILE = old_relay

    def test_server_bootstrap_key_is_overlay_restricted(self):
        original_key = api.NOTIFY_KEY
        original_registry = api.SERVER_REGISTRY_FILE
        with tempfile.TemporaryDirectory() as tmp:
            registry = pathlib.Path(tmp) / "servers.conf"
            registry.write_text("10.0.0.8\n", encoding="utf-8")
            try:
                api.SERVER_REGISTRY_FILE = str(registry)
                api.NOTIFY_KEY = b"x" * 32
                self.assertEqual(api.bootstrap_server_key("10.0.0.8"), b"x" * 32 + b"\n")
                with self.assertRaises(PermissionError):
                    api.bootstrap_server_key("10.0.0.3")
            finally:
                api.SERVER_REGISTRY_FILE = original_registry
                api.NOTIFY_KEY = original_key

    def test_one_line_bootstrap_assets_exist(self):
        root = ROOT / "bootstrap"
        for name in ("bootstrap-linux-client.sh", "bootstrap-linux-server.sh", "bootstrap-vps.py"):
            self.assertTrue((root / name).is_file())
        server_installer = (LINUX / "install_server.sh").read_text(encoding="utf-8")
        self.assertIn("10.0.0.*", server_installer)
        self.assertIn("wireguard-p2p server add", server_installer)
        self.assertIn("/bootstrap/server-key", server_installer)


if __name__ == "__main__":
    unittest.main()
