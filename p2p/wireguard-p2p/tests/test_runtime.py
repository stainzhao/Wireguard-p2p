import base64
import importlib.util
import os
import pathlib
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


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        agent.STATES = {}

    def _key(self):
        return base64.b64encode(b"x" * 32).decode()

    def _state(self, key, peer_ip="10.0.0.3"):
        session_id = str(uuid.uuid4())
        state = agent.new_peer_state(peer_ip, session_id, time.time_ns())
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
        self.assertEqual(agent.VERSION, "7.6.0")
        self.assertEqual(api.VERSION, "7.6.0")
        self.assertEqual(agent.DIRECT_MONITOR_INTERVAL, 30)
        self.assertEqual(agent.IDLE_MONITOR_INTERVAL, 60)
        self.assertEqual(agent.REFLEXIVE6_REFRESH_INTERVAL, 600)
        self.assertEqual(agent.REFLEXIVE6_TTL, 1800)
        self.assertEqual(api.SESSION_TTL, 180)
        self.assertEqual(api.OFFER_REFRESH, 120)
        self.assertEqual(api.ANNOUNCE_TTL, 300)

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
        self.assertEqual(len(payloads), len(api.SERVER_IPS))
        self.assertTrue(all(item["reason"] == "expired" for item in payloads))


if __name__ == "__main__":
    unittest.main()
