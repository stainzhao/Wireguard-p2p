import importlib.util
import os
import pathlib
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


api = load_module("peers_api_fast_recovery", ROOT / "vps" / "peers_api.py")
os.environ.setdefault("P2P_LISTEN_ADDRESS", "10.0.0.5")
agent = load_module("p2p_agent_fast_recovery", ROOT / "linux" / "p2p_agent.py")

KEY = "SCTH2DOd6XhU0QZLFCgClEKWgZPNHr6QtmPpb6S05EM="
OLD_INSTANCE = "11111111111141118111111111111111"
NEW_INSTANCE = "22222222222242228222222222222222"
SESSION = "33333333-3333-4333-8333-333333333333"


class CoordinatorInstanceTests(unittest.TestCase):
    def setUp(self):
        with api.STATE_LOCK:
            api.LAN_CANDIDATES.clear()
            api.NODE_CANDIDATES.clear()
            api.SESSIONS.clear()

    def test_instance_change_rotates_control_session(self):
        client = {
            "key": "client-key",
            "ip": "10.0.0.4",
            "role": "client",
            "endpoint": "203.0.113.4:40000",
        }
        server = {
            "key": "server-key",
            "ip": "10.0.0.5",
            "role": "server",
            "endpoint": "198.51.100.5:51820",
        }
        with mock.patch.object(api, "push_offer", return_value={"ok": True}), \
             mock.patch.object(api, "push_remove"):
            first = api.coordinate_client(
                client, "192.168.1.4:40000", [client, server],
                instance_id=OLD_INSTANCE,
            )
            same = api.coordinate_client(
                client, "192.168.1.4:40000", [client, server],
                force=True, instance_id=OLD_INSTANCE,
            )
            restarted = api.coordinate_client(
                client, "192.168.1.4:40000", [client, server],
                instance_id=NEW_INSTANCE,
            )
        self.assertEqual(first, same)
        self.assertNotEqual(first, restarted)
        self.assertEqual(api.SESSIONS[client["ip"]]["instance_id"], NEW_INSTANCE)

    def test_peer_payload_exposes_current_instance(self):
        now = time.time()
        peer = {
            "key": "server-key",
            "ip": "10.0.0.5",
            "role": "server",
            "endpoint": "198.51.100.5:51820",
            "latest_handshake": int(now),
        }
        with api.STATE_LOCK:
            api.SESSIONS[peer["ip"]] = {
                "instance_id": NEW_INSTANCE,
                "last_seen": now,
            }
        payload = api.peer_payload([peer])
        self.assertEqual(payload[0]["instance_id"], NEW_INSTANCE)


class AgentInstanceTests(unittest.TestCase):
    def setUp(self):
        with agent.STATE_LOCK:
            agent.STATES.clear()

    def test_remote_instance_change_drops_fresh_old_direct_and_reprobes(self):
        candidates = [{
            "type": "observed4",
            "family": "udp4",
            "endpoint": "198.51.100.8:51820",
            "priority": 700,
            "verified": True,
        }]
        state = agent.new_peer_state(
            "10.0.0.8", SESSION, agent.time_ns(), "initiator", OLD_INSTANCE
        )
        state.update({
            "mode": "direct",
            "candidate_signature": agent.candidate_signature(candidates),
            "candidates": candidates,
        })
        agent.STATES[KEY] = state
        local = {
            "endpoint": "198.51.100.8:51820",
            "allowed_ips": ["10.0.0.8/32"],
            "latest_handshake": int(time.time()),
            "keepalive": 25,
        }
        wg_calls = []

        def fake_wg_set(*args):
            wg_calls.append(args)

        with mock.patch.object(agent, "local_wg_peers", return_value={KEY: local}), \
             mock.patch.object(agent, "wg_set", side_effect=fake_wg_set), \
             mock.patch.object(agent, "launch_probe") as launch, \
             mock.patch.object(agent, "save_state"), \
             mock.patch.object(agent, "local_ipv4", return_value="192.168.0.2"), \
             mock.patch.object(agent, "listen_port", return_value=51820), \
             mock.patch.object(agent, "gather_candidates", return_value=[]), \
             mock.patch.object(agent, "current_reflexive6_candidate", return_value=None), \
             mock.patch.object(agent, "public_key", return_value="server-2"):
            agent.handle_offer({
                "peer_key": KEY,
                "peer_ip": "10.0.0.8",
                "peer_instance_id": NEW_INSTANCE,
                "session_id": SESSION,
                "session_started_ns": state["session_started_ns"],
                "endpoint": "198.51.100.8:51820",
                "endpoint_type": "WAN",
                "candidates": candidates,
            }, controller="initiator")

        self.assertIn(("peer", KEY, "remove"), wg_calls)
        self.assertEqual(agent.STATES[KEY]["peer_instance_id"], NEW_INSTANCE)
        self.assertEqual(agent.STATES[KEY]["mode"], "probe")
        launch.assert_called_once()


if __name__ == "__main__":
    unittest.main()
