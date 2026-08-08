import hashlib
import hmac
import importlib.util
import os
import pathlib
import time
import unittest
import uuid


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


api = load_module("peers_api_security_v7", ROOT / "vps" / "peers_api.py")
os.environ.setdefault("P2P_LISTEN_ADDRESS", "10.0.0.5")
agent = load_module("p2p_agent_security_v7", ROOT / "linux" / "p2p_agent.py")


VALID_KEY = "SCTH2DOd6XhU0QZLFCgClEKWgZPNHr6QtmPpb6S05EM="


class SignedNotificationTests(unittest.TestCase):
    def setUp(self):
        agent.NOTIFY_KEY = b"x" * 32
        with agent.NONCE_LOCK:
            agent.SEEN_NONCES.clear()

    def signed(self, path, nonce, body, now):
        timestamp = str(int(now))
        signature = hmac.new(
            agent.NOTIFY_KEY,
            agent.signature_payload("POST", path, timestamp, nonce, body),
            hashlib.sha256,
        ).hexdigest()
        return timestamp, signature

    def test_valid_notification_is_accepted_once(self):
        now = time.time()
        body = b'{"value":1}'
        nonce = "01" * 16
        timestamp, signature = self.signed("/offer", nonce, body, now)
        result = agent.verify_signed_notification(
            "POST", "/offer", timestamp, nonce, signature, body, now=now
        )
        self.assertEqual(result["value"], 1)
        with self.assertRaises(PermissionError):
            agent.verify_signed_notification(
                "POST", "/offer", timestamp, nonce, signature, body, now=now
            )

    def test_signature_is_bound_to_path(self):
        now = time.time()
        body = b'{"value":2}'
        nonce = "02" * 16
        timestamp, signature = self.signed("/offer", nonce, body, now)
        with self.assertRaises(PermissionError):
            agent.verify_signed_notification(
                "POST", "/remove", timestamp, nonce, signature, body, now=now
            )


class SessionIsolationTests(unittest.TestCase):
    def setUp(self):
        with api.STATE_LOCK:
            api.LAN_CANDIDATES.clear()
            api.NODE_CANDIDATES.clear()
            api.SESSIONS.clear()
        with agent.STATE_LOCK:
            agent.STATES.clear()

    def test_coordinator_reuses_session_id_for_refresh(self):
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
        original = api.push_offer
        api.push_offer = lambda *_args: {
            "ok": True,
            "lan_ip": "192.168.0.198",
            "listen_port": 33967,
        }
        try:
            first = api.coordinate_client(
                client, "192.168.1.4:40000", [client, server]
            )
            second = api.coordinate_client(
                client, "192.168.1.4:40000", [client, server], force=True
            )
        finally:
            api.push_offer = original
        self.assertEqual(first, second)
        uuid.UUID(first)
        self.assertGreater(api.SESSIONS[client["ip"]]["session_started_ns"], 0)

    def test_old_remove_cannot_delete_new_session(self):
        current_session = str(uuid.uuid4())
        stale_session = str(uuid.uuid4())
        with agent.STATE_LOCK:
            agent.STATES[VALID_KEY] = agent.new_peer_state(
                "10.0.0.4", current_session, api.time_ns()
            )
        result = agent.handle_remove({
            "peer_key": VALID_KEY,
            "peer_ip": "10.0.0.4",
            "session_id": stale_session,
        })
        self.assertFalse(result["removed"])
        self.assertEqual(result["reason"], "session_mismatch")
        self.assertIn(VALID_KEY, agent.STATES)

    def test_late_old_offer_cannot_replace_new_session(self):
        current_session = str(uuid.uuid4())
        stale_session = str(uuid.uuid4())
        current_started = api.time_ns()
        with agent.STATE_LOCK:
            agent.STATES[VALID_KEY] = agent.new_peer_state(
                "10.0.0.4", current_session, current_started
            )

        original = agent.local_wg_peers
        agent.local_wg_peers = lambda: {}
        try:
            result = agent.handle_offer({
                "session_id": stale_session,
                "session_started_ns": current_started - 1,
                "peer_key": VALID_KEY,
                "peer_ip": "10.0.0.4",
                "endpoint": "198.51.100.4:40000",
                "endpoint_type": "WAN",
                "candidates": [{
                    "type": "observed4",
                    "family": "udp4",
                    "endpoint": "198.51.100.4:40000",
                    "priority": 600,
                    "verified": True,
                }],
                "lease_expires": int(time.time()) + 120,
            })
        finally:
            agent.local_wg_peers = original

        self.assertTrue(result["ignored"])
        self.assertEqual(result["reason"], "stale_session")
        self.assertEqual(agent.STATES[VALID_KEY]["session_id"], current_session)


if __name__ == "__main__":
    unittest.main()
