import importlib.util
import contextlib
import io
import os
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


api = load_module("peers_api", ROOT / "vps" / "peers_api.py")
sync = load_module("p2p_sync", ROOT / "linux" / "p2p_sync.py")
os.environ.setdefault("P2P_LISTEN_ADDRESS", "10.0.0.5")
agent = load_module("p2p_agent", ROOT / "linux" / "p2p_agent.py")


class ApiTests(unittest.TestCase):
    def setUp(self):
        with api.STATE_LOCK:
            api.LAN_CANDIDATES.clear()
            api.SESSIONS.clear()
            for status in api.SERVER_PUSH_STATUS.values():
                status.update({
                    "ok": None,
                    "last_success": 0,
                    "last_error": 0,
                    "last_error_message": "",
                    "consecutive_failures": 0,
                    "last_error_log": 0,
                })

    def test_roles(self):
        self.assertEqual(api.peer_role("10.0.0.2"), "server")
        self.assertEqual(api.peer_role("10.0.0.8"), "relay_only")
        self.assertEqual(api.peer_role("10.0.0.4"), "client")

    def test_announcement_validation(self):
        self.assertEqual(
            api.validate_announcement({
                "lan_ip": "192.168.0.10",
                "listen_port": 51820,
            }),
            ("192.168.0.10", 51820),
        )
        with self.assertRaises(ValueError):
            api.validate_announcement({
                "lan_ip": "8.8.8.8",
                "listen_port": 51820,
            })

    def test_client_event_pushes_offer_and_records_server_lan(self):
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
            api.coordinate_client(client, "192.168.1.4:40000", [client, server])
        finally:
            api.push_offer = original
        self.assertIn("10.0.0.4", api.SESSIONS)
        self.assertEqual(
            api.LAN_CANDIDATES["10.0.0.5"]["lan_ip"],
            "192.168.0.198",
        )

    def test_disconnect_clears_client_and_server_candidates(self):
        client = {"key": "client-key", "ip": "10.0.0.4"}
        with api.STATE_LOCK:
            api.SESSIONS[client["ip"]] = dict(client, last_seen=1)
            api.LAN_CANDIDATES[client["ip"]] = {"seen": 1}
            api.LAN_CANDIDATES["10.0.0.2"] = {"seen": 1}
        original = api.push_remove
        api.push_remove = lambda _client: None
        try:
            api.disconnect_client(client)
        finally:
            api.push_remove = original
        self.assertEqual(api.SESSIONS, {})
        self.assertNotIn(client["ip"], api.LAN_CANDIDATES)
        self.assertNotIn("10.0.0.2", api.LAN_CANDIDATES)

    def test_push_status_tracks_failure_and_recovery(self):
        api.record_push_result("10.0.0.2", False, "timeout")
        self.assertEqual(
            api.SERVER_PUSH_STATUS["10.0.0.2"]["consecutive_failures"], 1
        )
        api.record_push_result("10.0.0.2", True)
        self.assertTrue(api.SERVER_PUSH_STATUS["10.0.0.2"]["ok"])
        self.assertEqual(
            api.SERVER_PUSH_STATUS["10.0.0.2"]["consecutive_failures"], 0
        )


class SyncTests(unittest.TestCase):
    def test_only_server_client_pairs_are_eligible(self):
        self.assertTrue(sync.eligible_pair("server", "client"))
        self.assertTrue(sync.eligible_pair("client", "server"))
        self.assertFalse(sync.eligible_pair("server", "server"))
        self.assertFalse(sync.eligible_pair("client", "client"))
        self.assertFalse(sync.eligible_pair("server", "relay_only"))

    def test_retry_delay_is_capped(self):
        self.assertEqual(sync.retry_delay(1), 60)
        self.assertEqual(sync.retry_delay(2), 120)
        self.assertEqual(sync.retry_delay(3), 300)
        self.assertEqual(sync.retry_delay(10), 300)


class AgentTests(unittest.TestCase):
    def test_direct_age_allows_wireguard_rekey_interval(self):
        self.assertEqual(agent.DIRECT_MAX_AGE, 180)
        self.assertEqual(sync.DIRECT_MAX_AGE, 180)

    def test_peer_validation(self):
        key = "SCTH2DOd6XhU0QZLFCgClEKWgZPNHr6QtmPpb6S05EM="
        self.assertEqual(agent.validate_public_key(key), key)
        self.assertEqual(agent.validate_peer_ip("10.0.0.4"), "10.0.0.4")
        self.assertEqual(
            agent.validate_endpoint("211.71.91.89:51820"),
            "211.71.91.89:51820",
        )

    def test_server_and_relay_peers_are_rejected(self):
        for address in ("10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.8"):
            with self.assertRaises(ValueError):
                agent.validate_peer_ip(address)

    def test_event_logs_are_quiet_by_default(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            agent.log("normal event")
        self.assertFalse(agent.VERBOSE_LOG)
        self.assertEqual(output.getvalue(), "")

    def test_errors_are_written_to_stderr(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            agent.log_error("monitor failed")
        self.assertIn("monitor failed", output.getvalue())

    def test_repeated_probe_failures_enter_long_cooldown(self):
        self.assertEqual(agent.retry_delay(1), 3)
        self.assertEqual(agent.retry_delay(2), 10)
        self.assertEqual(agent.retry_delay(3), 1800)
        self.assertEqual(agent.retry_delay(20), 1800)


if __name__ == "__main__":
    unittest.main()
