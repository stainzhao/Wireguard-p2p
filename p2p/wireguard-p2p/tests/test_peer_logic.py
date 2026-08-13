import contextlib
import importlib.util
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

    def test_roles_default_to_client_without_registry_entries(self):
        self.assertEqual(api.peer_role("10.0.0.2"), "client")
        self.assertEqual(api.peer_role("10.0.0.8"), "client")
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

    def test_disconnect_clears_client_and_explicit_server_candidates(self):
        client = {"key": "client-key", "ip": "10.0.0.4"}
        with api.STATE_LOCK:
            api.SESSIONS[client["ip"]] = dict(client, last_seen=1)
            api.LAN_CANDIDATES[client["ip"]] = {"seen": 1}
            api.LAN_CANDIDATES["10.0.0.2"] = {"seen": 1}
        original_push = api.push_remove
        original_servers = api.server_ips
        api.push_remove = lambda _client: None
        api.server_ips = lambda: {"10.0.0.2"}
        try:
            api.disconnect_client(client)
        finally:
            api.push_remove = original_push
            api.server_ips = original_servers
        self.assertEqual(api.SESSIONS, {})
        self.assertNotIn(client["ip"], api.LAN_CANDIDATES)
        self.assertNotIn("10.0.0.2", api.LAN_CANDIDATES)

    def test_server_initiator_targets_only_higher_server(self):
        source = {
            "key": "server-5",
            "ip": "10.0.0.5",
            "role": "server",
            "endpoint": "198.51.100.5:51820",
        }
        peers = [
            {"key": "server-2", "ip": "10.0.0.2", "role": "server"},
            source,
            {"key": "server-8", "ip": "10.0.0.8", "role": "server"},
        ]
        targets = api.initiator_servers(source, peers)
        self.assertEqual([item["ip"] for item in targets], ["10.0.0.8"])
        self.assertTrue(api.server_initiator_owns_pair("10.0.0.2", "10.0.0.5"))
        self.assertFalse(api.server_initiator_owns_pair("10.0.0.5", "10.0.0.2"))

    def test_normal_client_still_targets_all_servers(self):
        source = {"key": "client-4", "ip": "10.0.0.4", "role": "client"}
        peers = [
            source,
            {"key": "server-2", "ip": "10.0.0.2", "role": "server"},
            {"key": "server-5", "ip": "10.0.0.5", "role": "server"},
        ]
        targets = api.initiator_servers(source, peers)
        self.assertEqual(
            [item["ip"] for item in targets], ["10.0.0.2", "10.0.0.5"]
        )

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


class AgentTests(unittest.TestCase):
    def test_direct_age_allows_wireguard_rekey_interval(self):
        self.assertEqual(agent.DIRECT_MAX_AGE, 180)

    def test_peer_validation(self):
        key = "SCTH2DOd6XhU0QZLFCgClEKWgZPNHr6QtmPpb6S05EM="
        self.assertEqual(agent.validate_public_key(key), key)
        self.assertEqual(agent.validate_peer_ip("10.0.0.4"), "10.0.0.4")
        self.assertEqual(
            agent.validate_endpoint("211.71.91.89:51820"),
            "211.71.91.89:51820",
        )

    def test_only_vps_and_self_are_rejected_by_agent(self):
        for address in ("10.0.0.1", "10.0.0.5"):
            with self.assertRaises(ValueError):
                agent.validate_peer_ip(address)
        self.assertEqual(agent.validate_peer_ip("10.0.0.2"), "10.0.0.2")
        self.assertEqual(agent.validate_peer_ip("10.0.0.8"), "10.0.0.8")

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

    def test_new_control_session_refreshes_session_start_on_healthy_direct(self):
        key = "SCTH2DOd6XhU0QZLFCgClEKWgZPNHr6QtmPpb6S05EM="
        old_session = "11111111-1111-4111-8111-111111111111"
        new_session = "22222222-2222-4222-8222-222222222222"
        old_started = agent.time_ns() - 1000000000
        new_started = agent.time_ns()
        state = agent.new_peer_state("10.0.0.8", old_session, old_started)
        state["mode"] = "direct"
        agent.STATES = {key: state}
        local = {
            "endpoint": "203.0.113.8:51820",
            "allowed_ips": ["10.0.0.8/32"],
            "latest_handshake": int(__import__("time").time()),
            "keepalive": 25,
        }
        from unittest import mock
        with mock.patch.object(agent, "local_wg_peers", return_value={key: local}), \
             mock.patch.object(agent, "save_state"), \
             mock.patch.object(agent, "local_ipv4", return_value="192.168.0.5"), \
             mock.patch.object(agent, "listen_port", return_value=51820), \
             mock.patch.object(agent, "gather_candidates", return_value=[]), \
             mock.patch.object(agent, "current_reflexive6_candidate", return_value=None), \
             mock.patch.object(agent, "public_key", return_value="x"):
            agent.handle_offer({
                "peer_key": key,
                "peer_ip": "10.0.0.8",
                "session_id": new_session,
                "session_started_ns": new_started,
                "endpoint": "203.0.113.8:51820",
                "endpoint_type": "WAN",
                "candidates": [{
                    "type": "observed4",
                    "family": "udp4",
                    "endpoint": "203.0.113.8:51820",
                    "priority": 700,
                    "verified": True,
                }],
            })
        self.assertEqual(agent.STATES[key]["session_id"], new_session)
        self.assertEqual(agent.STATES[key]["session_started_ns"], new_started)

    def test_server_pair_has_single_deterministic_initiator(self):
        self.assertTrue(agent.server_initiator_owns_pair("10.0.0.2", "10.0.0.5"))
        self.assertFalse(agent.server_initiator_owns_pair("10.0.0.5", "10.0.0.2"))
        self.assertFalse(agent.server_initiator_owns_pair("10.0.0.5", "10.0.0.5"))

    def test_server_initiator_online_filter(self):
        now = 1000
        peer = {
            "key": "server-key",
            "ip": "10.0.0.8",
            "role": "server",
            "endpoint": "198.51.100.8:51820",
            "latest_handshake": now - 10,
        }
        self.assertTrue(agent.eligible_initiator_server(peer, now))
        peer["latest_handshake"] = now - agent.INITIATOR_ONLINE_MAX_AGE - 1
        self.assertFalse(agent.eligible_initiator_server(peer, now))

    def test_repeated_probe_failures_enter_long_cooldown(self):
        self.assertEqual(agent.retry_delay(1), 3)
        self.assertEqual(agent.retry_delay(2), 10)
        self.assertEqual(agent.retry_delay(3), 1800)
        self.assertEqual(agent.retry_delay(20), 1800)


if __name__ == "__main__":
    unittest.main()
