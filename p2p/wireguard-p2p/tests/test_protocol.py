import importlib.util
import os
import pathlib
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


api = load_module("peers_api_v7", ROOT / "vps" / "peers_api.py")
os.environ.setdefault("P2P_LISTEN_ADDRESS", "10.0.0.5")
agent = load_module("p2p_agent_v7", ROOT / "linux" / "p2p_agent.py")
candidates = load_module("candidates_v7", ROOT / "linux" / "candidates.py")


class CandidateProtocolTests(unittest.TestCase):
    def setUp(self):
        with api.STATE_LOCK:
            api.LAN_CANDIDATES.clear()
            api.NODE_CANDIDATES.clear()
            api.SESSIONS.clear()

    def test_ipv6_endpoint_requires_brackets(self):
        endpoint, address, port = api.parse_endpoint(
            "[2001:4860:4860::8888]:51820"
        )
        self.assertEqual(endpoint, "[2001:4860:4860::8888]:51820")
        self.assertEqual(address.version, 6)
        self.assertEqual(port, 51820)
        with self.assertRaises(ValueError):
            api.parse_endpoint("2001:4860:4860::8888:51820")

    def test_clients_cannot_claim_observed_candidate(self):
        with self.assertRaises(ValueError):
            api.validate_candidates([
                {
                    "type": "observed4",
                    "family": "udp4",
                    "endpoint": "8.8.8.8:51820",
                    "priority": 600,
                    "verified": True,
                }
            ])

    def test_vps_observed_candidate_is_verified(self):
        candidate = api.observed_candidate("8.8.8.8:51820")
        self.assertEqual(candidate["type"], "observed4")
        self.assertTrue(candidate["verified"])
        self.assertEqual(candidate["priority"], 600)

    def test_peer_payload_merges_legacy_and_v7_candidates(self):
        now = time.time()
        peer = {
            "key": "client-key",
            "ip": "10.0.0.4",
            "role": "client",
            "endpoint": "8.8.8.8:40000",
            "latest_handshake": int(now),
        }
        with api.STATE_LOCK:
            api.LAN_CANDIDATES["10.0.0.4"] = {
                "lan_ip": "192.168.1.13",
                "listen_port": 58442,
                "seen": now,
            }
            api.NODE_CANDIDATES["10.0.0.4"] = {
                "candidates": [{
                    "type": "host6",
                    "family": "udp6",
                    "endpoint": "[2001:4860:4860::8888]:58442",
                    "priority": 900,
                    "verified": False,
                }],
                "seen": now,
            }
        result = api.peer_payload([dict(peer)])[0]
        types = [item["type"] for item in result["candidates"]]
        self.assertEqual(types, ["lan4", "host6", "observed4"])
        self.assertEqual(result["lan_endpoint"], "192.168.1.13:58442")

    def test_linux_candidate_helpers(self):
        self.assertEqual(
            candidates.format_endpoint("2001:4860:4860::8888", 51820),
            "[2001:4860:4860::8888]:51820",
        )
        self.assertTrue(candidates.usable_global_ipv6("2001:4860:4860::8888"))
        self.assertTrue(candidates.usable_global_ipv6("2001:da8:216:191a::1"))
        self.assertFalse(candidates.usable_global_ipv6("2001:3::1"))
        self.assertFalse(candidates.usable_global_ipv6("2001:db8::1"))
        self.assertFalse(candidates.usable_global_ipv6("fe80::1"))
        self.assertFalse(candidates.usable_global_ipv6("fd00::1"))

    def test_special_use_ipv6_is_not_selected_as_host6(self):
        advertised = [{
            "type": "host6",
            "family": "udp6",
            "endpoint": "[2001:3::1234]:33967",
            "priority": 900,
        }]
        result = candidates.select_probe_candidates(
            advertised, "8.8.8.8:40000", "WAN"
        )
        self.assertEqual([item["type"] for item in result], ["observed4"])

    def test_observed6_endpoint_classification(self):
        self.assertEqual(
            candidates.observed_type_for_endpoint(
                "[2001:da8:216:191a:5ad9:d5ff:fe0d:dcf1]:48132"
            ),
            "observed6",
        )
        self.assertEqual(
            candidates.observed_type_for_endpoint("[2001:3::1234]:48132"),
            "",
        )

    def test_agent_accepts_v7_host6_candidate(self):
        result = agent.validate_candidates([
            {
                "type": "host6",
                "family": "udp6",
                "endpoint": "[2001:4860:4860::8888]:51820",
                "priority": 900,
            }
        ])
        self.assertEqual(result[0]["type"], "host6")
        self.assertEqual(result[0]["family"], "udp6")

    def test_probe_selection_filters_remote_lan_on_wan(self):
        advertised = [
            {
                "type": "lan4",
                "family": "udp4",
                "endpoint": "192.168.0.10:51820",
                "priority": 1000,
            },
            {
                "type": "host6",
                "family": "udp6",
                "endpoint": "[2001:4860:4860::8888]:51820",
                "priority": 900,
            },
        ]
        result = candidates.select_probe_candidates(
            advertised, "8.8.8.8:40000", "WAN"
        )
        types = [item["type"] for item in result]
        self.assertNotIn("lan4", types)
        self.assertEqual(types, ["host6", "observed4"])

    def test_probe_selection_can_skip_ipv6(self):
        advertised = [{
            "type": "host6",
            "family": "udp6",
            "endpoint": "[2001:4860:4860::8888]:51820",
            "priority": 900,
        }]
        result = candidates.select_probe_candidates(
            advertised,
            "8.8.8.8:40000",
            "WAN",
            allow_ipv6=False,
        )
        self.assertEqual([item["type"] for item in result], ["observed4"])

    def test_candidate_signature_changes_with_network_path(self):
        first = candidates.candidate_signature([
            {"type": "host6", "endpoint": "[2001:4860:4860::1]:51820"},
            {"type": "observed4", "endpoint": "8.8.8.8:40000"},
        ])
        second = candidates.candidate_signature([
            {"type": "host6", "endpoint": "[2001:4860:4860::2]:51820"},
            {"type": "observed4", "endpoint": "8.8.8.8:40000"},
        ])
        self.assertNotEqual(first, second)

    def test_beta_probe_window_is_short(self):
        self.assertEqual(agent.CANDIDATE_PROBE_WINDOW, 2.0)
        self.assertEqual(agent.PROBE_KEEPALIVE, 1)


if __name__ == "__main__":
    unittest.main()
