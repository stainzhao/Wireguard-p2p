import importlib.util
import os
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
os.environ.setdefault("P2P_LISTEN_ADDRESS", "10.0.0.5")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


candidates = load_module("candidates_v73", ROOT / "linux" / "candidates.py")
agent = load_module("agent_v73", ROOT / "linux" / "p2p_agent.py")
api = load_module("api_v73", ROOT / "vps" / "peers_api.py")


class IPv6SimultaneousPunchTests(unittest.TestCase):
    def test_versions_are_v73(self):
        self.assertEqual(agent.VERSION, "7.4.0")
        self.assertEqual(api.VERSION, "7.4.0")

    def test_reflexive6_candidate_uses_wireguard_port(self):
        candidate = candidates.reflexive6_candidate(
            "2001:da8:216:191a:5ad9:d5ff:fe0d:dcf1", 33967
        )
        self.assertEqual(candidate["type"], "reflexive6")
        self.assertEqual(candidate["family"], "udp6")
        self.assertEqual(
            candidate["endpoint"],
            "[2001:da8:216:191a:5ad9:d5ff:fe0d:dcf1]:33967",
        )
        self.assertEqual(candidate["priority"], 825)
        self.assertFalse(candidate["verified"])

    def test_reflexive6_rejects_special_use_ipv6(self):
        self.assertIsNone(candidates.reflexive6_candidate("2001:3::1", 33967))

    def test_vps_accepts_unverified_reflexive6(self):
        result = api.validate_candidates([
            {
                "type": "reflexive6",
                "family": "udp6",
                "endpoint": "[2001:da8:216:191a::1]:33967",
                "priority": 825,
                "verified": True,
            }
        ])
        self.assertEqual(result[0]["type"], "reflexive6")
        self.assertFalse(result[0]["verified"])

    def test_nat66_host6_probe_gets_long_overlap_window(self):
        original = agent.global_ipv6_addresses
        try:
            agent.global_ipv6_addresses = lambda: []
            self.assertEqual(
                agent.candidate_probe_window({"type": "host6"}),
                agent.SIMULTANEOUS_IPV6_WINDOW,
            )
            agent.global_ipv6_addresses = lambda: ["2001:da8::1"]
            self.assertEqual(
                agent.candidate_probe_window({"type": "host6"}),
                agent.CANDIDATE_PROBE_WINDOW,
            )
        finally:
            agent.global_ipv6_addresses = original


if __name__ == "__main__":
    unittest.main()
