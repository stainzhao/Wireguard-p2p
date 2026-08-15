import importlib.util
import os
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LINUX = ROOT / "linux"
os.environ.setdefault("P2P_LISTEN_ADDRESS", "10.0.0.5")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


candidates = load_module("candidates_ipv6", LINUX / "candidates.py")
agent = load_module("agent_ipv6", LINUX / "p2p_agent.py")
api = load_module("api_ipv6", ROOT / "vps" / "peers_api.py")


class IPv6PunchTests(unittest.TestCase):
    def test_current_release_versions_match(self):
        self.assertEqual(agent.VERSION, "7.13.0")
        self.assertEqual(api.VERSION, "7.13.0")

    def test_deprecated_ipv6_lifetime_is_rejected(self):
        self.assertTrue(candidates.ipv6_address_info_unusable({
            "flags": [], "preferred_life_time": 0,
        }))
        self.assertTrue(candidates.ipv6_address_info_unusable({
            "flags": ["deprecated"], "preferred_life_time": 120,
        }))
        self.assertFalse(candidates.ipv6_address_info_unusable({
            "flags": [], "preferred_life_time": "forever",
        }))

    def test_preferred_source_is_ranked_above_backup_host6(self):
        original_global = candidates.global_ipv6_addresses
        original_preferred = candidates.preferred_source_ipv6
        try:
            candidates.global_ipv6_addresses = lambda: [
                "2001:da8:216:191a::1",
                "2001:da8:216:191a::2",
            ]
            candidates.preferred_source_ipv6 = lambda: "2001:da8:216:191a::2"
            result = candidates.gather_candidates(51820)
            host6 = [item for item in result if item["type"] == "host6"]
            self.assertEqual(host6[0]["endpoint"], "[2001:da8:216:191a::2]:51820")
            self.assertEqual(host6[0]["priority"], candidates.PREFERRED_HOST6_PRIORITY)
            self.assertEqual(host6[1]["priority"], candidates.PRIORITY["host6"])
        finally:
            candidates.global_ipv6_addresses = original_global
            candidates.preferred_source_ipv6 = original_preferred

    def test_preferred_native_host6_gets_overlap_window(self):
        original = agent.global_ipv6_addresses
        try:
            agent.global_ipv6_addresses = lambda: ["2001:da8::1"]
            self.assertEqual(
                agent.candidate_probe_window({"type": "host6", "priority": 910}),
                agent.SIMULTANEOUS_IPV6_WINDOW,
            )
            self.assertEqual(
                agent.candidate_probe_window({"type": "host6", "priority": 900}),
                agent.CANDIDATE_PROBE_WINDOW,
            )
        finally:
            agent.global_ipv6_addresses = original

    def test_confirmation_rekey_only_for_nat66_server_to_host6(self):
        original = agent.global_ipv6_addresses
        try:
            agent.global_ipv6_addresses = lambda: []
            self.assertTrue(agent.should_confirmation_rekey({"type": "host6"}))
            self.assertFalse(agent.should_confirmation_rekey({"type": "observed4"}))
            agent.global_ipv6_addresses = lambda: ["2001:4860::1"]
            self.assertFalse(agent.should_confirmation_rekey({"type": "host6"}))
        finally:
            agent.global_ipv6_addresses = original

    def test_confirmation_rekey_window_is_bounded(self):
        self.assertEqual(agent.CONFIRMATION_REKEY_DELAY, 3.0)
        self.assertEqual(agent.CONFIRMATION_REKEY_WINDOW, 8.0)

    def test_retry_schedule_is_fast_then_quiet(self):
        self.assertEqual(agent.RETRY_DELAYS, (3, 10))
        self.assertEqual(agent.retry_delay(1), 3)
        self.assertEqual(agent.retry_delay(2), 10)
        self.assertEqual(agent.retry_delay(3), agent.FAILURE_COOLDOWN)
        self.assertEqual(agent.FAILURE_COOLDOWN, 1800)

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

    def test_vps_forces_reflexive6_unverified(self):
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

    def test_nat66_host6_probe_gets_overlap_window(self):
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
