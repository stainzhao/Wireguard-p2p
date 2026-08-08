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


candidates = load_module("candidates_ipv4", ROOT / "linux" / "candidates.py")
agent = load_module("agent_ipv4", ROOT / "linux" / "p2p_agent.py")
api = load_module("api_ipv4", ROOT / "vps" / "peers_api.py")


class IPv4PunchTests(unittest.TestCase):
    def test_release_versions(self):
        self.assertEqual(agent.VERSION, "7.7.1")
        self.assertEqual(api.VERSION, "7.7.1")

    def test_priorities(self):
        self.assertEqual(candidates.PRIORITY["mapped4"], 800)
        self.assertEqual(candidates.PRIORITY["observed4"], 700)
        self.assertEqual(candidates.PRIORITY["predicted4"], 500)

    def test_observed4_uses_simultaneous_window(self):
        self.assertEqual(
            agent.candidate_probe_window({"type": "observed4"}),
            agent.SIMULTANEOUS_IPV4_WINDOW,
        )
        self.assertEqual(agent.SIMULTANEOUS_IPV4_WINDOW, 8.0)
        self.assertEqual(
            agent.candidate_probe_window({"type": "predicted4"}),
            agent.PREDICTED_IPV4_WINDOW,
        )

    def test_predictions_are_bounded_to_verified_ip(self):
        values = api.predicted_candidates("211.71.91.89:38621")
        self.assertEqual(len(values), 4)
        self.assertEqual(
            {item["endpoint"] for item in values},
            {
                "211.71.91.89:38619",
                "211.71.91.89:38620",
                "211.71.91.89:38622",
                "211.71.91.89:38623",
            },
        )
        self.assertTrue(all(item["priority"] == 500 for item in values))
        self.assertTrue(all(not item["verified"] for item in values))

    def test_private_or_invalid_prediction_source_is_rejected(self):
        self.assertEqual(api.predicted_candidates("192.168.1.2:51820"), [])
        self.assertEqual(api.predicted_candidates("bad"), [])

    def test_nodes_cannot_self_advertise_predicted4(self):
        with self.assertRaises(ValueError):
            api.validate_candidates([
                {
                    "type": "predicted4",
                    "family": "udp4",
                    "endpoint": "211.71.91.89:38622",
                    "priority": 500,
                }
            ], allow_observed=False)

    def test_internal_predicted4_validation_is_allowed(self):
        result = api.validate_candidates([
            {
                "type": "predicted4",
                "family": "udp4",
                "endpoint": "211.71.91.89:38622",
                "priority": 500,
            }
        ], allow_observed=True)
        self.assertEqual(result[0]["type"], "predicted4")


if __name__ == "__main__":
    unittest.main()
