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


agent = load_module("p2p_agent_performance", LINUX / "p2p_agent.py")


class PerformancePolicyTests(unittest.TestCase):
    def test_release_version(self):
        self.assertEqual(agent.VERSION, "7.13.0")

    def test_server_direct_retry_curve(self):
        expected = {
            1: 3,
            2: 10,
            3: 30,
            4: 60,
            5: 300,
            20: 300,
        }
        for failures, delay in expected.items():
            with self.subTest(failures=failures):
                self.assertEqual(agent.retry_delay(failures), delay)

    def test_server_recovery_control_intervals(self):
        self.assertLessEqual(agent.INITIATOR_SYNC_INTERVAL, 10)
        self.assertLessEqual(agent.ACTIVE_MONITOR_INTERVAL, 5)
        self.assertLessEqual(agent.DIRECT_MONITOR_INTERVAL, 20)
        self.assertLessEqual(agent.FAILURE_COOLDOWN, 300)

    def test_data_plane_tuning_is_unchanged(self):
        self.assertEqual(agent.KEEPALIVE, 25)
        self.assertEqual(agent.PROBE_KEEPALIVE, 1)
        self.assertEqual(agent.DIRECT_MAX_AGE, 180)
        self.assertEqual(agent.SIMULTANEOUS_IPV6_WINDOW, 8.0)
        self.assertEqual(agent.SIMULTANEOUS_IPV4_WINDOW, 8.0)


if __name__ == "__main__":
    unittest.main()
