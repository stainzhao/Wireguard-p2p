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


agent = load_module("p2p_agent_fast_punch", LINUX / "p2p_agent.py")


class FastPunchTests(unittest.TestCase):
    def test_version_marks_fast_ipv6_release(self):
        self.assertEqual(agent.VERSION, "7.3.0")

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


if __name__ == "__main__":
    unittest.main()
