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
        self.assertEqual(agent.VERSION, "7.2.1")

    def test_retry_schedule_is_fast_then_quiet(self):
        self.assertEqual(agent.RETRY_DELAYS, (3, 10))
        self.assertEqual(agent.retry_delay(1), 3)
        self.assertEqual(agent.retry_delay(2), 10)
        self.assertEqual(agent.retry_delay(3), agent.FAILURE_COOLDOWN)
        self.assertEqual(agent.FAILURE_COOLDOWN, 1800)


if __name__ == "__main__":
    unittest.main()
