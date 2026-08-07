import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
LINUX = ROOT / "linux"


class QuietRuntimeTests(unittest.TestCase):
    def test_systemd_services_discard_routine_stdout_and_keep_errors(self):
        for name in (
            "wireguard-p2p-agent.service",
            "wireguard-p2p-portmap.service",
            "wireguard-p2p-sync.service",
        ):
            text = (LINUX / name).read_text(encoding="utf-8")
            self.assertIn("RuntimeDirectory=wireguard-p2p", text)
            self.assertIn("RuntimeDirectoryMode=0700", text)
            self.assertIn("StandardOutput=null", text)
            self.assertIn("StandardError=journal", text)
            self.assertIn("LogRateLimitIntervalSec=5min", text)
            self.assertIn("LogRateLimitBurst=20", text)
            self.assertNotIn("StateDirectory=wireguard-p2p", text)

    def test_all_runtime_state_defaults_are_ram_backed(self):
        agent = (LINUX / "p2p_agent.py").read_text(encoding="utf-8")
        portmap = (LINUX / "portmap_daemon.py").read_text(encoding="utf-8")
        legacy_sync = (LINUX / "p2p_sync.py").read_text(encoding="utf-8")

        self.assertIn('/run/wireguard-p2p/state.json', agent)
        self.assertIn('/run/wireguard-p2p/mapped4.json', portmap)
        self.assertIn('/run/wireguard-p2p/legacy-sync-state.json', legacy_sync)
        self.assertNotIn('/var/lib/wireguard-p2p/state.json', legacy_sync)

    def test_tmpfs_mapping_cache_does_not_request_durable_fsync(self):
        portmap = (LINUX / "portmap_daemon.py").read_text(encoding="utf-8")
        self.assertNotIn("os.fsync", portmap)

    def test_legacy_sync_errors_use_stderr(self):
        legacy_sync = (LINUX / "p2p_sync.py").read_text(encoding="utf-8")
        self.assertIn("def log_error(message):", legacy_sync)
        self.assertIn('log_error("sync failed: {}".format(message))', legacy_sync)


if __name__ == "__main__":
    unittest.main()
