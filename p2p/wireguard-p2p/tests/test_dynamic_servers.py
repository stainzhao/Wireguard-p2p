import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


api = load_module("dynamic_peers_api", ROOT / "vps" / "peers_api.py")
manager = load_module("dynamic_manager", ROOT / "manage" / "wireguard-p2p.py")


class DynamicServerTests(unittest.TestCase):
    def test_missing_registry_keeps_legacy_servers(self):
        old = api.SERVER_REGISTRY_FILE
        try:
            api.SERVER_REGISTRY_FILE = "/definitely/missing/p2p-servers.conf"
            self.assertEqual(api.peer_role("10.0.0.2"), "server")
            self.assertEqual(api.peer_role("10.0.0.5"), "server")
        finally:
            api.SERVER_REGISTRY_FILE = old

    def test_registry_can_authorize_dot10_without_code_change(self):
        old = api.SERVER_REGISTRY_FILE
        with tempfile.TemporaryDirectory() as tmp:
            registry = pathlib.Path(tmp) / "servers.conf"
            registry.write_text("10.0.0.10\n", encoding="utf-8")
            try:
                api.SERVER_REGISTRY_FILE = str(registry)
                self.assertEqual(api.peer_role("10.0.0.10"), "server")
                self.assertEqual(api.peer_role("10.0.0.2"), "client")
                self.assertEqual(api.peer_role("10.0.0.8"), "relay_only")
            finally:
                api.SERVER_REGISTRY_FILE = old

    def test_bootstrap_key_is_only_for_authorized_servers(self):
        old_file = api.SERVER_REGISTRY_FILE
        old_key = api.NOTIFY_KEY
        with tempfile.TemporaryDirectory() as tmp:
            registry = pathlib.Path(tmp) / "servers.conf"
            registry.write_text("10.0.0.10\n", encoding="utf-8")
            try:
                api.SERVER_REGISTRY_FILE = str(registry)
                api.NOTIFY_KEY = b"x" * 32
                self.assertEqual(api.bootstrap_server_key("10.0.0.10"), b"x" * 32 + b"\n")
                with self.assertRaises(PermissionError):
                    api.bootstrap_server_key("10.0.0.4")
            finally:
                api.SERVER_REGISTRY_FILE = old_file
                api.NOTIFY_KEY = old_key

    def test_manager_rejects_reserved_addresses(self):
        self.assertEqual(manager.validate_server_ip("10.0.0.10"), "10.0.0.10")
        for value in ("10.0.0.1", "10.0.0.8", "10.0.0.0", "10.0.0.255", "192.168.1.10"):
            with self.assertRaises(RuntimeError):
                manager.validate_server_ip(value)


if __name__ == "__main__":
    unittest.main()
