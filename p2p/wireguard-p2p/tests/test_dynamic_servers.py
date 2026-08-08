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


class GenericRoleTests(unittest.TestCase):
    def test_missing_registries_have_no_magic_nodes(self):
        old_server = api.SERVER_REGISTRY_FILE
        old_relay = api.RELAY_ONLY_REGISTRY_FILE
        try:
            api.SERVER_REGISTRY_FILE = "/definitely/missing/servers.conf"
            api.RELAY_ONLY_REGISTRY_FILE = "/definitely/missing/relay-only.conf"
            for value in ("10.0.0.2", "10.0.0.5", "10.0.0.8", "10.0.0.10"):
                self.assertEqual(api.peer_role(value), "client")
        finally:
            api.SERVER_REGISTRY_FILE = old_server
            api.RELAY_ONLY_REGISTRY_FILE = old_relay

    def test_any_eligible_node_can_be_server_or_relay_only(self):
        old_server = api.SERVER_REGISTRY_FILE
        old_relay = api.RELAY_ONLY_REGISTRY_FILE
        with tempfile.TemporaryDirectory() as tmp:
            server = pathlib.Path(tmp) / "servers.conf"
            relay = pathlib.Path(tmp) / "relay-only.conf"
            server.write_text("10.0.0.8\n10.0.0.10\n", encoding="utf-8")
            relay.write_text("10.0.0.20\n", encoding="utf-8")
            try:
                api.SERVER_REGISTRY_FILE = str(server)
                api.RELAY_ONLY_REGISTRY_FILE = str(relay)
                self.assertEqual(api.peer_role("10.0.0.8"), "server")
                self.assertEqual(api.peer_role("10.0.0.10"), "server")
                self.assertEqual(api.peer_role("10.0.0.20"), "relay_only")
                self.assertEqual(api.peer_role("10.0.0.2"), "client")
            finally:
                api.SERVER_REGISTRY_FILE = old_server
                api.RELAY_ONLY_REGISTRY_FILE = old_relay

    def test_bootstrap_key_is_only_for_current_server_role(self):
        old_file = api.SERVER_REGISTRY_FILE
        old_key = api.NOTIFY_KEY
        with tempfile.TemporaryDirectory() as tmp:
            registry = pathlib.Path(tmp) / "servers.conf"
            registry.write_text("10.0.0.8\n", encoding="utf-8")
            try:
                api.SERVER_REGISTRY_FILE = str(registry)
                api.NOTIFY_KEY = b"x" * 32
                self.assertEqual(api.bootstrap_server_key("10.0.0.8"), b"x" * 32 + b"\n")
                with self.assertRaises(PermissionError):
                    api.bootstrap_server_key("10.0.0.4")
            finally:
                api.SERVER_REGISTRY_FILE = old_file
                api.NOTIFY_KEY = old_key

    def test_dot8_is_not_reserved(self):
        self.assertEqual(manager.validate_role_ip("10.0.0.8"), "10.0.0.8")
        self.assertEqual(manager.validate_role_ip("10.0.0.10"), "10.0.0.10")
        for value in ("10.0.0.1", "10.0.0.0", "10.0.0.255", "192.168.1.10"):
            with self.assertRaises(RuntimeError):
                manager.validate_role_ip(value)

    def test_role_switch_is_mutually_exclusive(self):
        old_server = manager.SERVER_REGISTRY_FILE
        old_relay = manager.RELAY_ONLY_REGISTRY_FILE
        with tempfile.TemporaryDirectory() as tmp:
            try:
                manager.SERVER_REGISTRY_FILE = pathlib.Path(tmp) / "servers.conf"
                manager.RELAY_ONLY_REGISTRY_FILE = pathlib.Path(tmp) / "relay-only.conf"
                manager.set_node_role("10.0.0.8", "server")
                self.assertEqual(manager.explicit_roles(), {"10.0.0.8": "server"})
                manager.set_node_role("10.0.0.8", "relay_only")
                self.assertEqual(manager.explicit_roles(), {"10.0.0.8": "relay_only"})
                manager.set_node_role("10.0.0.8", "client")
                self.assertEqual(manager.explicit_roles(), {})
            finally:
                manager.SERVER_REGISTRY_FILE = old_server
                manager.RELAY_ONLY_REGISTRY_FILE = old_relay

    def test_go_client_discovers_server_role_dynamically(self):
        client_root = ROOT.parent / "wireguard-p2p-client"
        main = (client_root / "main.go").read_text(encoding="utf-8")
        probe = (client_root / "probe.go").read_text(encoding="utf-8")
        self.assertIn('Role            string      `json:"role"`', main)
        self.assertIn('peer.Role == "server"', probe)
        self.assertNotIn("serverKeys = map", main)


if __name__ == "__main__":
    unittest.main()
