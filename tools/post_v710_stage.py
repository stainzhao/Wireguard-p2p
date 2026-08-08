#!/usr/bin/env python3
from pathlib import Path

p = Path(__file__).resolve().parents[1] / "p2p/wireguard-p2p/tests/test_peer_logic.py"
text = p.read_text(encoding="utf-8")
old = '''    def test_disconnect_clears_client_and_server_candidates(self):
        client = {"key": "client-key", "ip": "10.0.0.4"}
        with api.STATE_LOCK:
            api.SESSIONS[client["ip"]] = dict(client, last_seen=1)
            api.LAN_CANDIDATES[client["ip"]] = {"seen": 1}
            api.LAN_CANDIDATES["10.0.0.2"] = {"seen": 1}
        original = api.push_remove
        api.push_remove = lambda _client: None
        try:
            api.disconnect_client(client)
        finally:
            api.push_remove = original
        self.assertEqual(api.SESSIONS, {})
        self.assertNotIn(client["ip"], api.LAN_CANDIDATES)
        self.assertNotIn("10.0.0.2", api.LAN_CANDIDATES)
'''
new = '''    def test_disconnect_clears_client_and_explicit_server_candidates(self):
        client = {"key": "client-key", "ip": "10.0.0.4"}
        with api.STATE_LOCK:
            api.SESSIONS[client["ip"]] = dict(client, last_seen=1)
            api.LAN_CANDIDATES[client["ip"]] = {"seen": 1}
            api.LAN_CANDIDATES["10.0.0.2"] = {"seen": 1}
        original_push = api.push_remove
        original_servers = api.server_ips
        api.push_remove = lambda _client: None
        api.server_ips = lambda: {"10.0.0.2"}
        try:
            api.disconnect_client(client)
        finally:
            api.push_remove = original_push
            api.server_ips = original_servers
        self.assertEqual(api.SESSIONS, {})
        self.assertNotIn(client["ip"], api.LAN_CANDIDATES)
        self.assertNotIn("10.0.0.2", api.LAN_CANDIDATES)
'''
if old not in text:
    raise SystemExit("disconnect test anchor not found")
p.write_text(text.replace(old, new, 1), encoding="utf-8")
