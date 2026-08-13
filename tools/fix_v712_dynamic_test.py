#!/usr/bin/env python3
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "p2p/wireguard-p2p/tests/test_dynamic_servers.py"
text = path.read_text(encoding="utf-8")
old = '''        self.assertIn('peer.Role == "server"', probe)\n        self.assertNotIn("serverKeys = map", main)\n'''
new = '''        self.assertIn('peer.Role != "server"', probe)\n        self.assertIn('serverInitiatorOwnsPair', probe)\n        self.assertNotIn("serverKeys = map", main)\n'''
if old not in text:
    raise SystemExit("dynamic server assertion anchor not found")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
