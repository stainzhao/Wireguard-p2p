#!/usr/bin/env python3
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "p2p/wireguard-p2p/tests/test_runtime.py"
text = path.read_text(encoding="utf-8")
text = text.replace("self.assertEqual(len(payloads), len(api.SERVER_IPS))", "self.assertEqual(len(payloads), len(api.server_ips()))")
text = text.replace('self.assertIn("10.0.0.2|10.0.0.5", server_installer)', 'self.assertIn("10.0.0.*", server_installer)\n        self.assertIn("wireguard-p2p server add", server_installer)')
path.write_text(text, encoding="utf-8")
