#!/usr/bin/env python3
from pathlib import Path

p = Path(__file__).resolve().parents[1] / "p2p/wireguard-p2p/tests/test_protocol.py"
text = p.read_text(encoding="utf-8")
old = 'self.assertEqual(candidate["priority"], 600)'
if old not in text:
    raise SystemExit("observed4 priority assertion not found")
text = text.replace(old, 'self.assertEqual(candidate["priority"], 700)', 1)
old = 'self.assertEqual(types, ["lan4", "host6", "observed4"])'
if old not in text:
    raise SystemExit("candidate type assertion not found")
text = text.replace(
    old,
    'self.assertEqual(types, ["lan4", "host6", "observed4", "predicted4", "predicted4", "predicted4", "predicted4"])',
    1,
)
p.write_text(text, encoding="utf-8")
