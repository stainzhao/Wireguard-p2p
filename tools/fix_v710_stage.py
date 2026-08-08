#!/usr/bin/env python3
from pathlib import Path

p = Path(__file__).resolve().parent / "apply_v710_generic_roles.py"
text = p.read_text(encoding="utf-8")
text = text.replace(
'''    '    def test_server_and_relay_peers_are_rejected(self):\\n        for address in ("10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.8"):\\n            with self.assertRaises(ValueError):\\n                agent.validate_peer_ip(address)\\n',
''',
'''    '    def test_self_vps_and_relay_peers_are_rejected(self):\\n        for address in ("10.0.0.1", "10.0.0.5", "10.0.0.8"):\\n            with self.assertRaises(ValueError):\\n                agent.validate_peer_ip(address)\\n',
''')
anchor = 'name = "p2p/wireguard-p2p/tests/test_runtime.py"\ntext = read(name)\npattern = re.compile('
if anchor not in text:
    raise SystemExit("runtime patch anchor not found")
text = text.replace(
    anchor,
    'name = "p2p/wireguard-p2p/tests/test_runtime.py"\ntext = read(name)\ntext = replace_once(text, "import pathlib\\n", "import pathlib\\nimport tempfile\\n", "runtime tempfile import")\npattern = re.compile(',
    1,
)
p.write_text(text, encoding="utf-8")
