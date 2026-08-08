#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def patch_runtime(path):
    file = ROOT / path
    text = file.read_text(encoding="utf-8")
    if "time.time_ns()" not in text:
        raise RuntimeError("no time.time_ns() found in " + path)
    text = text.replace("time.time_ns()", "time_ns()")
    anchor = '\nVERSION = "7.10.1"\n'
    helper = '''\n\ndef time_ns():\n    native = getattr(time, "time_ns", None)\n    if native is not None:\n        return native()\n    return int(time.time() * 1000000000)\n'''
    if anchor not in text:
        raise RuntimeError("version anchor missing in " + path)
    text = text.replace(anchor, helper + anchor, 1)
    file.write_text(text, encoding="utf-8")


patch_runtime("p2p/wireguard-p2p/linux/p2p_agent.py")
patch_runtime("p2p/wireguard-p2p/vps/peers_api.py")

runtime_test = ROOT / "p2p/wireguard-p2p/tests/test_runtime.py"
text = runtime_test.read_text(encoding="utf-8")
text = text.replace("time.time_ns()", "agent.time_ns()")
anchor = '''    def test_python36_manager_compatibility(self):\n        source = (ROOT / "manage" / "wireguard-p2p.py").read_text(encoding="utf-8")\n        self.assertNotIn("missing_ok=True", source)\n        self.assertNotIn("text=True", source)\n        self.assertIn("universal_newlines=True", source)\n\n'''
replacement = anchor + '''    def test_python36_time_ns_fallback(self):\n        agent_source = (LINUX / "p2p_agent.py").read_text(encoding="utf-8")\n        api_source = (ROOT / "vps" / "peers_api.py").read_text(encoding="utf-8")\n        self.assertNotIn("time.time_ns()", agent_source)\n        self.assertNotIn("time.time_ns()", api_source)\n        self.assertIsInstance(agent.time_ns(), int)\n        self.assertIsInstance(api.time_ns(), int)\n\n'''
if anchor not in text:
    raise RuntimeError("runtime compatibility test anchor missing")
text = text.replace(anchor, replacement, 1)
runtime_test.write_text(text, encoding="utf-8")

security_test = ROOT / "p2p/wireguard-p2p/tests/test_security.py"
text = security_test.read_text(encoding="utf-8")
text = text.replace("time.time_ns()", "api.time_ns()")
security_test.write_text(text, encoding="utf-8")

print("Replaced Python 3.7-only time.time_ns() with a 3.6-compatible fallback")
