#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

for p in list(ROOT.rglob("*.py")) + list(ROOT.rglob("*.go")) + list(ROOT.rglob("*.md")):
    if ".git" in p.parts or p == Path(__file__):
        continue
    text = p.read_text(encoding="utf-8")
    if "7.7.0" in text:
        p.write_text(text.replace("7.7.0", "7.7.1"), encoding="utf-8")

# Existing services must be restarted after first-time managed-install migration.
client = ROOT / "p2p/wireguard-p2p-client/deploy/linux/install.sh"
text = client.read_text(encoding="utf-8")
old = "systemctl daemon-reload\nsystemctl enable --now wireguard-p2p-client.service\nsleep 1\n"
new = "systemctl daemon-reload\nsystemctl enable wireguard-p2p-client.service\nsystemctl restart wireguard-p2p-client.service\nsleep 1\n"
if old not in text:
    raise SystemExit("client installer pattern missing")
client.write_text(text.replace(old, new, 1), encoding="utf-8")

server = ROOT / "p2p/wireguard-p2p/linux/install_server.sh"
text = server.read_text(encoding="utf-8")
old = "systemctl daemon-reload\nsystemctl enable --now wireguard-p2p-agent.service\nsystemctl enable --now wireguard-p2p-portmap.service\n"
new = "systemctl daemon-reload\nsystemctl enable wireguard-p2p-agent.service wireguard-p2p-portmap.service\nsystemctl restart wireguard-p2p-portmap.service\nsystemctl restart wireguard-p2p-agent.service\n"
if old not in text:
    raise SystemExit("server installer pattern missing")
server.write_text(text.replace(old, new, 1), encoding="utf-8")

vps = ROOT / "p2p/wireguard-p2p/vps/install_vps.sh"
text = vps.read_text(encoding="utf-8")
old = "systemctl daemon-reload\nsystemctl enable --now peers-api.service\n"
new = "systemctl daemon-reload\nsystemctl enable peers-api.service\nsystemctl restart peers-api.service\n"
if old not in text:
    raise SystemExit("VPS installer pattern missing")
vps.write_text(text.replace(old, new, 1), encoding="utf-8")

# Regression guard: all three managed installers must restart overwritten services.
test = ROOT / "p2p/wireguard-p2p/tests/test_runtime.py"
text = test.read_text(encoding="utf-8")
marker = '\n\nif __name__ == "__main__":\n'
extra = r'''

    def test_managed_installers_restart_existing_services(self):
        client_installer = (ROOT.parent / "wireguard-p2p-client" / "deploy" / "linux" / "install.sh").read_text(encoding="utf-8")
        server_installer = (LINUX / "install_server.sh").read_text(encoding="utf-8")
        vps_installer = (ROOT / "vps" / "install_vps.sh").read_text(encoding="utf-8")
        self.assertIn("systemctl restart wireguard-p2p-client.service", client_installer)
        self.assertIn("systemctl restart wireguard-p2p-agent.service", server_installer)
        self.assertIn("systemctl restart wireguard-p2p-portmap.service", server_installer)
        self.assertIn("systemctl restart peers-api.service", vps_installer)
'''
if marker not in text:
    raise SystemExit("test insertion marker missing")
test.write_text(text.replace(marker, extra + marker, 1), encoding="utf-8")

print("v7.7.1 bootstrap restart fix applied")
