#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def write(path, text):
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit("{}: expected one match, got {}".format(label, count))
    return text.replace(old, new, 1)


# When a new Coordinator session supersedes an old control session while the
# authenticated direct path is still healthy, refresh both session identity
# fields. Otherwise the next refresh would reject the new session start.
path = "p2p/wireguard-p2p/linux/p2p_agent.py"
text = read(path)
text = replace_once(
    text,
    '''        state["session_id"] = session_id\n        state["ip"] = peer_ip\n        state["controller"] = controller\n''',
    '''        state["session_id"] = session_id\n        state["session_started_ns"] = session_started_ns\n        state["ip"] = peer_ip\n        state["controller"] = controller\n''',
    "refresh session start",
)
write(path, text)

# A v7.12 server has initiator capability inside the Python Agent. If an older
# experiment installed the ordinary Go Linux Client service on a server, stop
# it before starting the Agent so two controllers cannot race on wg0.
path = "p2p/wireguard-p2p/linux/install_server.sh"
text = read(path)
text = replace_once(
    text,
    '''systemctl daemon-reload\nsystemctl enable wireguard-p2p-agent.service wireguard-p2p-portmap.service\n''',
    '''systemctl daemon-reload\n# v7.12 server Agent already contains the initiator; never run the ordinary\n# Linux Client controller on the same WireGuard interface.\nsystemctl disable --now wireguard-p2p-client.service >/dev/null 2>&1 || true\nsystemctl enable wireguard-p2p-agent.service wireguard-p2p-portmap.service\n''',
    "server installer client conflict cleanup",
)
write(path, text)

path = "p2p/wireguard-p2p/manage/wireguard-p2p.py"
text = read(path)
text = replace_once(
    text,
    '''        portmap_enabled = systemctl("is-enabled", "--quiet", "wireguard-p2p-portmap.service", check=False).returncode == 0\n        try:\n''',
    '''        portmap_enabled = systemctl("is-enabled", "--quiet", "wireguard-p2p-portmap.service", check=False).returncode == 0\n        client_enabled = systemctl("is-enabled", "--quiet", "wireguard-p2p-client.service", check=False).returncode == 0\n        client_active = systemctl("is-active", "--quiet", "wireguard-p2p-client.service", check=False).returncode == 0\n        if client_active:\n            systemctl("stop", "wireguard-p2p-client.service", check=False)\n        try:\n''',
    "manager capture client service",
)
text = replace_once(
    text,
    '''                    if health.get("ok") and health.get("version") == target:\n                        print("Updated Linux server {} -> {}.".format(current, target))\n                        return\n''',
    '''                    if health.get("ok") and health.get("version") == target:\n                        # The dual-capability Agent owns server initiation now.\n                        # Keep any legacy ordinary Linux Client service disabled.\n                        systemctl("disable", "wireguard-p2p-client.service", check=False)\n                        print("Updated Linux server {} -> {}.".format(current, target))\n                        return\n''',
    "manager disable client after success",
)
text = replace_once(
    text,
    '''            if portmap_enabled:\n                systemctl("restart", "wireguard-p2p-portmap.service", check=False)\n            systemctl("restart", "wireguard-p2p-agent.service", check=False)\n            raise\n''',
    '''            if portmap_enabled:\n                systemctl("restart", "wireguard-p2p-portmap.service", check=False)\n            systemctl("restart", "wireguard-p2p-agent.service", check=False)\n            if client_enabled:\n                systemctl("enable", "wireguard-p2p-client.service", check=False)\n            if client_active:\n                systemctl("restart", "wireguard-p2p-client.service", check=False)\n            raise\n''',
    "manager rollback client state",
)
write(path, text)

# Tests for the migration conflict guard and session rollover.
path = "p2p/wireguard-p2p/tests/test_runtime.py"
text = read(path)
text = replace_once(
    text,
    '''        self.assertIn("systemctl restart wireguard-p2p-portmap.service", server_installer)\n        self.assertIn("systemctl restart peers-api.service", vps_installer)\n''',
    '''        self.assertIn("systemctl restart wireguard-p2p-portmap.service", server_installer)\n        self.assertIn("disable --now wireguard-p2p-client.service", server_installer)\n        manager_source = (ROOT / "manage" / "wireguard-p2p.py").read_text(encoding="utf-8")\n        self.assertIn('systemctl("disable", "wireguard-p2p-client.service"', manager_source)\n        self.assertIn("systemctl restart peers-api.service", vps_installer)\n''',
    "runtime client conflict guard",
)
write(path, text)

path = "p2p/wireguard-p2p/tests/test_peer_logic.py"
text = read(path)
marker = '''    def test_server_pair_has_single_deterministic_initiator(self):\n'''
new_test = '''    def test_new_control_session_refreshes_session_start_on_healthy_direct(self):\n        key = "SCTH2DOd6XhU0QZLFCgClEKWgZPNHr6QtmPpb6S05EM="\n        old_session = "11111111-1111-4111-8111-111111111111"\n        new_session = "22222222-2222-4222-8222-222222222222"\n        old_started = agent.time_ns() - 1000000000\n        new_started = agent.time_ns()\n        state = agent.new_peer_state("10.0.0.8", old_session, old_started)\n        state["mode"] = "direct"\n        agent.STATES = {key: state}\n        local = {\n            "endpoint": "203.0.113.8:51820",\n            "allowed_ips": ["10.0.0.8/32"],\n            "latest_handshake": int(__import__("time").time()),\n            "keepalive": 25,\n        }\n        from unittest import mock\n        with mock.patch.object(agent, "local_wg_peers", return_value={key: local}), \\\n             mock.patch.object(agent, "save_state"), \\\n             mock.patch.object(agent, "local_ipv4", return_value="192.168.0.5"), \\\n             mock.patch.object(agent, "listen_port", return_value=51820), \\\n             mock.patch.object(agent, "gather_candidates", return_value=[]), \\\n             mock.patch.object(agent, "current_reflexive6_candidate", return_value=None), \\\n             mock.patch.object(agent, "public_key", return_value="x"):\n            agent.handle_offer({\n                "peer_key": key,\n                "peer_ip": "10.0.0.8",\n                "session_id": new_session,\n                "session_started_ns": new_started,\n                "endpoint": "203.0.113.8:51820",\n                "endpoint_type": "WAN",\n                "candidates": [{\n                    "type": "observed4",\n                    "family": "udp4",\n                    "endpoint": "203.0.113.8:51820",\n                    "priority": 700,\n                    "verified": True,\n                }],\n            })\n        self.assertEqual(agent.STATES[key]["session_id"], new_session)\n        self.assertEqual(agent.STATES[key]["session_started_ns"], new_started)\n\n'''
if "test_new_control_session_refreshes_session_start_on_healthy_direct" not in text:
    text = replace_once(text, marker, new_test + marker, "session rollover regression")
write(path, text)

path = "README.md"
text = read(path)
needle = '''Agent 内置 Server↔Server initiator，不额外安装 Linux Client\n安装 systemd services\n'''
replacement = '''Agent 内置 Server↔Server initiator，不额外安装 Linux Client\n若检测到旧的 `wireguard-p2p-client.service`，会停用它以避免两个控制器竞争同一 wg0 Peer\n安装 systemd services\n'''
text = replace_once(text, needle, replacement, "README migration guard")
write(path, text)

print("v7.12 post-generation hardening applied")
