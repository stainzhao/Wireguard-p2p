#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
OLD = "7.9.0"
NEW = "7.10.0"


def path(name):
    return ROOT / name


def read(name):
    return path(name).read_text(encoding="utf-8")


def write(name, text):
    path(name).write_text(text, encoding="utf-8")


def replace_once(text, old, new, label):
    if old not in text:
        raise RuntimeError(f"missing anchor: {label}")
    return text.replace(old, new, 1)


# Version bump for all current release-bearing sources/tests/docs.
for name in [
    "README.md",
    "p2p/wireguard-p2p-client/main.go",
    "p2p/wireguard-p2p-client/cross_platform_test.go",
    "p2p/wireguard-p2p/linux/p2p_agent.py",
    "p2p/wireguard-p2p/manage/wireguard-p2p.py",
    "p2p/wireguard-p2p/vps/peers_api.py",
    "p2p/wireguard-p2p/docs/operations.md",
    "p2p/wireguard-p2p/tests/test_ipv4_punch.py",
    "p2p/wireguard-p2p/tests/test_ipv6_punch.py",
    "p2p/wireguard-p2p/tests/test_runtime.py",
]:
    text = read(name)
    if OLD not in text:
        raise RuntimeError(f"{name}: expected {OLD}")
    write(name, text.replace(OLD, NEW))

# ---------------------------------------------------------------------------
# VPS coordinator: no node-specific defaults. Explicit role registries only.
# ---------------------------------------------------------------------------
name = "p2p/wireguard-p2p/vps/peers_api.py"
text = read(name)
text = replace_once(
    text,
    'DEFAULT_SERVER_IPS = {"10.0.0.2", "10.0.0.5"}\nSERVER_REGISTRY_FILE = os.environ.get("P2P_SERVER_REGISTRY_FILE", "/etc/wireguard-p2p/servers.conf")\nRELAY_ONLY_IPS = {"10.0.0.8"}\nOVERLAY_NETWORK = ipaddress.ip_network("10.0.0.0/24")\n',
    'SERVER_REGISTRY_FILE = os.environ.get("P2P_SERVER_REGISTRY_FILE", "/etc/wireguard-p2p/servers.conf")\nRELAY_ONLY_REGISTRY_FILE = os.environ.get("P2P_RELAY_ONLY_REGISTRY_FILE", "/etc/wireguard-p2p/relay-only.conf")\nOVERLAY_NETWORK = ipaddress.ip_network("10.0.0.0/24")\n',
    "coordinator role constants",
)
start = text.index("def server_ips():\n")
end = text.index("\ndef new_push_status():", start)
role_helpers = '''def load_role_registry(filename):
    try:
        with open(filename, "r", encoding="utf-8") as handle:
            raw = [line.split("#", 1)[0].strip() for line in handle]
    except OSError:
        return set()
    result = set()
    for value in raw:
        if not value:
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        normalized = str(address)
        if (
            address.version == 4
            and address in OVERLAY_NETWORK
            and address not in (OVERLAY_NETWORK.network_address, OVERLAY_NETWORK.broadcast_address)
            and normalized != LISTEN_ADDRESS
        ):
            result.add(normalized)
    return result


def server_ips():
    return load_role_registry(SERVER_REGISTRY_FILE)


def relay_only_ips():
    return load_role_registry(RELAY_ONLY_REGISTRY_FILE)
'''
text = text[:start] + role_helpers + text[end:]
text = replace_once(
    text,
    'def peer_role(overlay_ip):\n    if overlay_ip in RELAY_ONLY_IPS:\n        return "relay_only"\n    if overlay_ip in server_ips():\n        return "server"\n    return "client"\n',
    'def peer_role(overlay_ip):\n    if overlay_ip in relay_only_ips():\n        return "relay_only"\n    if overlay_ip in server_ips():\n        return "server"\n    return "client"\n',
    "coordinator peer role",
)
write(name, text)

# ---------------------------------------------------------------------------
# Linux Server Agent: .8 is no longer special. Coordinator role decides peers.
# ---------------------------------------------------------------------------
name = "p2p/wireguard-p2p/linux/p2p_agent.py"
text = read(name)
text = replace_once(
    text,
    '    if str(address) in (VPS_ADDRESS, LISTEN_ADDRESS, "10.0.0.8"):\n        raise ValueError("peer is not P2P eligible")\n',
    '    if str(address) in (VPS_ADDRESS, LISTEN_ADDRESS):\n        raise ValueError("peer is not P2P eligible")\n',
    "agent fixed relay-only address",
)
write(name, text)

# ---------------------------------------------------------------------------
# VPS manager: generic explicit server/relay_only roles. Client is implicit.
# ---------------------------------------------------------------------------
name = "p2p/wireguard-p2p/manage/wireguard-p2p.py"
text = read(name)
text = replace_once(
    text,
    'SERVER_REGISTRY_FILE = Path(os.environ.get("P2P_SERVER_REGISTRY_FILE", "/etc/wireguard-p2p/servers.conf"))\nDEFAULT_SERVER_IPS = {"10.0.0.2", "10.0.0.5"}\nRESERVED_SERVER_IPS = {"10.0.0.1", "10.0.0.8"}\nOVERLAY_NETWORK = ipaddress.ip_network("10.0.0.0/24")\n',
    'SERVER_REGISTRY_FILE = Path(os.environ.get("P2P_SERVER_REGISTRY_FILE", "/etc/wireguard-p2p/servers.conf"))\nRELAY_ONLY_REGISTRY_FILE = Path(os.environ.get("P2P_RELAY_ONLY_REGISTRY_FILE", "/etc/wireguard-p2p/relay-only.conf"))\nCOORDINATOR_IP = "10.0.0.1"\nOVERLAY_NETWORK = ipaddress.ip_network("10.0.0.0/24")\n',
    "manager role constants",
)
start = text.index("def validate_server_ip(value):\n")
end = text.index("\ndef show_status(role):", start)
manager_roles = r'''def validate_role_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise RuntimeError("invalid overlay IP: " + str(value))
    normalized = str(address)
    if (
        address.version != 4
        or address not in OVERLAY_NETWORK
        or address in (OVERLAY_NETWORK.network_address, OVERLAY_NETWORK.broadcast_address)
        or normalized == COORDINATOR_IP
    ):
        raise RuntimeError("role IP must be an eligible 10.0.0.x address; coordinator/network/broadcast addresses are not assignable")
    return normalized


def validate_server_ip(value):
    # Compatibility API retained for existing automation/tests.
    return validate_role_ip(value)


def read_role_registry(registry_file):
    try:
        lines = registry_file.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return set()
    values = {line.split("#", 1)[0].strip() for line in lines}
    return {validate_role_ip(value) for value in values if value}


def write_role_registry(registry_file, values):
    values = {validate_role_ip(value) for value in values}
    registry_file.parent.mkdir(parents=True, exist_ok=True)
    temporary = registry_file.with_name(registry_file.name + ".tmp")
    ordered = sorted(values, key=lambda value: int(ipaddress.ip_address(value)))
    temporary.write_text("".join(value + "\n" for value in ordered), encoding="utf-8")
    os.chmod(temporary, 0o640)
    try:
        shutil.chown(temporary, user="root", group="wireguard-p2p")
    except LookupError:
        pass
    os.replace(temporary, registry_file)


def read_server_registry():
    return read_role_registry(SERVER_REGISTRY_FILE)


def write_server_registry(values):
    write_role_registry(SERVER_REGISTRY_FILE, values)


def read_relay_only_registry():
    return read_role_registry(RELAY_ONLY_REGISTRY_FILE)


def write_relay_only_registry(values):
    write_role_registry(RELAY_ONLY_REGISTRY_FILE, values)


def set_node_role(address, role):
    address = validate_role_ip(address)
    if role not in ("client", "server", "relay_only"):
        raise RuntimeError("role must be one of: client, server, relay_only")
    servers = read_server_registry()
    relay_only = read_relay_only_registry()
    servers.discard(address)
    relay_only.discard(address)
    if role == "server":
        servers.add(address)
    elif role == "relay_only":
        relay_only.add(address)
    write_server_registry(servers)
    write_relay_only_registry(relay_only)
    return address


def explicit_roles():
    result = {address: "server" for address in read_server_registry()}
    for address in read_relay_only_registry():
        result[address] = "relay_only"
    return result


def manage_servers(arguments):
    action = arguments[0] if arguments else "list"
    if action == "list":
        for value in sorted(read_server_registry(), key=lambda item: int(ipaddress.ip_address(item))):
            print(value)
        return
    if action not in ("add", "remove") or len(arguments) != 2:
        raise RuntimeError("usage: wireguard-p2p server [list|add <10.0.0.x>|remove <10.0.0.x>]")
    address = validate_role_ip(arguments[1])
    if action == "add":
        set_node_role(address, "server")
        print("Authorized P2P server {}.".format(address))
        print("On {} run:".format(address))
        print("curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-server.sh | sudo sh")
        return
    if address not in read_server_registry():
        print("Server {} is not authorized.".format(address))
        return
    set_node_role(address, "client")
    print("Removed server role from {}. The node is now a normal client unless another role is assigned.".format(address))


def manage_relay_only(arguments):
    action = arguments[0] if arguments else "list"
    if action == "list":
        for value in sorted(read_relay_only_registry(), key=lambda item: int(ipaddress.ip_address(item))):
            print(value)
        return
    if action not in ("add", "remove") or len(arguments) != 2:
        raise RuntimeError("usage: wireguard-p2p relay-only [list|add <10.0.0.x>|remove <10.0.0.x>]")
    address = validate_role_ip(arguments[1])
    if action == "add":
        set_node_role(address, "relay_only")
        print("Assigned relay_only role to {}.".format(address))
        return
    if address not in read_relay_only_registry():
        print("Node {} is not relay_only.".format(address))
        return
    set_node_role(address, "client")
    print("Removed relay_only role from {}. The node is now a normal client.".format(address))


def manage_roles(arguments):
    action = arguments[0] if arguments else "list"
    if action == "list":
        roles = explicit_roles()
        for address in sorted(roles, key=lambda item: int(ipaddress.ip_address(item))):
            print("{} {}".format(address, roles[address]))
        return
    if action == "get" and len(arguments) == 2:
        address = validate_role_ip(arguments[1])
        print(explicit_roles().get(address, "client"))
        return
    if action == "set" and len(arguments) == 3:
        address = set_node_role(arguments[1], arguments[2])
        print("{} -> {}".format(address, arguments[2]))
        return
    raise RuntimeError("usage: wireguard-p2p role [list|get <IP>|set <IP> <client|server|relay_only>]")

'''
text = text[:start] + manager_roles + text[end:]
text = replace_once(
    text,
    '    if os.geteuid() != 0 and command in ("update", "server"):\n        raise RuntimeError("run this command with sudo")\n',
    '    if os.geteuid() != 0 and command in ("update", "server", "relay-only", "role"):\n        raise RuntimeError("run this command with sudo")\n',
    "manager root commands",
)
text = replace_once(
    text,
    '    elif command == "server":\n        if role != "vps":\n            raise RuntimeError("server authorization is managed on the VPS")\n        manage_servers(sys.argv[2:])\n    else:\n        raise RuntimeError("usage: wireguard-p2p [version|status|update [--force]|server [list|add IP|remove IP]]")\n',
    '    elif command == "server":\n        if role != "vps":\n            raise RuntimeError("server authorization is managed on the VPS")\n        manage_servers(sys.argv[2:])\n    elif command == "relay-only":\n        if role != "vps":\n            raise RuntimeError("relay_only roles are managed on the VPS")\n        manage_relay_only(sys.argv[2:])\n    elif command == "role":\n        if role != "vps":\n            raise RuntimeError("node roles are managed on the VPS")\n        manage_roles(sys.argv[2:])\n    else:\n        raise RuntimeError("usage: wireguard-p2p [version|status|update [--force]|server ...|relay-only ...|role ...]")\n',
    "manager role dispatch",
)
write(name, text)

# ---------------------------------------------------------------------------
# VPS install: clean installs have no historical node identities; upgrades keep files.
# ---------------------------------------------------------------------------
name = "p2p/wireguard-p2p/vps/install_vps.sh"
text = read(name)
text = replace_once(
    text,
    'SERVER_REGISTRY_FILE="$CONFIG_DIR/servers.conf"\n',
    'SERVER_REGISTRY_FILE="$CONFIG_DIR/servers.conf"\nRELAY_ONLY_REGISTRY_FILE="$CONFIG_DIR/relay-only.conf"\n',
    "vps relay role registry var",
)
text = replace_once(
    text,
    'if [ ! -e "$SERVER_REGISTRY_FILE" ]; then\n    printf \'10.0.0.2\\n10.0.0.5\\n\' > "$SERVER_REGISTRY_FILE"\nfi\nchown root:"$SERVICE_USER" "$SERVER_REGISTRY_FILE"\nchmod 0640 "$SERVER_REGISTRY_FILE"\n',
    'if [ ! -e "$SERVER_REGISTRY_FILE" ]; then\n    : > "$SERVER_REGISTRY_FILE"\nfi\nif [ ! -e "$RELAY_ONLY_REGISTRY_FILE" ]; then\n    : > "$RELAY_ONLY_REGISTRY_FILE"\nfi\nchown root:"$SERVICE_USER" "$SERVER_REGISTRY_FILE" "$RELAY_ONLY_REGISTRY_FILE"\nchmod 0640 "$SERVER_REGISTRY_FILE" "$RELAY_ONLY_REGISTRY_FILE"\n',
    "vps clean role registries",
)
write(name, text)

# ---------------------------------------------------------------------------
# Server installer: any eligible .x, including .8; always verify server authorization.
# ---------------------------------------------------------------------------
name = "p2p/wireguard-p2p/linux/install_server.sh"
text = read(name)
text = replace_once(
    text,
    'case "$OVERLAY_IP" in\n    10.0.0.1|10.0.0.8|"") echo "Overlay IP \'${OVERLAY_IP:-none}\' cannot be used as a P2P server." >&2; exit 1 ;;\n    10.0.0.*) ;;\n    *) echo "P2P server requires a 10.0.0.x overlay address; detected \'${OVERLAY_IP:-none}\'." >&2; exit 1 ;;\nesac\n',
    'case "$OVERLAY_IP" in\n    10.0.0.0|10.0.0.1|10.0.0.255|"") echo "Overlay IP \'${OVERLAY_IP:-none}\' cannot be used as a P2P server." >&2; exit 1 ;;\n    10.0.0.*) ;;\n    *) echo "P2P server requires an eligible 10.0.0.x overlay address; detected \'${OVERLAY_IP:-none}\'." >&2; exit 1 ;;\nesac\n',
    "server installer fixed .8",
)
text = replace_once(text, 'if [ ! -s "$KEY_FILE" ]; then\n    KEY_FILE="$KEY_FILE" OVERLAY_IP="$OVERLAY_IP" python3 - <<\'PY\'\n', 'KEY_FILE="$KEY_FILE" OVERLAY_IP="$OVERLAY_IP" python3 - <<\'PY\'\n', "server always verify role")
text = replace_once(text, 'PY\nfi\nchown "$SERVICE_USER:$SERVICE_USER" "$KEY_FILE"\n', 'PY\nchown "$SERVICE_USER:$SERVICE_USER" "$KEY_FILE"\n', "server remove conditional key close")
write(name, text)

# ---------------------------------------------------------------------------
# Tests: explicit role model; no magic .2/.5/.8 identities.
# ---------------------------------------------------------------------------
write("p2p/wireguard-p2p/tests/test_dynamic_servers.py", '''import importlib.util
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
            server.write_text("10.0.0.8\\n10.0.0.10\\n", encoding="utf-8")
            relay.write_text("10.0.0.20\\n", encoding="utf-8")
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
            registry.write_text("10.0.0.8\\n", encoding="utf-8")
            try:
                api.SERVER_REGISTRY_FILE = str(registry)
                api.NOTIFY_KEY = b"x" * 32
                self.assertEqual(api.bootstrap_server_key("10.0.0.8"), b"x" * 32 + b"\\n")
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
''')

name = "p2p/wireguard-p2p/tests/test_peer_logic.py"
text = read(name)
text = replace_once(
    text,
    '    def test_roles(self):\n        self.assertEqual(api.peer_role("10.0.0.2"), "server")\n        self.assertEqual(api.peer_role("10.0.0.8"), "relay_only")\n        self.assertEqual(api.peer_role("10.0.0.4"), "client")\n',
    '    def test_roles_default_to_client_without_registry_entries(self):\n        self.assertEqual(api.peer_role("10.0.0.2"), "client")\n        self.assertEqual(api.peer_role("10.0.0.8"), "client")\n        self.assertEqual(api.peer_role("10.0.0.4"), "client")\n',
    "peer logic default roles",
)
text = replace_once(
    text,
    '    def test_server_and_relay_peers_are_rejected(self):\n        for address in ("10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.8"):\n            with self.assertRaises(ValueError):\n                agent.validate_peer_ip(address)\n',
    '    def test_only_vps_and_self_are_rejected_by_agent(self):\n        for address in ("10.0.0.1", "10.0.0.5"):\n            with self.assertRaises(ValueError):\n                agent.validate_peer_ip(address)\n        self.assertEqual(agent.validate_peer_ip("10.0.0.2"), "10.0.0.2")\n        self.assertEqual(agent.validate_peer_ip("10.0.0.8"), "10.0.0.8")\n',
    "agent peer validation test",
)
write(name, text)

# Runtime tests need explicit server registry during bootstrap-key checks.
name = "p2p/wireguard-p2p/tests/test_runtime.py"
text = read(name)
pattern = re.compile(r'''    def test_server_bootstrap_key_is_overlay_restricted\(self\):\n.*?        finally:\n            api.NOTIFY_KEY = original\n''', re.S)
replacement = '''    def test_server_bootstrap_key_is_overlay_restricted(self):
        original_key = api.NOTIFY_KEY
        original_registry = api.SERVER_REGISTRY_FILE
        with tempfile.TemporaryDirectory() as tmp:
            registry = pathlib.Path(tmp) / "servers.conf"
            registry.write_text("10.0.0.8\\n", encoding="utf-8")
            try:
                api.SERVER_REGISTRY_FILE = str(registry)
                api.NOTIFY_KEY = b"x" * 32
                self.assertEqual(api.bootstrap_server_key("10.0.0.8"), b"x" * 32 + b"\\n")
                with self.assertRaises(PermissionError):
                    api.bootstrap_server_key("10.0.0.3")
            finally:
                api.SERVER_REGISTRY_FILE = original_registry
                api.NOTIFY_KEY = original_key
'''
text, count = pattern.subn(replacement, text, count=1)
if count != 1:
    raise RuntimeError("runtime bootstrap role test anchor missing")
write(name, text)

# ---------------------------------------------------------------------------
# README: Agent-first generic role deployment guide.
# ---------------------------------------------------------------------------
write("README.md", r'''# WireGuard P2P

当前生产版本：**v7.10.0**，协议版本 7。

这是一个建立在现有 WireGuard Overlay 之上的自动 P2P Direct 项目。当前默认拓扑仍是：

```text
Overlay CIDR: 10.0.0.0/24
Coordinator:  10.0.0.1
API:          http://10.0.0.1:8899
WG interface: wg0
```

**v7.10 的核心变化：节点编号不再具有任何内置含义。** `.2`、`.5`、`.8`、`.10` 都只是普通 Overlay 地址；除 VPS `10.0.0.1`、网络地址 `.0` 和广播地址 `.255` 外，任意合法 `10.0.0.x` 都可以被配置成 `client`、`server` 或 `relay_only`。

> 这意味着 `10.0.0.8` 不再被写死成 `relay_only`，`.2/.5` 也不再是新安装时的默认 Server。

## 1. 角色模型

角色由 VPS 配置决定，不由 IP 尾号决定：

```text
client       默认角色。没有显式配置的普通 WireGuard Peer 都是 client。
server       可被 Client 自动发现并尝试 P2P Direct 的 Linux Server Agent。
relay_only   可选角色。节点保持 WireGuard Relay 基线，但不参与 P2P 协调。
```

VPS 使用两个配置文件：

```text
/etc/wireguard-p2p/servers.conf
/etc/wireguard-p2p/relay-only.conf
```

**不要让 Agent 直接编辑这些文件。** 使用管理命令：

```bash
sudo wireguard-p2p role list
sudo wireguard-p2p role get 10.0.0.8
sudo wireguard-p2p role set 10.0.0.8 client
sudo wireguard-p2p role set 10.0.0.8 server
sudo wireguard-p2p role set 10.0.0.8 relay_only
```

兼容快捷命令仍保留：

```bash
sudo wireguard-p2p server list
sudo wireguard-p2p server add 10.0.0.10
sudo wireguard-p2p server remove 10.0.0.10

sudo wireguard-p2p relay-only list
sudo wireguard-p2p relay-only add 10.0.0.20
sudo wireguard-p2p relay-only remove 10.0.0.20
```

`role set` 会保证角色互斥：一个节点不会同时存在于 `server` 与 `relay_only` 注册表中。`client` 是隐式默认角色，因此设置为 `client` 会从两个显式注册表中移除该 IP。

## 2. 不可破坏的网络不变量

P2P 是增强层，不是基础 WireGuard 的替代品：

```text
Relay baseline: AllowedIPs = 10.0.0.0/24
Direct route:   只有 fresh authenticated WireGuard handshake 成功后才安装目标 /32
Keepalive:      Direct = 25 s
Fallback:       Direct 失败或过期时回退 VPS /24 Relay
```

Agent **禁止**因为部署 P2P 而重建 WireGuard key、删除 VPS Peer、删除 `/24 AllowedIPs`、关闭 Relay，或仅凭 Candidate 信息直接安装 `/32`。

## 3. 给 Agent 的部署决策

先执行：

```bash
wg show wg0
ping -c 2 10.0.0.1
```

基础 WireGuard 不通时，先修 WireGuard，不要继续 P2P 安装。

### 3.1 VPS / Coordinator 首次安装

前提：VPS 已有 `wg0=10.0.0.1`，并安装 `python3`、`wireguard-tools`、`systemd`。

私有 GitHub 仓库首次输入只读 Token：

```bash
read -rsp 'GitHub read token: ' T; echo; curl -fsSL -H "Authorization: Bearer $T" -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/stainzhao/p2p/contents/p2p/wireguard-p2p/bootstrap/bootstrap-vps.py?ref=main' | sudo env P2P_GITHUB_TOKEN="$T" python3 -
```

验证：

```bash
curl -fsS http://10.0.0.1:8899/health
sudo wireguard-p2p version
sudo wireguard-p2p role list
```

**全新 v7.10 安装不会自动创建 `.2/.5/.8` 等任何角色。** 两个角色注册表初始为空。若从 v7.9 升级，已有 `servers.conf` 会被保留，因此旧 `.2/.5` Server 不会因升级丢失。

### 3.2 部署任意 Linux P2P Server

例如目标 Overlay IP 是 `10.0.0.10`。

在 VPS：

```bash
sudo wireguard-p2p role set 10.0.0.10 server
```

然后在目标 Linux 机器：

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-server.sh | sudo sh
```

Server 安装器会：

```text
检查 wg0
自动读取本机 10.0.0.x
向 VPS 再次验证该 IP 当前确实是 server
领取/刷新 notify.key
安装 Python Agent + port mapping
安装 systemd services
启动并重启服务
```

因此 `.2`、`.5`、`.8`、`.10`、`.100` 的部署方式完全相同。IP 尾号不再进入源码逻辑。

验证：

```bash
sudo wireguard-p2p version
systemctl is-active wireguard-p2p-agent.service
systemctl is-active wireguard-p2p-portmap.service
wg show wg0
```

### 3.3 普通 Linux Client

没有显式角色时默认就是 `client`，无需先在 VPS 注册。

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-client.sh | sudo sh
```

验证：

```bash
systemctl is-active wireguard-p2p-client.service
journalctl -u wireguard-p2p-client.service -n 50 --no-pager
wg show wg0
```

### 3.4 Windows Client

安装 WireGuard 并导入基础配置，然后运行 Release 中：

```text
wireguard-p2p-windows-amd64.exe
```

Windows/Linux Go Client 都根据 Coordinator 返回的 `role=server` 动态发现 Server，不保存固定 Server IP 或公钥列表。

### 3.5 可选 relay_only 节点

只有明确希望某节点**不参与 P2P，只保留基础 WireGuard Relay 行为**时才配置：

```bash
sudo wireguard-p2p role set 10.0.0.20 relay_only
```

恢复普通 Client：

```bash
sudo wireguard-p2p role set 10.0.0.20 client
```

`relay_only` 是一种可选配置能力，不再绑定任何固定 IP。

## 4. 更新

建议顺序：

```text
VPS -> Servers -> Clients
```

VPS、Linux Server：

```bash
sudo wireguard-p2p update
```

普通 Linux Client 同样：

```bash
sudo wireguard-p2p update
```

Windows：

```powershell
.\wireguard-p2p.exe update
```

VPS 是唯一访问私有 GitHub Release 的节点。发布物经 SHA-256 验证后缓存到：

```text
/var/lib/wireguard-p2p/updates/current
```

其他节点只从 `10.0.0.1:8899/updates/` 获取。

## 5. Candidate 顺序

```text
lan4        1000
host6        900
observed6    850
reflexive6   825
mapped4      800
observed4    700
predicted4   500
VPS /24      baseline
```

v7.10 **没有修改** Candidate 优先级、IPv4/IPv6 打洞窗口、fresh-handshake promotion、Direct keepalive 或 Relay fallback。

## 6. 常用运维命令

VPS：

```bash
sudo wireguard-p2p status
sudo wireguard-p2p role list
curl -fsS http://10.0.0.1:8899/health
systemctl status peers-api.service --no-pager
```

Server：

```bash
sudo wireguard-p2p status
systemctl status wireguard-p2p-agent.service --no-pager
systemctl status wireguard-p2p-portmap.service --no-pager
journalctl -u wireguard-p2p-agent.service -n 100 --no-pager
wg show wg0 endpoints
wg show wg0 latest-handshakes
```

Linux Client：

```bash
systemctl status wireguard-p2p-client.service --no-pager
journalctl -u wireguard-p2p-client.service -n 100 --no-pager
wg show wg0
```

## 7. Agent 故障处理规则

- Server bootstrap 返回 `403`：在 VPS 执行 `sudo wireguard-p2p role get <IP>`；若不是 `server`，先 `role set <IP> server`。
- `/updates/...` 返回 `404`：VPS 先执行 `sudo wireguard-p2p update --force`。
- Direct 失败但 Overlay IP 仍通：这是正常 Relay fallback，不要破坏 `/24`。
- `10.0.0.1` 不通：属于基础 WireGuard 问题。
- 改角色不需要重新编译 Client，也不需要改 Server 公钥列表。

## 8. Agent 硬规则

1. 先读本 README，再部署。
2. 先验证 `wg0` 和 `10.0.0.1` 基线。
3. 普通 Linux Client 使用 Go Client，不安装 Python Server Agent。
4. Linux Server 必须先在 VPS 显式设置为 `server`。
5. 不根据 IP 尾号猜角色；`.8` 没有特殊意义。
6. 不直接编辑角色注册表，优先使用 `wireguard-p2p role ...`。
7. 不修改 WireGuard 私钥、公钥、基础 VPS Peer 和 `/24 AllowedIPs`。
8. 更新后验证版本、systemd active 状态以及 VPS/Server `/health`。
9. Direct 失败时保留 Relay。

## 9. 当前“通用”的边界

v7.10 已经实现**节点角色通用化**：项目源码不再依赖 `.2/.5/.8` 等具体设备地址，新节点可直接通过角色配置加入。

当前默认 Overlay 拓扑仍固定为 `10.0.0.0/24 + VPS 10.0.0.1 + wg0`。如果未来需要把这个项目直接复用到 `172.16.x.x`、`10.20.0.0/16` 或不同 Coordinator 地址，可继续把 Overlay CIDR/API 地址参数化；这与本次“去除设备硬编码”是独立的一层。
''')

# ---------------------------------------------------------------------------
# Current docs: remove stale fixed-node wording.
# ---------------------------------------------------------------------------
write("p2p/wireguard-p2p/docs/operations.md", r'''# Operations

当前版本：**v7.10.0**。

## Roles

VPS `10.0.0.1` 是 Coordinator。其他合法 `10.0.0.x` 没有固定身份：默认是 `client`，可由 VPS 显式设置为 `server` 或 `relay_only`。

```bash
sudo wireguard-p2p role list
sudo wireguard-p2p role get 10.0.0.8
sudo wireguard-p2p role set 10.0.0.8 server
sudo wireguard-p2p role set 10.0.0.8 relay_only
sudo wireguard-p2p role set 10.0.0.8 client
```

新安装的角色注册表为空；升级保留已有文件：

```text
/etc/wireguard-p2p/servers.conf
/etc/wireguard-p2p/relay-only.conf
```

## One-line deployment

Linux Server：先在 VPS 设置 `server`，然后目标机：

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-server.sh | sudo sh
```

普通 Linux Client：

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-client.sh | sudo sh
```

## Update

```bash
sudo wireguard-p2p update
```

Windows 使用：

```powershell
.\wireguard-p2p.exe update
```

建议更新顺序：VPS -> Servers -> Clients。

## Runtime checks

VPS：

```bash
sudo wireguard-p2p status
sudo wireguard-p2p role list
curl -fsS http://10.0.0.1:8899/health
```

Server：

```bash
sudo wireguard-p2p status
systemctl is-active wireguard-p2p-agent.service
systemctl is-active wireguard-p2p-portmap.service
wg show wg0
```

Client：

```bash
systemctl is-active wireguard-p2p-client.service
wg show wg0
```

所有安装和更新都不得修改 WireGuard key、基础 VPS peer 或 `AllowedIPs=10.0.0.0/24` Relay baseline。
''')

write("p2p/wireguard-p2p/docs/architecture.md", r'''# Current architecture — v7.10.0

## 1. Control/relay baseline

VPS `10.0.0.1` 同时承担 Coordinator/control plane 和 WireGuard `/24` Relay。P2P 只是增强层；只有 fresh authenticated WireGuard handshake 成功后才安装目标 `/32` Direct route。失败或 Direct stale 时删除动态 `/32`，自然回退 `/24`。

## 2. Generic node roles

具体 IP 尾号不再进入程序逻辑。除 Coordinator/network/broadcast 地址外，Overlay Peer 默认是 `client`；VPS 可显式配置：

```text
server       -> Linux Python Agent，可被 Client 动态发现
relay_only   -> 不参与 P2P 协调，只保留基础 Relay
client       -> 默认，无需注册
```

角色文件：

```text
/etc/wireguard-p2p/servers.conf
/etc/wireguard-p2p/relay-only.conf
```

Coordinator 的 `peer_payload()` 将实时角色返回给 Go Client，因此新增/删除 Server 不要求重编译 Client。Server bootstrap key 只向当前 `server` 角色 IP 返回。

## 3. Candidate priority

```text
lan4        1000
host6        900
observed6    850
reflexive6   825
mapped4      800
observed4    700
predicted4   500
VPS /24      baseline
```

IPv6 NAT66 simultaneous punch、IPv4 observed4 simultaneous punch、bounded predicted4、PCP/NAT-PMP/UPnP mapped4 均继续遵守 fresh-handshake promotion。

## 4. Security and lifecycle

VPS -> Server Agent 使用 HMAC-SHA256，带 timestamp、128-bit nonce 和 session identity。旧 session 不能覆盖新 session。Control lease 与健康 Direct 解耦；Direct 健康由真实 WireGuard handshake 和 `/32` route 判断。

## 5. Cross-platform Client

Windows amd64、Linux amd64、Linux arm64 使用同一 Go core。Client 从 Coordinator 返回的 `role=server` 动态构造目标集合，不包含固定 Server 公钥/IP 表。

## 6. Genericity boundary

v7.10 去除了具体节点 `.2/.5/.8` 的硬编码。默认网络拓扑仍为 `10.0.0.0/24`、Coordinator `10.0.0.1`、接口 `wg0`；这是下一层可参数化配置，不影响当前任意 `.x` 节点的动态角色能力。
''')
