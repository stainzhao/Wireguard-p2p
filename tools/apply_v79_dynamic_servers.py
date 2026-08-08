#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OLD = "7.8.0"
NEW = "7.9.0"


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def write(path, text):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def replace_once(text, old, new, label):
    if old not in text:
        raise RuntimeError(f"missing anchor: {label}")
    return text.replace(old, new, 1)


# Version bump.
for path in [
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
    text = read(path)
    if OLD not in text:
        raise RuntimeError(f"{path}: expected {OLD}")
    write(path, text.replace(OLD, NEW))

# ---------------------------------------------------------------------------
# VPS: dynamic server registry instead of hard-coded .2/.5.
# ---------------------------------------------------------------------------
path = "p2p/wireguard-p2p/vps/peers_api.py"
text = read(path)
text = replace_once(
    text,
    'SERVER_IPS = {"10.0.0.2", "10.0.0.5"}\nRELAY_ONLY_IPS = {"10.0.0.8"}\n\nLAN_CANDIDATES = {}\nNODE_CANDIDATES = {}\nSESSIONS = {}\nSERVER_PUSH_STATUS = {\n    server_ip: {\n        "ok": None,\n        "last_success": 0,\n        "last_error": 0,\n        "last_error_message": "",\n        "consecutive_failures": 0,\n        "last_error_log": 0,\n    }\n    for server_ip in SERVER_IPS\n}\n',
    'DEFAULT_SERVER_IPS = {"10.0.0.2", "10.0.0.5"}\nSERVER_REGISTRY_FILE = os.environ.get("P2P_SERVER_REGISTRY_FILE", "/etc/wireguard-p2p/servers.conf")\nRELAY_ONLY_IPS = {"10.0.0.8"}\nOVERLAY_NETWORK = ipaddress.ip_network("10.0.0.0/24")\n\nLAN_CANDIDATES = {}\nNODE_CANDIDATES = {}\nSESSIONS = {}\nSERVER_PUSH_STATUS = {}\n',
    "server constants",
)
anchor = 'def peer_role(overlay_ip):\n    if overlay_ip in SERVER_IPS:\n        return "server"\n    if overlay_ip in RELAY_ONLY_IPS:\n        return "relay_only"\n    return "client"\n'
replacement = '''def server_ips():
    try:
        with open(SERVER_REGISTRY_FILE, "r", encoding="utf-8") as handle:
            raw = [line.split("#", 1)[0].strip() for line in handle]
    except OSError:
        raw = sorted(DEFAULT_SERVER_IPS)
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
            and normalized not in RELAY_ONLY_IPS
        ):
            result.add(normalized)
    return result


def new_push_status():
    return {
        "ok": None,
        "last_success": 0,
        "last_error": 0,
        "last_error_message": "",
        "consecutive_failures": 0,
        "last_error_log": 0,
    }


def peer_role(overlay_ip):
    if overlay_ip in RELAY_ONLY_IPS:
        return "relay_only"
    if overlay_ip in server_ips():
        return "server"
    return "client"
'''
text = replace_once(text, anchor, replacement, "peer_role")
text = text.replace('status = SERVER_PUSH_STATUS[server_ip]', 'status = SERVER_PUSH_STATUS.setdefault(server_ip, new_push_status())')
text = text.replace('for server_ip in SERVER_IPS', 'for server_ip in server_ips()')
text = text.replace('if source_ip not in SERVER_IPS:', 'if source_ip not in server_ips():')
write(path, text)

# ---------------------------------------------------------------------------
# Server Agent: self/VPS/relay rejection only. Server identity comes from VPS.
# ---------------------------------------------------------------------------
path = "p2p/wireguard-p2p/linux/p2p_agent.py"
text = read(path)
text = replace_once(
    text,
    '    if str(address) in (\n        VPS_ADDRESS,\n        LISTEN_ADDRESS,\n        "10.0.0.2",\n        "10.0.0.5",\n        "10.0.0.8",\n    ):\n',
    '    if str(address) in (VPS_ADDRESS, LISTEN_ADDRESS, "10.0.0.8"):\n',
    "agent peer role rejection",
)
write(path, text)

# ---------------------------------------------------------------------------
# Go Client: discover servers from coordinator role instead of compiled keys.
# ---------------------------------------------------------------------------
path = "p2p/wireguard-p2p-client/main.go"
text = read(path)
old_var = '''var (
\terrDeviceNotRegistered = errors.New("this device is not registered/online on the VPS")
\tserverKeys             = map[string]string{
\t\t"YmAf+TDF3vM4QyOjPLbYu51owmIpqJt7osYugYtyhSg=": "10.0.0.5", // 2696
\t\t"XTMmfyf2EWH7prfVCSkcWDOB5Lth5+F+OU8KsgtJhQQ=": "10.0.0.2", // GPU
\t}
)
'''
new_var = '''var (
\terrDeviceNotRegistered = errors.New("this device is not registered/online on the VPS")
)
'''
text = replace_once(text, old_var, new_var, "compiled server keys")
text = replace_once(text, 'type apiPeer struct {\n\tKey             string      `json:"key"`\n\tIP              string      `json:"ip"`\n', 'type apiPeer struct {\n\tKey             string      `json:"key"`\n\tIP              string      `json:"ip"`\n\tRole            string      `json:"role"`\n', "api peer role")
text = replace_once(text, '\tstates             map[string]*peerState\n', '\tstates             map[string]*peerState\n\tserverKeys         map[string]string\n', "app server map")
text = replace_once(text, '\t\tstates: make(map[string]*peerState),\n', '\t\tstates:     make(map[string]*peerState),\n\t\tserverKeys: make(map[string]string),\n', "app init server map")
text = text.replace('for key := range serverKeys {', 'for key := range a.serverKeys {')
text = text.replace('for key, serverIP := range serverKeys {', 'for key, serverIP := range a.serverKeys {')
write(path, text)

path = "p2p/wireguard-p2p-client/probe.go"
text = read(path)
anchor = '''\tnow := time.Now().Unix()
\tactive := make(map[string]bool)

\tfor _, peer := range peers {
\t\tserverIP, isServer := serverKeys[peer.Key]
'''
replacement = '''\tnow := time.Now().Unix()
\tactive := make(map[string]bool)
\tcurrentServers := make(map[string]string)
\tfor _, peer := range peers {
\t\tif peer.Role == "server" && peer.Key != "" && peer.IP != "" {
\t\t\tcurrentServers[peer.Key] = peer.IP
\t\t}
\t}
\ta.mu.Lock()
\tpreviousServers := make(map[string]string, len(a.serverKeys))
\tfor key, serverIP := range a.serverKeys {
\t\tpreviousServers[key] = serverIP
\t}
\ta.serverKeys = currentServers
\ta.mu.Unlock()

\tfor _, peer := range peers {
\t\tserverIP, isServer := currentServers[peer.Key]
'''
text = replace_once(text, anchor, replacement, "dynamic client servers")
old_cleanup = '''\tfor key := range serverKeys {
\t\tif active[key] {
\t\t\tcontinue
\t\t}
'''
new_cleanup = '''\ttrackedServers := make(map[string]bool, len(previousServers)+len(currentServers))
\tfor key := range previousServers {
\t\ttrackedServers[key] = true
\t}
\tfor key := range currentServers {
\t\ttrackedServers[key] = true
\t}
\tfor key := range trackedServers {
\t\tif active[key] {
\t\t\tcontinue
\t\t}
'''
text = replace_once(text, old_cleanup, new_cleanup, "dynamic server cleanup")
write(path, text)

# ---------------------------------------------------------------------------
# VPS manager: authorize/revoke arbitrary server overlay IPs safely.
# ---------------------------------------------------------------------------
path = "p2p/wireguard-p2p/manage/wireguard-p2p.py"
text = read(path)
text = replace_once(text, 'import hashlib\n', 'import hashlib\nimport ipaddress\n', "manager ipaddress import")
text = replace_once(
    text,
    'UPDATE_STATE = Path("/var/lib/wireguard-p2p")\n',
    'UPDATE_STATE = Path("/var/lib/wireguard-p2p")\nSERVER_REGISTRY_FILE = Path(os.environ.get("P2P_SERVER_REGISTRY_FILE", "/etc/wireguard-p2p/servers.conf"))\nDEFAULT_SERVER_IPS = {"10.0.0.2", "10.0.0.5"}\nRESERVED_SERVER_IPS = {"10.0.0.1", "10.0.0.8"}\nOVERLAY_NETWORK = ipaddress.ip_network("10.0.0.0/24")\n',
    "manager registry constants",
)
anchor = '\ndef show_status(role):\n'
helper = r'''
def validate_server_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise RuntimeError("invalid server overlay IP: " + str(value))
    normalized = str(address)
    if (
        address.version != 4
        or address not in OVERLAY_NETWORK
        or address in (OVERLAY_NETWORK.network_address, OVERLAY_NETWORK.broadcast_address)
        or normalized in RESERVED_SERVER_IPS
    ):
        raise RuntimeError("server IP must be an eligible 10.0.0.x address; 10.0.0.1 and 10.0.0.8 are reserved")
    return normalized


def read_server_registry():
    try:
        lines = SERVER_REGISTRY_FILE.read_text(encoding="utf-8").splitlines()
        values = {line.split("#", 1)[0].strip() for line in lines}
        return {validate_server_ip(value) for value in values if value}
    except FileNotFoundError:
        return set(DEFAULT_SERVER_IPS)


def write_server_registry(values):
    values = {validate_server_ip(value) for value in values}
    SERVER_REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = SERVER_REGISTRY_FILE.with_name(SERVER_REGISTRY_FILE.name + ".tmp")
    ordered = sorted(values, key=lambda value: int(ipaddress.ip_address(value)))
    temporary.write_text("".join(value + "\n" for value in ordered), encoding="utf-8")
    os.chmod(temporary, 0o640)
    try:
        shutil.chown(temporary, user="root", group="wireguard-p2p")
    except LookupError:
        pass
    os.replace(temporary, SERVER_REGISTRY_FILE)


def manage_servers(arguments):
    action = arguments[0] if arguments else "list"
    values = read_server_registry()
    if action == "list":
        for value in sorted(values, key=lambda item: int(ipaddress.ip_address(item))):
            print(value)
        return
    if action not in ("add", "remove") or len(arguments) != 2:
        raise RuntimeError("usage: wireguard-p2p server [list|add <10.0.0.x>|remove <10.0.0.x>]")
    address = validate_server_ip(arguments[1])
    if action == "add":
        if address in values:
            print("Server {} is already authorized.".format(address))
        else:
            values.add(address)
            write_server_registry(values)
            print("Authorized P2P server {}.".format(address))
        print("On {} run:".format(address))
        print("curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-server.sh | sudo sh")
        return
    if address not in values:
        print("Server {} is not authorized.".format(address))
        return
    values.remove(address)
    write_server_registry(values)
    print("Revoked P2P server {}. Existing direct sessions age out normally; stop its Agent if the role is being removed.".format(address))

'''
text = replace_once(text, anchor, '\n' + helper + 'def show_status(role):\n', "manager server commands")
old_main = '''    if os.geteuid() != 0 and len(sys.argv) > 1 and sys.argv[1] == "update":
        raise RuntimeError("run update with sudo")
    role = detect_role()
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    force = "--force" in sys.argv[2:]
'''
new_main = '''    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if os.geteuid() != 0 and command in ("update", "server"):
        raise RuntimeError("run this command with sudo")
    role = detect_role()
    force = "--force" in sys.argv[2:]
'''
text = replace_once(text, old_main, new_main, "manager main root check")
text = replace_once(
    text,
    '''    elif command == "update":
        if role == "vps":
            update_vps(force=force)
        else:
            update_server(force=force)
    else:
        raise RuntimeError("usage: wireguard-p2p [version|status|update [--force]]")
''',
    '''    elif command == "update":
        if role == "vps":
            update_vps(force=force)
        else:
            update_server(force=force)
    elif command == "server":
        if role != "vps":
            raise RuntimeError("server authorization is managed on the VPS")
        manage_servers(sys.argv[2:])
    else:
        raise RuntimeError("usage: wireguard-p2p [version|status|update [--force]|server [list|add IP|remove IP]]")
''',
    "manager main server command",
)
write(path, text)

# ---------------------------------------------------------------------------
# Installers: seed legacy servers on VPS, make Linux server installer generic.
# ---------------------------------------------------------------------------
path = "p2p/wireguard-p2p/vps/install_vps.sh"
text = read(path)
text = replace_once(text, 'TOKEN_FILE="$CONFIG_DIR/github.token"\n', 'TOKEN_FILE="$CONFIG_DIR/github.token"\nSERVER_REGISTRY_FILE="$CONFIG_DIR/servers.conf"\n', "vps registry variable")
text = replace_once(
    text,
    'chmod 0400 "$KEY_FILE"\n\nif [ -n "${P2P_GITHUB_TOKEN:-}" ]; then\n',
    'chmod 0400 "$KEY_FILE"\n\nif [ ! -e "$SERVER_REGISTRY_FILE" ]; then\n    printf \'10.0.0.2\\n10.0.0.5\\n\' > "$SERVER_REGISTRY_FILE"\nfi\nchown root:"$SERVICE_USER" "$SERVER_REGISTRY_FILE"\nchmod 0640 "$SERVER_REGISTRY_FILE"\n\nif [ -n "${P2P_GITHUB_TOKEN:-}" ]; then\n',
    "vps seed server registry",
)
write(path, text)

path = "p2p/wireguard-p2p/linux/install_server.sh"
text = read(path)
text = replace_once(
    text,
    '''case "$OVERLAY_IP" in
    10.0.0.2|10.0.0.5) ;;
    *) echo "This installer is only for P2P server roles 10.0.0.2/10.0.0.5; detected '${OVERLAY_IP:-none}'." >&2; exit 1 ;;
esac
''',
    '''case "$OVERLAY_IP" in
    10.0.0.1|10.0.0.8|"") echo "Overlay IP '${OVERLAY_IP:-none}' cannot be used as a P2P server." >&2; exit 1 ;;
    10.0.0.*) ;;
    *) echo "P2P server requires a 10.0.0.x overlay address; detected '${OVERLAY_IP:-none}'." >&2; exit 1 ;;
esac
''',
    "generic server address",
)
old_py = '''KEY_FILE="$KEY_FILE" python3 - <<'PY'
import os, urllib.request
path = os.environ["KEY_FILE"]
request = urllib.request.Request("http://10.0.0.1:8899/bootstrap/server-key")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(request, timeout=10) as response:
    data = response.read()
if len(data.strip()) < 32:
    raise SystemExit("VPS returned an invalid notification key")
with open(path, "wb") as handle:
    handle.write(data)
PY
'''
new_py = '''KEY_FILE="$KEY_FILE" OVERLAY_IP="$OVERLAY_IP" python3 - <<'PY'
import os, urllib.error, urllib.request
path = os.environ["KEY_FILE"]
overlay_ip = os.environ["OVERLAY_IP"]
request = urllib.request.Request("http://10.0.0.1:8899/bootstrap/server-key")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    with opener.open(request, timeout=10) as response:
        data = response.read()
except urllib.error.HTTPError as exc:
    if exc.code == 403:
        raise SystemExit(
            "Server {} is not authorized. On the VPS run: sudo wireguard-p2p server add {}".format(
                overlay_ip, overlay_ip
            )
        )
    raise
if len(data.strip()) < 32:
    raise SystemExit("VPS returned an invalid notification key")
with open(path, "wb") as handle:
    handle.write(data)
PY
'''
text = replace_once(text, old_py, new_py, "server key enrollment error")
write(path, text)

# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------
path = "p2p/wireguard-p2p/tests/test_peer_logic.py"
text = read(path)
text = replace_once(
    text,
    '    def test_server_and_relay_peers_are_rejected(self):\n        for address in ("10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.8"):\n',
    '    def test_self_vps_and_relay_peers_are_rejected(self):\n        for address in ("10.0.0.1", "10.0.0.5", "10.0.0.8"):\n',
    "agent validation test",
)
write(path, text)

write("p2p/wireguard-p2p/tests/test_dynamic_servers.py", r'''import importlib.util
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


class DynamicServerTests(unittest.TestCase):
    def test_missing_registry_keeps_legacy_servers(self):
        old = api.SERVER_REGISTRY_FILE
        try:
            api.SERVER_REGISTRY_FILE = "/definitely/missing/p2p-servers.conf"
            self.assertEqual(api.peer_role("10.0.0.2"), "server")
            self.assertEqual(api.peer_role("10.0.0.5"), "server")
        finally:
            api.SERVER_REGISTRY_FILE = old

    def test_registry_can_authorize_dot10_without_code_change(self):
        old = api.SERVER_REGISTRY_FILE
        with tempfile.TemporaryDirectory() as tmp:
            registry = pathlib.Path(tmp) / "servers.conf"
            registry.write_text("10.0.0.10\n", encoding="utf-8")
            try:
                api.SERVER_REGISTRY_FILE = str(registry)
                self.assertEqual(api.peer_role("10.0.0.10"), "server")
                self.assertEqual(api.peer_role("10.0.0.2"), "client")
                self.assertEqual(api.peer_role("10.0.0.8"), "relay_only")
            finally:
                api.SERVER_REGISTRY_FILE = old

    def test_bootstrap_key_is_only_for_authorized_servers(self):
        old_file = api.SERVER_REGISTRY_FILE
        old_key = api.NOTIFY_KEY
        with tempfile.TemporaryDirectory() as tmp:
            registry = pathlib.Path(tmp) / "servers.conf"
            registry.write_text("10.0.0.10\n", encoding="utf-8")
            try:
                api.SERVER_REGISTRY_FILE = str(registry)
                api.NOTIFY_KEY = b"x" * 32
                self.assertEqual(api.bootstrap_server_key("10.0.0.10"), b"x" * 32 + b"\n")
                with self.assertRaises(PermissionError):
                    api.bootstrap_server_key("10.0.0.4")
            finally:
                api.SERVER_REGISTRY_FILE = old_file
                api.NOTIFY_KEY = old_key

    def test_manager_rejects_reserved_addresses(self):
        self.assertEqual(manager.validate_server_ip("10.0.0.10"), "10.0.0.10")
        for value in ("10.0.0.1", "10.0.0.8", "10.0.0.0", "10.0.0.255", "192.168.1.10"):
            with self.assertRaises(RuntimeError):
                manager.validate_server_ip(value)


if __name__ == "__main__":
    unittest.main()
''')

# ---------------------------------------------------------------------------
# README: agent-oriented deployment contract.
# ---------------------------------------------------------------------------
write("README.md", r'''# WireGuard P2P

当前生产版本：**v7.9.0**，协议版本仍为 7。

本项目是在现有 WireGuard `10.0.0.0/24` 网络之上增加自动 P2P Direct。**VPS relay 永远是基线，P2P 失败不能破坏基础连通性。**

## 1. 角色

```text
VPS / Coordinator
  10.0.0.1
  peers_api.py

Linux P2P Server
  任意经 VPS 授权的 10.0.0.x，例如 10.0.0.2 / .5 / .10
  Python p2p_agent.py + port mapping

P2P Client
  Windows amd64
  Linux amd64 / arm64
  共享 Go client core
```

`10.0.0.8` 当前保留为 `relay_only`，不要注册为 Server。`10.0.0.1` 是 VPS。

Server **不再写死 `.2/.5`，也不再把 Server 公钥编译进 Client**。VPS 通过 `/etc/wireguard-p2p/servers.conf` 管理 Server 授权，Client 根据 Coordinator 返回的 `role=server` 动态发现所有 Server。因此以后新增 `.10/.11/...` 不需要修改源码或重新编译 Client。

## 2. 不可破坏的网络约束

部署 Agent 必须遵守：

```text
WireGuard interface: wg0（默认）
VPS overlay:        10.0.0.1
Coordinator API:    http://10.0.0.1:8899
Relay baseline:     AllowedIPs = 10.0.0.0/24
Direct route:       仅 fresh authenticated WG handshake 后添加目标 /32
Keepalive:          Direct 使用 25s
```

除非用户明确要求，否则 **不要修改 WireGuard 私钥、公钥、VPS Endpoint、基础 `/24 AllowedIPs`、Candidate 优先级、打洞窗口或 relay 基线**。

## 3. Agent 最短部署流程

### A. VPS 首次安装

前提：VPS 已有可工作的 `wg0=10.0.0.1`，并安装 `python3`、`wireguard-tools`、`systemd`。

私有 GitHub 仓库首次需要一个只读 Token：

```bash
read -rsp 'GitHub read token: ' T; echo; curl -fsSL -H "Authorization: Bearer $T" -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/stainzhao/p2p/contents/p2p/wireguard-p2p/bootstrap/bootstrap-vps.py?ref=main' | sudo env P2P_GITHUB_TOKEN="$T" python3 -
```

验证：

```bash
curl -fsS http://10.0.0.1:8899/health
sudo wireguard-p2p version
sudo wireguard-p2p server list
```

首次安装会默认保留历史 Server `.2` 和 `.5`。Server 注册表位于：

```text
/etc/wireguard-p2p/servers.conf
```

不要让 Agent 直接编辑该文件，优先使用管理命令。

### B. 新增任意 Linux P2P Server（例如 `.10`）

前提：该机器已经完成基础 WireGuard 配置，`wg0` 上有 `10.0.0.10`，且：

```bash
ping -c 2 10.0.0.1
```

先在 **VPS** 授权：

```bash
sudo wireguard-p2p server add 10.0.0.10
```

再在 **10.0.0.10** 机器执行唯一安装命令：

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-server.sh | sudo sh
```

安装器会自动读取 `wg0` 的 overlay IP，不需要传 `.10`、用户名、CPU 架构或 `notify.key`。只有已经在 VPS 授权的 Server IP 才能取得 Server HMAC key；未授权节点会返回 403，并提示先执行 `server add`。

`.2/.5` 在首次 VPS 安装后默认已授权，因此可以直接运行同一条 Server bootstrap 命令。

验证 Server：

```bash
sudo wireguard-p2p version
systemctl is-active wireguard-p2p-agent.service
systemctl is-active wireguard-p2p-portmap.service
curl -fsS http://$(ip -4 -o addr show dev wg0 | awk '$4 ~ /^10\.0\.0\./ {sub(/\/.*/,"",$4); print $4; exit}'):8898/health
```

删除 Server 授权：

```bash
sudo wireguard-p2p server remove 10.0.0.10
```

此命令在 VPS 执行。若设备不再承担 Server 角色，还应停止该设备上的 Agent service。

### C. 普通 Linux Client 首次安装

前提：`wg0` 已能访问 `10.0.0.1`。

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-client.sh | sudo sh
```

自动识别：

```text
x86_64/amd64 -> linux-amd64
aarch64/arm64 -> linux-arm64
```

验证：

```bash
systemctl is-active wireguard-p2p-client.service
journalctl -u wireguard-p2p-client.service -n 50 --no-pager
wg show wg0
```

### D. Windows Client

安装 WireGuard、导入基础 `wg0` 配置，然后使用 Release 中：

```text
wireguard-p2p-windows-amd64.exe
```

运行后会动态发现 VPS 当前授权的全部 Server，不需要在 EXE 中维护 `.2/.5/.10` 公钥列表。

## 4. 更新

建议顺序：

```text
VPS -> Linux Servers -> Clients
```

所有 Linux VPS/Server/Client：

```bash
sudo wireguard-p2p update
```

Windows：

```powershell
.\wireguard-p2p.exe update
```

VPS 是唯一访问私有 GitHub Release 的节点。VPS 校验 SHA-256 后把 Release 缓存在：

```text
/var/lib/wireguard-p2p/updates/current
```

其他节点只从 WireGuard overlay 的 `10.0.0.1:8899/updates/` 获取包。

## 5. Candidate 优先级

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

只有 fresh authenticated WireGuard handshake 才能提升为 Direct `/32`。

## 6. Agent 部署决策表

| 目标机器 | Agent 应做什么 |
|---|---|
| VPS `10.0.0.1` | 首次跑 VPS bootstrap；以后 `sudo wireguard-p2p update` |
| 新 P2P Server | 先在 VPS `server add <overlay-ip>`，再在目标机跑 server bootstrap |
| 已授权 `.2/.5` | 直接跑 server bootstrap |
| 普通 Linux Client | 直接跑 client bootstrap |
| Windows Client | 使用 Release EXE；以后 EXE `update` |

Agent 在执行前必须先确认：

```bash
wg show wg0
ping -c 2 10.0.0.1
```

若基础 WireGuard 不通，**先排查 WireGuard，不要用 P2P 安装器掩盖问题**。

## 7. 常用诊断

VPS：

```bash
sudo wireguard-p2p status
sudo wireguard-p2p server list
curl -fsS http://10.0.0.1:8899/health
systemctl status peers-api.service --no-pager
```

Server：

```bash
sudo wireguard-p2p status
systemctl status wireguard-p2p-agent.service --no-pager
sudo journalctl -u wireguard-p2p-agent.service -n 100 --no-pager
wg show wg0 endpoints
wg show wg0 latest-handshakes
```

Linux Client：

```bash
systemctl status wireguard-p2p-client.service --no-pager
journalctl -u wireguard-p2p-client.service -n 100 --no-pager
wg show wg0
```

常见错误：

- Server bootstrap `403`：该 overlay IP 尚未在 VPS `server add` 授权。
- `/updates/...` 返回 `404`：VPS 尚未完成当前 Release 缓存，先在 VPS `sudo wireguard-p2p update --force`。
- P2P Direct 失败但 `10.0.0.x` 仍可访问：这是正常 Relay fallback。
- `10.0.0.1` 本身不通：基础 WireGuard 问题，不属于 P2P Agent。

## 8. 发布与源码结构

```text
.github/workflows/ci.yml
p2p/wireguard-p2p-client/        Windows/Linux Go Client
p2p/wireguard-p2p/linux/         Linux Server Agent
p2p/wireguard-p2p/vps/           Coordinator
p2p/wireguard-p2p/manage/        Linux VPS/Server 管理命令
p2p/wireguard-p2p/bootstrap/     一行首次安装入口
p2p/wireguard-p2p/tests/         Python 回归测试
p2p/wireguard-p2p/docs/          当前文档
```

`main` CI 构建并发布 Windows amd64、Linux amd64/arm64、Server、VPS 与 bootstrap 资产。编译产物不提交到 Git。

## 9. 给自动化 Agent 的硬规则

1. 优先读取本 README，再执行部署。
2. 不要把普通 Linux Client 安装成 Python Server Agent。
3. 新 Server IP 必须先通过 VPS `wireguard-p2p server add` 授权。
4. 不要把 `10.0.0.8` 注册为 Server。
5. 不要覆盖 `/etc/wireguard/` 或重新生成 WireGuard key。
6. 不要删除 `AllowedIPs = 10.0.0.0/24` relay baseline。
7. 更新后必须检查版本、systemd active 状态和 `/health`。
8. Direct 失败时保留 Relay，不要为了“强制 P2P”破坏基础连通性。
''')

# Operations doc gets a concise dynamic-server section; README is canonical for agents.
path = "p2p/wireguard-p2p/docs/operations.md"
text = read(path)
text += r'''

## Dynamic Server enrollment (v7.9+)

Linux Server identities are no longer compiled as `.2/.5`. The VPS registry `/etc/wireguard-p2p/servers.conf` is authoritative. Use:

```bash
sudo wireguard-p2p server list
sudo wireguard-p2p server add 10.0.0.10
sudo wireguard-p2p server remove 10.0.0.10
```

After authorization, the target Linux node can install with:

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-server.sh | sudo sh
```

Clients discover all current servers from coordinator `role=server`; server public keys are not compiled into the Go client.
'''
write(path, text)
