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


# Version bump for current runtime/tests/docs only.
version_files = [
    "p2p/wireguard-p2p-client/main.go",
    "p2p/wireguard-p2p-client/cross_platform_test.go",
    "p2p/wireguard-p2p/linux/p2p_agent.py",
    "p2p/wireguard-p2p/vps/peers_api.py",
    "p2p/wireguard-p2p/manage/wireguard-p2p.py",
    "p2p/wireguard-p2p/tests/test_runtime.py",
    "p2p/wireguard-p2p/tests/test_ipv4_punch.py",
    "p2p/wireguard-p2p/tests/test_ipv6_punch.py",
    "p2p/wireguard-p2p/docs/architecture.md",
    "p2p/wireguard-p2p/docs/operations.md",
    "README.md",
]
for path in version_files:
    text = read(path)
    if "7.11.0" not in text:
        raise SystemExit("{}: missing 7.11.0 marker".format(path))
    write(path, text.replace("7.11.0", "7.12.0"))


# Go Client: if it is ever run on a server node, exclude self and use the same
# deterministic lower-overlay-IP ownership as the Python server initiator.
path = "p2p/wireguard-p2p-client/main.go"
text = read(path)
anchor = '''func endpointIP(endpoint string) string {\n'''
helper = '''func serverInitiatorOwnsPair(localIP, remoteIP string) bool {\n\tlocal := net.ParseIP(localIP).To4()\n\tremote := net.ParseIP(remoteIP).To4()\n\tif local == nil || remote == nil || bytes.Equal(local, remote) {\n\t\treturn false\n\t}\n\treturn bytes.Compare(local, remote) < 0\n}\n\n'''
text = replace_once(text, anchor, helper + anchor, "go server pair helper")
write(path, text)

path = "p2p/wireguard-p2p-client/probe.go"
text = read(path)
old = '''\tcurrentServers := make(map[string]string)\n\tfor _, peer := range peers {\n\t\tif peer.Role == "server" && peer.Key != "" && peer.IP != "" {\n\t\t\tcurrentServers[peer.Key] = peer.IP\n\t\t}\n\t}\n'''
new = '''\tcurrentServers := make(map[string]string)\n\tfor _, peer := range peers {\n\t\tif peer.Role != "server" || peer.Key == "" || peer.IP == "" || peer.Key == ownKey {\n\t\t\tcontinue\n\t\t}\n\t\tif ours.Role == "server" && !serverInitiatorOwnsPair(ours.IP, peer.IP) {\n\t\t\tcontinue\n\t\t}\n\t\tcurrentServers[peer.Key] = peer.IP\n\t}\n'''
text = replace_once(text, old, new, "go deterministic server target set")
write(path, text)

path = "p2p/wireguard-p2p-client/main_test.go"
text = read(path)
if "TestServerInitiatorOwnsPair" not in text:
    text += '''\n\nfunc TestServerInitiatorOwnsPair(t *testing.T) {\n\tif !serverInitiatorOwnsPair("10.0.0.2", "10.0.0.5") {\n\t\tt.Fatal("lower overlay IP should own the server pair")\n\t}\n\tif serverInitiatorOwnsPair("10.0.0.5", "10.0.0.2") {\n\t\tt.Fatal("higher overlay IP must not duplicate-control the pair")\n\t}\n\tif serverInitiatorOwnsPair("10.0.0.2", "10.0.0.2") {\n\t\tt.Fatal("server must never target itself")\n\t}\n}\n'''
write(path, text)


# Coordinator: server-role nodes are allowed to open initiator sessions, but
# only the lower overlay IP coordinates each server-server pair. This prevents
# two Agents from racing over the same WireGuard peer endpoint.
path = "p2p/wireguard-p2p/vps/peers_api.py"
text = read(path)
anchor = '''def coordinate_client(client, client_lan_endpoint, peers, client_candidates=None, force=False):\n'''
helpers = '''def server_initiator_owns_pair(local_ip, remote_ip):\n    try:\n        local = ipaddress.ip_address(local_ip)\n        remote = ipaddress.ip_address(remote_ip)\n    except ValueError:\n        return False\n    return (\n        local.version == 4\n        and remote.version == 4\n        and local != remote\n        and int(local) < int(remote)\n    )\n\n\ndef initiator_servers(initiator, peers):\n    result = []\n    for peer in peers:\n        if peer.get("role") != "server":\n            continue\n        if not peer.get("key") or not peer.get("ip"):\n            continue\n        if peer.get("key") == initiator.get("key") or peer.get("ip") == initiator.get("ip"):\n            continue\n        if (\n            initiator.get("role") == "server"\n            and not server_initiator_owns_pair(initiator.get("ip", ""), peer.get("ip", ""))\n        ):\n            continue\n        result.append(peer)\n    return result\n\n\n'''
text = replace_once(text, anchor, helpers + anchor, "coordinator initiator helpers")
text = replace_once(
    text,
    '    servers = [peer for peer in peers if peer.get("role") == "server"]\n',
    '    servers = initiator_servers(client, peers)\n',
    "coordinator target filter",
)
text = replace_once(
    text,
    '''            for server_ip in server_ips()\n''',
    '''            for server_ip in server_ips() if server_ip != session.get("ip")\n''',
    "remove excludes initiating server itself",
)
text = replace_once(
    text,
    '''                if source.get("role") == "client":\n                    disconnect_client(source)\n''',
    '''                if source.get("role") in ("client", "server"):\n                    disconnect_client(source)\n''',
    "server initiator disconnect",
)
text = replace_once(
    text,
    '''            if source.get("role") == "client":\n                session_id = coordinate_client(\n                    source, lan_endpoint, peers, advertised\n                )\n''',
    '''            if source.get("role") in ("client", "server"):\n                session_id = coordinate_client(\n                    source, lan_endpoint, peers, advertised\n                )\n''',
    "server initiator coordinate",
)
needle = '                    response["session_id"] = session_id\n'
replacement = '''                    response["session_id"] = session_id\n                    with STATE_LOCK:\n                        current_session = SESSIONS.get(source["ip"], {})\n                        if current_session.get("session_id") == session_id:\n                            response["session_started_ns"] = int(\n                                current_session.get("session_started_ns", 0) or 0\n                            )\n'''
count = text.count(needle)
if count != 2:
    raise SystemExit("session metadata response: expected two matches, got {}".format(count))
text = text.replace(needle, replacement)
write(path, text)


# Linux Server Agent: integrate active Server->Server initiation into the same
# process that already handles inbound offers. A single process owns the peer
# state, avoiding Go/Python endpoint races and avoiding /usr/local/bin conflicts.
path = "p2p/wireguard-p2p/linux/p2p_agent.py"
text = read(path)
text = replace_once(
    text,
    '''VPS_ADDRESS = "10.0.0.1"\nSTATE_FILE = os.environ.get("P2P_STATE_FILE", "/run/wireguard-p2p/state.json")\n''',
    '''VPS_ADDRESS = "10.0.0.1"\nCOORDINATOR_SYNC_URL = "http://10.0.0.1:8899/sync"\nINITIATOR_SYNC_INTERVAL = 15\nINITIATOR_ONLINE_MAX_AGE = 180\nSTATE_FILE = os.environ.get("P2P_STATE_FILE", "/run/wireguard-p2p/state.json")\n''',
    "agent initiator constants",
)
anchor = '''def validate_candidates(values):\n'''
helpers = '''def endpoint_address(value):\n    try:\n        endpoint = validate_endpoint(value)\n    except (TypeError, ValueError):\n        return ""\n    if endpoint.startswith("["):\n        return endpoint[1:endpoint.index("]")]\n    return endpoint.rsplit(":", 1)[0]\n\n\ndef server_initiator_owns_pair(local_ip, remote_ip):\n    try:\n        local = ipaddress.ip_address(local_ip)\n        remote = ipaddress.ip_address(remote_ip)\n    except ValueError:\n        return False\n    return (\n        local.version == 4\n        and remote.version == 4\n        and local != remote\n        and int(local) < int(remote)\n    )\n\n\n'''
text = replace_once(text, anchor, helpers + anchor, "agent server pair helpers")
text = replace_once(
    text,
    '''def new_peer_state(peer_ip, session_id, session_started_ns):\n    return {\n''',
    '''def new_peer_state(peer_ip, session_id, session_started_ns, controller="responder"):\n    return {\n        "controller": controller,\n''',
    "agent controller state",
)
text = replace_once(
    text,
    '''def handle_offer(data):\n''',
    '''def handle_offer(data, controller="responder"):\n''',
    "agent handle offer controller",
)
text = text.replace(
    'state = new_peer_state(peer_ip, session_id, session_started_ns)',
    'state = new_peer_state(peer_ip, session_id, session_started_ns, controller)',
)
text = replace_once(
    text,
    '''        state["session_id"] = session_id\n        state["ip"] = peer_ip\n''',
    '''        state["session_id"] = session_id\n        state["ip"] = peer_ip\n        state["controller"] = controller\n''',
    "agent controller refresh",
)
anchor = '''def reflexive6_loop():\n'''
initiator_code = '''def local_candidate_snapshot():\n    lan_ip = local_ipv4()\n    wg_port = listen_port()\n    if not lan_ip or not wg_port:\n        raise RuntimeError("local WireGuard candidate is unavailable")\n    local_candidates = gather_candidates(wg_port, lan_ip)\n    reflexive = current_reflexive6_candidate(wg_port)\n    if reflexive:\n        local_candidates.append(reflexive)\n        local_candidates.sort(\n            key=lambda item: (\n                -int(item.get("priority", 0)), item.get("endpoint", "")\n            )\n        )\n    return lan_ip, wg_port, local_candidates\n\n\ndef coordinator_sync_once():\n    lan_ip, wg_port, local_candidates = local_candidate_snapshot()\n    payload = json.dumps({\n        "protocol": 7,\n        "lan_ip": lan_ip,\n        "listen_port": wg_port,\n        "candidates": local_candidates,\n    }, separators=(",", ":")).encode()\n    request = urllib.request.Request(\n        COORDINATOR_SYNC_URL,\n        data=payload,\n        headers={"Content-Type": "application/json"},\n        method="POST",\n    )\n    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))\n    with opener.open(request, timeout=5) as response:\n        result = json.loads(response.read().decode())\n    if int(result.get("protocol", 0) or 0) != 7:\n        raise RuntimeError("Coordinator protocol mismatch")\n    return result\n\n\ndef eligible_initiator_server(peer, now=None):\n    if not isinstance(peer, dict) or peer.get("role") != "server":\n        return False\n    if not peer.get("key") or not peer.get("ip") or not peer.get("endpoint"):\n        return False\n    if not server_initiator_owns_pair(LISTEN_ADDRESS, peer.get("ip", "")):\n        return False\n    now = time.time() if now is None else float(now)\n    latest = int(peer.get("latest_handshake", 0) or 0)\n    return bool(latest and now - latest <= INITIATOR_ONLINE_MAX_AGE)\n\n\ndef cleanup_initiator_states(active_keys):\n    active_keys = set(active_keys or ())\n    with STATE_LOCK:\n        current = local_wg_peers()\n        changed = False\n        for key, state in list(STATES.items()):\n            if state.get("controller") != "initiator" or key in active_keys:\n                continue\n            state["generation"] = int(state.get("generation", 0)) + 1\n            state["worker_running"] = False\n            if key in current:\n                try:\n                    wg_set("peer", key, "remove")\n                except Exception as exc:\n                    log_error("initiator peer cleanup failed: {}".format(exc))\n            del STATES[key]\n            changed = True\n        if changed:\n            save_state()\n\n\ndef server_initiator_once():\n    result = coordinator_sync_once()\n    peers = result.get("peers", [])\n    if not isinstance(peers, list):\n        raise RuntimeError("Coordinator returned invalid peers")\n    ours = next(\n        (peer for peer in peers if peer.get("ip") == LISTEN_ADDRESS), None\n    )\n    if ours is None or ours.get("role") != "server":\n        cleanup_initiator_states(set())\n        return\n\n    session_id = result.get("session_id", "")\n    session_started_ns = int(result.get("session_started_ns", 0) or 0)\n    if not session_id or session_started_ns <= 0:\n        cleanup_initiator_states(set())\n        return\n\n    our_wan = endpoint_address(ours.get("endpoint", ""))\n    now = time.time()\n    active_keys = set()\n    for peer in peers:\n        if not eligible_initiator_server(peer, now):\n            continue\n        key = peer.get("key")\n        active_keys.add(key)\n        peer_wan = endpoint_address(peer.get("endpoint", ""))\n        same_nat = bool(our_wan and peer_wan and our_wan == peer_wan)\n        lan_endpoint = peer.get("lan_endpoint", "")\n        endpoint_type = "LAN" if same_nat and lan_endpoint else "WAN"\n        endpoint = lan_endpoint if endpoint_type == "LAN" else peer.get("endpoint", "")\n        try:\n            handle_offer({\n                "peer_key": key,\n                "peer_ip": peer.get("ip", ""),\n                "session_id": session_id,\n                "session_started_ns": session_started_ns,\n                "endpoint": endpoint,\n                "endpoint_type": endpoint_type,\n                "candidates": peer.get("candidates", []),\n                "lease_expires": int(now) + 180,\n            }, controller="initiator")\n        except Exception as exc:\n            log_error(\n                "server initiator reconcile failed for {}: {}".format(\n                    peer.get("ip", "?"), exc\n                )\n            )\n    cleanup_initiator_states(active_keys)\n\n\ndef coordinator_disconnect():\n    request = urllib.request.Request(\n        "http://10.0.0.1:8899/disconnect",\n        data=b"{}",\n        headers={"Content-Type": "application/json"},\n        method="POST",\n    )\n    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))\n    with opener.open(request, timeout=3) as response:\n        response.read()\n\n\ndef server_initiator_loop():\n    last_error = ""\n    last_error_time = 0\n    while not STOP.is_set():\n        try:\n            server_initiator_once()\n            if last_error:\n                log("server initiator recovered")\n            last_error = ""\n        except Exception as exc:\n            message = str(exc)\n            now = time.time()\n            if message != last_error or now - last_error_time >= 300:\n                log_error("server initiator sync failed: {}".format(message))\n                last_error = message\n                last_error_time = now\n        if STOP.wait(INITIATOR_SYNC_INTERVAL):\n            return\n\n\n'''
text = replace_once(text, anchor, initiator_code + anchor, "agent initiator loop")
text = replace_once(
    text,
    '''    SERVER = ThreadingHTTPServer((LISTEN_ADDRESS, LISTEN_PORT), Handler)\n    log(\n''',
    '''    SERVER = ThreadingHTTPServer((LISTEN_ADDRESS, LISTEN_PORT), Handler)\n    initiator = threading.Thread(\n        target=server_initiator_loop, name="server-initiator"\n    )\n    initiator.daemon = True\n    initiator.start()\n    log(\n''',
    "agent initiator thread start",
)
text = replace_once(
    text,
    '''    finally:\n        STOP.set()\n        SERVER.server_close()\n''',
    '''    finally:\n        STOP.set()\n        try:\n            coordinator_disconnect()\n        except Exception:\n            pass\n        try:\n            cleanup_initiator_states(set())\n        except Exception:\n            pass\n        SERVER.server_close()\n''',
    "agent initiator shutdown",
)
write(path, text)


# Python regression tests for deterministic server/server ownership and the
# integrated Agent initiator.
path = "p2p/wireguard-p2p/tests/test_peer_logic.py"
text = read(path)
marker = '''    def test_push_status_tracks_failure_and_recovery(self):\n'''
api_tests = '''    def test_server_initiator_targets_only_higher_server(self):\n        source = {\n            "key": "server-5",\n            "ip": "10.0.0.5",\n            "role": "server",\n            "endpoint": "198.51.100.5:51820",\n        }\n        peers = [\n            {"key": "server-2", "ip": "10.0.0.2", "role": "server"},\n            source,\n            {"key": "server-8", "ip": "10.0.0.8", "role": "server"},\n        ]\n        targets = api.initiator_servers(source, peers)\n        self.assertEqual([item["ip"] for item in targets], ["10.0.0.8"])\n        self.assertTrue(api.server_initiator_owns_pair("10.0.0.2", "10.0.0.5"))\n        self.assertFalse(api.server_initiator_owns_pair("10.0.0.5", "10.0.0.2"))\n\n    def test_normal_client_still_targets_all_servers(self):\n        source = {"key": "client-4", "ip": "10.0.0.4", "role": "client"}\n        peers = [\n            source,\n            {"key": "server-2", "ip": "10.0.0.2", "role": "server"},\n            {"key": "server-5", "ip": "10.0.0.5", "role": "server"},\n        ]\n        targets = api.initiator_servers(source, peers)\n        self.assertEqual(\n            [item["ip"] for item in targets], ["10.0.0.2", "10.0.0.5"]\n        )\n\n'''
if "test_server_initiator_targets_only_higher_server" not in text:
    text = replace_once(text, marker, api_tests + marker, "coordinator server initiator tests")
marker = '''    def test_repeated_probe_failures_enter_long_cooldown(self):\n'''
agent_tests = '''    def test_server_pair_has_single_deterministic_initiator(self):\n        self.assertTrue(agent.server_initiator_owns_pair("10.0.0.2", "10.0.0.5"))\n        self.assertFalse(agent.server_initiator_owns_pair("10.0.0.5", "10.0.0.2"))\n        self.assertFalse(agent.server_initiator_owns_pair("10.0.0.5", "10.0.0.5"))\n\n    def test_server_initiator_online_filter(self):\n        now = 1000\n        peer = {\n            "key": "server-key",\n            "ip": "10.0.0.8",\n            "role": "server",\n            "endpoint": "198.51.100.8:51820",\n            "latest_handshake": now - 10,\n        }\n        self.assertTrue(agent.eligible_initiator_server(peer, now))\n        peer["latest_handshake"] = now - agent.INITIATOR_ONLINE_MAX_AGE - 1\n        self.assertFalse(agent.eligible_initiator_server(peer, now))\n\n'''
if "test_server_pair_has_single_deterministic_initiator" not in text:
    text = replace_once(text, marker, agent_tests + marker, "agent server initiator tests")
write(path, text)

path = "p2p/wireguard-p2p/tests/test_runtime.py"
text = read(path)
text = replace_once(
    text,
    '''        self.assertEqual(api.ANNOUNCE_TTL, 300)\n''',
    '''        self.assertEqual(api.ANNOUNCE_TTL, 300)\n        self.assertEqual(agent.INITIATOR_SYNC_INTERVAL, 15)\n        self.assertEqual(agent.INITIATOR_ONLINE_MAX_AGE, 180)\n''',
    "runtime initiator constants",
)
marker = '''    def test_managed_update_distribution(self):\n'''
new_test = '''    def test_server_dual_capability_is_integrated_into_agent(self):\n        source = (LINUX / "p2p_agent.py").read_text(encoding="utf-8")\n        self.assertIn("def server_initiator_loop", source)\n        self.assertIn("COORDINATOR_SYNC_URL", source)\n        self.assertIn('controller="initiator"', source)\n        self.assertNotIn("wireguard-p2p-initiator.service", source)\n\n'''
if "test_server_dual_capability_is_integrated_into_agent" not in text:
    text = replace_once(text, marker, new_test + marker, "runtime dual capability test")
write(path, text)


# Documentation: describe the new behavior as one Agent with responder +
# deterministic initiator capability; no second client installer is needed.
path = "README.md"
text = read(path)
anchor = '''**v7.11 的 IPv6 变化：多 GUA 主机不再把所有 `host6` 当成完全等价。Client/Server 会询问操作系统实际的 IPv6 源地址选择，将该地址以更高优先级发布，并给首选 `host6` 8 秒重叠打洞窗口；deprecated/tentative IPv6 不再发布，IPv6 Probe 会明确写入日志。**\n'''
insert = '''**v7.12 的 Server 变化：Linux `server` 现在是双能力节点。同一个 Python Agent 既响应 Client/Server 的入站协调，也会主动同步 Coordinator 并建立 Server↔Server Direct。每一对 Server 由 Overlay IP 较小的一端负责主动协调，避免双方同时修改同一个 WireGuard Peer；一旦 Direct 建立，数据面本身是双向的。无需在 Server 上额外安装普通 Linux Client。**\n\n'''
text = replace_once(text, anchor, insert + anchor, "README v7.12 summary")
text = text.replace(
    'server       可被 Client 自动发现并尝试 P2P Direct 的 Linux Server Agent。',
    'server       Linux 双能力 Agent：可被 Client/Server 连接，也会主动建立 Server↔Server Direct。',
)
text = text.replace(
    '安装 Python Agent + port mapping\n安装 systemd services',
    '安装 Python 双能力 Agent + port mapping\nAgent 内置 Server↔Server initiator，不额外安装 Linux Client\n安装 systemd services',
)
text = text.replace(
    '''lan4        1000\nhost6        900\nobserved6    850''',
    '''lan4                  1000\npreferred host6          910\nbackup host6             900\nobserved6                850''',
)
server_verify = '''systemctl is-active wireguard-p2p-portmap.service\nwg show wg0\n'''
server_verify_new = '''systemctl is-active wireguard-p2p-portmap.service\n# Server↔Server initiator 已集成在 wireguard-p2p-agent.service 中\nwg show wg0\n'''
text = replace_once(text, server_verify, server_verify_new, "README server verification")
write(path, text)

path = "p2p/wireguard-p2p/docs/architecture.md"
text = read(path)
text = text.replace(
    'server       -> Linux Python Agent，可被 Client 动态发现',
    'server       -> Linux 双能力 Python Agent，可响应连接并主动协调其他 Server',
)
anchor = '''## 3. Candidate priority\n'''
section = '''## 3. Server↔Server ownership\n\nServer Agent 内置 responder 与 initiator 两种能力。为避免一对 Server 的两端同时修改同一 WireGuard Peer，Coordinator 和 Agent 使用一致的确定性规则：Overlay IPv4 数值较小的一端负责主动发起该 Server↔Server 会话，较大的一端响应 VPS `/offer`。这只决定控制权；fresh handshake 成功后的 `/32` Direct 数据面始终双向。普通 Client 仍会主动尝试全部 Server。\n\n'''
text = replace_once(text, anchor, section + anchor.replace("## 3.", "## 4."), "architecture server ownership")
text = text.replace("## 4. Security and lifecycle", "## 5. Security and lifecycle")
text = text.replace("## 5. Cross-platform Client", "## 6. Cross-platform Client")
text = text.replace("## 6. Genericity boundary", "## 7. Genericity boundary")
write(path, text)

print("v7.12 server dual-capability transformation applied")
