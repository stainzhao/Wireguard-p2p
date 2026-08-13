#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path, old, new):
    path = ROOT / path
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit("{}: expected one match, found {} for {!r}".format(path, count, old[:120]))
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_all(path, old, new):
    path = ROOT / path
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit("{}: missing {!r}".format(path, old))
    path.write_text(text.replace(old, new), encoding="utf-8")


# ---------------------------------------------------------------------------
# Shared Go client: publish a per-process instance ID and force immediate
# re-probe when a server's instance changes, even if its endpoint/candidates
# happen to be identical after reboot.
# ---------------------------------------------------------------------------
main_go = "p2p/wireguard-p2p-client/main.go"
replace_once(main_go, 'import (\n\t"bytes"\n', 'import (\n\t"bytes"\n\t"crypto/rand"\n')
replace_once(main_go, 'version          = "7.12.0"', 'version          = "7.12.1"')
replace_once(
    main_go,
    '\tRole            string      `json:"role"`\n\tEndpoint        string      `json:"endpoint"`\n',
    '\tRole            string      `json:"role"`\n\tInstanceID      string      `json:"instance_id"`\n\tEndpoint        string      `json:"endpoint"`\n',
)
replace_once(
    main_go,
    '\tCandidateSignature string\n\tStarted            int64\n',
    '\tCandidateSignature string\n\tPeerInstanceID     string\n\tStarted            int64\n',
)
replace_once(
    main_go,
    '\twgPath             string\n\thttpClient         *http.Client\n',
    '\twgPath             string\n\tinstanceID         string\n\thttpClient         *http.Client\n',
)
replace_once(
    main_go,
    'var (\n\terrDeviceNotRegistered = errors.New("this device is not registered/online on the VPS")\n)\n',
    '''var (\n\terrDeviceNotRegistered = errors.New("this device is not registered/online on the VPS")\n)\n\nfunc newInstanceID() string {\n\tvalue := make([]byte, 16)\n\tif _, err := rand.Read(value); err == nil {\n\t\treturn fmt.Sprintf("%x", value)\n\t}\n\treturn fmt.Sprintf("%032x", uint64(time.Now().UnixNano()))\n}\n\nfunc serverInstanceChanged(previous, current string) bool {\n\treturn current != "" && previous != "" && previous != current\n}\n''',
)
replace_once(
    main_go,
    '\t\tpreferredInterface: *preferred,\n\t\twgPath:             wgPath,\n',
    '\t\tpreferredInterface: *preferred,\n\t\twgPath:             wgPath,\n\t\tinstanceID:         newInstanceID(),\n',
)
replace_once(
    main_go,
    '\t\t"protocol":    7,\n\t\t"lan_ip":      lanIP,\n',
    '\t\t"protocol":    7,\n\t\t"instance_id": a.instanceID,\n\t\t"lan_ip":      lanIP,\n',
)

old_reconcile = '''\t\ta.mu.Lock()\n\t\tstate := a.states[peer.Key]\n\t\tif state == nil {\n\t\t\tstate = &peerState{Mode: "idle", Generation: 1}\n\t\t\ta.states[peer.Key] = state\n\t\t}\n\t\tstate.Candidates = append([]Candidate(nil), candidates...)\n\n\t\tdirect := exists && contains(local.AllowedIPs, serverIP+"/32")\n\t\tsignatureChanged := state.CandidateSignature != signature\n\t\tif signatureChanged {\n\t\t\tstate.CandidateSignature = signature\n\t\t\tstate.Generation++\n\t\t\tstate.Failures = 0\n\t\t\tstate.RetryAfter = 0\n\t\t\tstate.WorkerRunning = false\n\n\t\t\tif direct && local.LatestHandshake > 0 && now-local.LatestHandshake <= int64(directMaxAge/time.Second) &&\n\t\t\t\t(candidateEndpointExists(candidates, local.Endpoint) ||\n\t\t\t\t\t(observedTypeForEndpoint(local.Endpoint) == "observed6" || observedTypeForEndpoint(local.Endpoint) == "observed4")) {\n\t\t\t\tstate.Mode = "direct"\n\t\t\t\tstate.Endpoint = local.Endpoint\n\t\t\t\tstate.SelectedType = candidateTypeForEndpoint(candidates, local.Endpoint)\n\t\t\t\tif state.SelectedType == "" {\n\t\t\t\t\tstate.SelectedType = observedTypeForEndpoint(local.Endpoint)\n\t\t\t\t}\n\t\t\t\ta.mu.Unlock()\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\tif exists {\n\t\t\t\t_, _ = a.wg("set", a.interfaceName, "peer", peer.Key, "remove")\n\t\t\t\texists = false\n\t\t\t\tdirect = false\n\t\t\t}\n\t\t\tstate.Mode = "idle"\n\t\t\tstate.Endpoint = ""\n\t\t\tstate.SelectedType = ""\n\t\t\tstate.Started = 0\n\t\t\ta.log("Candidates changed for " + serverIP + "; retrying now.")\n\t\t}\n'''
new_reconcile = '''\t\ta.mu.Lock()\n\t\tstate := a.states[peer.Key]\n\t\tif state == nil {\n\t\t\tstate = &peerState{Mode: "idle", Generation: 1, PeerInstanceID: peer.InstanceID}\n\t\t\ta.states[peer.Key] = state\n\t\t}\n\t\tinstanceChanged := serverInstanceChanged(state.PeerInstanceID, peer.InstanceID)\n\t\tif peer.InstanceID != "" {\n\t\t\tstate.PeerInstanceID = peer.InstanceID\n\t\t}\n\t\tstate.Candidates = append([]Candidate(nil), candidates...)\n\n\t\tdirect := exists && contains(local.AllowedIPs, serverIP+"/32")\n\t\tsignatureChanged := state.CandidateSignature != signature\n\t\ttopologyChanged := signatureChanged || instanceChanged\n\t\tif topologyChanged {\n\t\t\tif signatureChanged {\n\t\t\t\tstate.CandidateSignature = signature\n\t\t\t}\n\t\t\tstate.Generation++\n\t\t\tstate.Failures = 0\n\t\t\tstate.RetryAfter = 0\n\t\t\tstate.WorkerRunning = false\n\n\t\t\t// A changed process instance is authoritative reboot evidence.  Never\n\t\t\t// preserve the old /32 Direct in that case.  For candidate-only changes,\n\t\t\t// keep a healthy Direct only when its exact learned endpoint is still\n\t\t\t// present in the newly advertised candidate set.\n\t\t\tif !instanceChanged && direct && local.LatestHandshake > 0 &&\n\t\t\t\tnow-local.LatestHandshake <= int64(directMaxAge/time.Second) &&\n\t\t\t\tcandidateEndpointExists(candidates, local.Endpoint) {\n\t\t\t\tstate.Mode = "direct"\n\t\t\t\tstate.Endpoint = local.Endpoint\n\t\t\t\tstate.SelectedType = candidateTypeForEndpoint(candidates, local.Endpoint)\n\t\t\t\tif state.SelectedType == "" {\n\t\t\t\t\tstate.SelectedType = observedTypeForEndpoint(local.Endpoint)\n\t\t\t\t}\n\t\t\t\ta.mu.Unlock()\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\tif exists {\n\t\t\t\t_, _ = a.wg("set", a.interfaceName, "peer", peer.Key, "remove")\n\t\t\t\texists = false\n\t\t\t\tdirect = false\n\t\t\t}\n\t\t\tstate.Mode = "idle"\n\t\t\tstate.Endpoint = ""\n\t\t\tstate.SelectedType = ""\n\t\t\tstate.Started = 0\n\t\t\tif instanceChanged {\n\t\t\t\ta.log("Server restarted " + serverIP + "; retrying P2P now.")\n\t\t\t} else {\n\t\t\t\ta.log("Candidates changed for " + serverIP + "; retrying now.")\n\t\t\t}\n\t\t}\n'''
replace_once(main_go, old_reconcile, new_reconcile)

main_test = "p2p/wireguard-p2p-client/main_test.go"
replace_once(
    main_test,
    '''func TestServerInitiatorOwnsPair(t *testing.T) {\n''',
    '''func TestServerInstanceChanged(t *testing.T) {\n\tif serverInstanceChanged("", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {\n\t\tt.Fatal("first observation must not look like a reboot")\n\t}\n\tif serverInstanceChanged("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {\n\t\tt.Fatal("same instance must remain stable")\n\t}\n\tif !serverInstanceChanged("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {\n\t\tt.Fatal("changed instance must trigger fast recovery")\n\t}\n\tif got := newInstanceID(); len(got) != 32 {\n\t\tt.Fatalf("instance id length = %d, want 32", len(got))\n\t}\n}\n\nfunc TestServerInitiatorOwnsPair(t *testing.T) {\n''',
)

# ---------------------------------------------------------------------------
# Linux dual-capability Agent: publish its own boot/process instance and carry
# the remote instance through both responder offers and synthetic initiator
# offers.  A changed remote instance immediately tears down the old /32.
# ---------------------------------------------------------------------------
agent_py = "p2p/wireguard-p2p/linux/p2p_agent.py"
replace_once(agent_py, 'VERSION = "7.12.0"\n', 'VERSION = "7.12.1"\nINSTANCE_ID = uuid.uuid4().hex\n')
replace_once(
    agent_py,
    '        "protocol": 7,\n        "lan_ip": lan_ip,\n',
    '        "protocol": 7,\n        "instance_id": INSTANCE_ID,\n        "lan_ip": lan_ip,\n',
)
replace_once(
    agent_py,
    '                "peer_ip": peer.get("ip", ""),\n                "session_id": session_id,\n',
    '                "peer_ip": peer.get("ip", ""),\n                "peer_instance_id": peer.get("instance_id", ""),\n                "session_id": session_id,\n',
)
replace_once(
    agent_py,
    'def new_peer_state(peer_ip, session_id, session_started_ns, controller="responder"):\n',
    'def new_peer_state(peer_ip, session_id, session_started_ns, controller="responder", peer_instance_id=""):\n',
)
replace_once(
    agent_py,
    '        "session_started_ns": session_started_ns,\n        "ip": peer_ip,\n',
    '        "session_started_ns": session_started_ns,\n        "peer_instance_id": peer_instance_id,\n        "ip": peer_ip,\n',
)
replace_once(
    agent_py,
    '    session_started_ns = validate_session_started_ns(data["session_started_ns"])\n    advertised = validate_candidates(data.get("candidates", []))\n',
    '''    session_started_ns = validate_session_started_ns(data["session_started_ns"])\n    peer_instance_id = ""\n    if data.get("peer_instance_id"):\n        try:\n            peer_instance_id = uuid.UUID(str(data.get("peer_instance_id"))).hex\n        except (ValueError, AttributeError, TypeError):\n            raise ValueError("invalid peer instance id")\n    advertised = validate_candidates(data.get("candidates", []))\n''',
)
replace_once(
    agent_py,
    '''        state = STATES.get(key)\n\n        if state is not None and state.get("session_id") != session_id:\n''',
    '''        state = STATES.get(key)\n        instance_changed = bool(\n            state is not None\n            and peer_instance_id\n            and state.get("peer_instance_id", "") != peer_instance_id\n        )\n\n        if instance_changed:\n            state["generation"] = int(state.get("generation", 0)) + 1\n            state["worker_running"] = False\n            if local:\n                wg_set("peer", key, "remove")\n                local = None\n            state = new_peer_state(\n                peer_ip, session_id, session_started_ns, controller, peer_instance_id\n            )\n            STATES[key] = state\n            log("peer instance changed {}; retrying P2P now".format(peer_ip))\n        elif state is not None and state.get("session_id") != session_id:\n''',
)
replace_once(
    agent_py,
    '                state = new_peer_state(peer_ip, session_id, session_started_ns, controller)\n',
    '                state = new_peer_state(peer_ip, session_id, session_started_ns, controller, peer_instance_id)\n',
)
replace_once(
    agent_py,
    '            state = new_peer_state(peer_ip, session_id, session_started_ns, controller)\n            STATES[key] = state\n',
    '            state = new_peer_state(peer_ip, session_id, session_started_ns, controller, peer_instance_id)\n            STATES[key] = state\n',
)
replace_once(
    agent_py,
    '        state["session_started_ns"] = session_started_ns\n        state["ip"] = peer_ip\n',
    '        state["session_started_ns"] = session_started_ns\n        if peer_instance_id:\n            state["peer_instance_id"] = peer_instance_id\n        state["ip"] = peer_ip\n',
)
replace_once(
    agent_py,
    '''                and (\n                    candidate_endpoint_exists(\n                        candidates, local.get("endpoint", "")\n                    )\n                    or observed_type_for_endpoint(local.get("endpoint", "")) in ("observed6", "observed4")\n                )\n''',
    '''                and candidate_endpoint_exists(\n                    candidates, local.get("endpoint", "")\n                )\n''',
)
replace_once(
    agent_py,
    '        "protocol": 7,\n        "session_id": session_id,\n        "key": public_key(),\n',
    '        "protocol": 7,\n        "session_id": session_id,\n        "instance_id": INSTANCE_ID,\n        "key": public_key(),\n',
)

# ---------------------------------------------------------------------------
# Coordinator: instance IDs are optional protocol-7 metadata.  A changed ID
# starts a fresh control session and is exposed in peer_payload so lower-IP
# Server initiators and ordinary Go clients can react immediately.
# ---------------------------------------------------------------------------
api_py = "p2p/wireguard-p2p/vps/peers_api.py"
replace_once(api_py, 'VERSION = "7.12.0"', 'VERSION = "7.12.1"')
replace_once(
    api_py,
    '''            stored = NODE_CANDIDATES.get(peer["ip"], {}).get("candidates", [])\n''',
    '''            session = SESSIONS.get(peer["ip"], {})\n            peer["instance_id"] = (\n                session.get("instance_id", "")\n                if now - float(session.get("last_seen", 0) or 0) <= SESSION_TTL\n                else ""\n            )\n            stored = NODE_CANDIDATES.get(peer["ip"], {}).get("candidates", [])\n''',
)
replace_once(
    api_py,
    '''def record_candidate(overlay_ip, lan_ip, listen_port):\n''',
    '''def validate_instance_id(value):\n    if value in (None, ""):\n        return ""\n    try:\n        return uuid.UUID(str(value)).hex\n    except (ValueError, AttributeError, TypeError):\n        raise ValueError("invalid instance id")\n\n\ndef record_candidate(overlay_ip, lan_ip, listen_port):\n''',
)
replace_once(
    api_py,
    '''        client.get("key", ""),\n        client.get("endpoint", ""),\n''',
    '''        client.get("key", ""),\n        client.get("instance_id", ""),\n        client.get("endpoint", ""),\n''',
)
replace_once(
    api_py,
    '''        "peer_key": client["key"],\n        "peer_ip": client["ip"],\n''',
    '''        "peer_key": client["key"],\n        "peer_ip": client["ip"],\n        "peer_instance_id": client.get("instance_id", ""),\n''',
)
replace_once(
    api_py,
    'def coordinate_client(client, client_lan_endpoint, peers, client_candidates=None, force=False):\n',
    'def coordinate_client(client, client_lan_endpoint, peers, client_candidates=None, force=False, instance_id=""):\n',
)
replace_once(
    api_py,
    '''    client_candidates = client_candidates or []\n    servers = initiator_servers(client, peers)\n''',
    '''    client_candidates = client_candidates or []\n    if instance_id:\n        client = dict(client)\n        client["instance_id"] = instance_id\n    servers = initiator_servers(client, peers)\n''',
)
replace_once(
    api_py,
    '''            is_new_session = existing is None or existing.get("key") != client["key"]\n''',
    '''            is_new_session = (\n                existing is None\n                or existing.get("key") != client["key"]\n                or bool(instance_id and existing.get("instance_id", "") != instance_id)\n            )\n''',
)
replace_once(
    api_py,
    '''                    "ip": client["ip"],\n                    "last_seen": now,\n''',
    '''                    "ip": client["ip"],\n                    "instance_id": instance_id,\n                    "last_seen": now,\n''',
)
replace_once(
    api_py,
    '''                session["key"] = client["key"]\n                session["last_seen"] = now\n''',
    '''                session["key"] = client["key"]\n                if instance_id:\n                    session["instance_id"] = instance_id\n                session["last_seen"] = now\n''',
)
replace_once(
    api_py,
    '''            lan_ip, listen_port = validate_announcement(data)\n            record_candidate(source["ip"], lan_ip, listen_port)\n''',
    '''            lan_ip, listen_port = validate_announcement(data)\n            instance_id = validate_instance_id(data.get("instance_id", ""))\n            if instance_id:\n                source = dict(source)\n                source["instance_id"] = instance_id\n            record_candidate(source["ip"], lan_ip, listen_port)\n''',
)
replace_once(
    api_py,
    '''                session_id = coordinate_client(\n                    source, lan_endpoint, peers, advertised\n                )\n''',
    '''                session_id = coordinate_client(\n                    source, lan_endpoint, peers, advertised, instance_id=instance_id\n                )\n''',
)

# ---------------------------------------------------------------------------
# Version strings / docs.
# ---------------------------------------------------------------------------
replace_once("p2p/wireguard-p2p/manage/wireguard-p2p.py", 'VERSION = "7.12.0"', 'VERSION = "7.12.1"')
for path in [
    "README.md",
    "p2p/wireguard-p2p/docs/architecture.md",
    "p2p/wireguard-p2p/docs/operations.md",
    "p2p/wireguard-p2p/tests/test_ipv4_punch.py",
    "p2p/wireguard-p2p/tests/test_ipv6_punch.py",
    "p2p/wireguard-p2p/tests/test_runtime.py",
    "p2p/wireguard-p2p-client/cross_platform_test.go",
]:
    replace_all(path, "7.12.0", "7.12.1")

replace_once(
    "README.md",
    '当前生产版本：**v7.12.1**，协议版本 7。\n',
    '''当前生产版本：**v7.12.1**，协议版本 7。\n\n**v7.12.1 的恢复变化：每个运行中的 Client/Server 都会向 Coordinator 发布随机 `instance_id`。节点重启或 Agent/Client 进程重启后该 ID 立即变化；对端在下一次控制同步时会废弃旧 `/32` Direct 并马上重新 Probe，不再等待 180 秒 handshake stale。Candidate 集发生变化时，也只有当前 Direct endpoint 仍明确存在于新 Candidate 集中才会继续保留 Direct。**\n''',
)

# ---------------------------------------------------------------------------
# Targeted recovery tests.
# ---------------------------------------------------------------------------
recovery_test = ROOT / "p2p/wireguard-p2p/tests/test_fast_recovery.py"
recovery_test.write_text(r'''import importlib.util
import os
import pathlib
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


api = load_module("peers_api_fast_recovery", ROOT / "vps" / "peers_api.py")
os.environ.setdefault("P2P_LISTEN_ADDRESS", "10.0.0.2")
agent = load_module("p2p_agent_fast_recovery", ROOT / "linux" / "p2p_agent.py")

KEY = "SCTH2DOd6XhU0QZLFCgClEKWgZPNHr6QtmPpb6S05EM="
OLD_INSTANCE = "11111111111141118111111111111111"
NEW_INSTANCE = "22222222222242228222222222222222"
SESSION = "33333333-3333-4333-8333-333333333333"


class CoordinatorInstanceTests(unittest.TestCase):
    def setUp(self):
        with api.STATE_LOCK:
            api.LAN_CANDIDATES.clear()
            api.NODE_CANDIDATES.clear()
            api.SESSIONS.clear()

    def test_instance_change_rotates_control_session(self):
        client = {
            "key": "client-key",
            "ip": "10.0.0.4",
            "role": "client",
            "endpoint": "203.0.113.4:40000",
        }
        server = {
            "key": "server-key",
            "ip": "10.0.0.5",
            "role": "server",
            "endpoint": "198.51.100.5:51820",
        }
        with mock.patch.object(api, "push_offer", return_value={"ok": True}), \
             mock.patch.object(api, "push_remove"):
            first = api.coordinate_client(
                client, "192.168.1.4:40000", [client, server],
                instance_id=OLD_INSTANCE,
            )
            same = api.coordinate_client(
                client, "192.168.1.4:40000", [client, server],
                force=True, instance_id=OLD_INSTANCE,
            )
            restarted = api.coordinate_client(
                client, "192.168.1.4:40000", [client, server],
                instance_id=NEW_INSTANCE,
            )
        self.assertEqual(first, same)
        self.assertNotEqual(first, restarted)
        self.assertEqual(api.SESSIONS[client["ip"]]["instance_id"], NEW_INSTANCE)

    def test_peer_payload_exposes_current_instance(self):
        now = time.time()
        peer = {
            "key": "server-key",
            "ip": "10.0.0.5",
            "role": "server",
            "endpoint": "198.51.100.5:51820",
            "latest_handshake": int(now),
        }
        with api.STATE_LOCK:
            api.SESSIONS[peer["ip"]] = {
                "instance_id": NEW_INSTANCE,
                "last_seen": now,
            }
        payload = api.peer_payload([peer])
        self.assertEqual(payload[0]["instance_id"], NEW_INSTANCE)


class AgentInstanceTests(unittest.TestCase):
    def setUp(self):
        with agent.STATE_LOCK:
            agent.STATES.clear()

    def test_remote_instance_change_drops_fresh_old_direct_and_reprobes(self):
        candidates = [{
            "type": "observed4",
            "family": "udp4",
            "endpoint": "198.51.100.5:51820",
            "priority": 700,
            "verified": True,
        }]
        state = agent.new_peer_state(
            "10.0.0.5", SESSION, agent.time_ns(), "initiator", OLD_INSTANCE
        )
        state.update({
            "mode": "direct",
            "candidate_signature": agent.candidate_signature(candidates),
            "candidates": candidates,
        })
        agent.STATES[KEY] = state
        local = {
            "endpoint": "198.51.100.5:51820",
            "allowed_ips": ["10.0.0.5/32"],
            "latest_handshake": int(time.time()),
            "keepalive": 25,
        }
        wg_calls = []

        def fake_wg_set(*args):
            wg_calls.append(args)

        with mock.patch.object(agent, "local_wg_peers", return_value={KEY: local}), \
             mock.patch.object(agent, "wg_set", side_effect=fake_wg_set), \
             mock.patch.object(agent, "launch_probe") as launch, \
             mock.patch.object(agent, "save_state"), \
             mock.patch.object(agent, "local_ipv4", return_value="192.168.0.2"), \
             mock.patch.object(agent, "listen_port", return_value=51820), \
             mock.patch.object(agent, "gather_candidates", return_value=[]), \
             mock.patch.object(agent, "current_reflexive6_candidate", return_value=None), \
             mock.patch.object(agent, "public_key", return_value="server-2"):
            agent.handle_offer({
                "peer_key": KEY,
                "peer_ip": "10.0.0.5",
                "peer_instance_id": NEW_INSTANCE,
                "session_id": SESSION,
                "session_started_ns": state["session_started_ns"],
                "endpoint": "198.51.100.5:51820",
                "endpoint_type": "WAN",
                "candidates": candidates,
            }, controller="initiator")

        self.assertIn(("peer", KEY, "remove"), wg_calls)
        self.assertEqual(agent.STATES[KEY]["peer_instance_id"], NEW_INSTANCE)
        self.assertEqual(agent.STATES[KEY]["mode"], "probe")
        launch.assert_called_once()


if __name__ == "__main__":
    unittest.main()
''', encoding="utf-8")
