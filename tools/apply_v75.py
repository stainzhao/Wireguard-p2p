#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def replace(path, old, new, count=-1):
    p = ROOT / path
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing pattern in {path}: {old[:120]!r}")
    text = text.replace(old, new, count)
    p.write_text(text, encoding="utf-8")

# Release versions.
for path in (
    "p2p/wireguard-p2p-exe/main.go",
    "p2p/wireguard-p2p/linux/p2p_agent.py",
    "p2p/wireguard-p2p/vps/peers_api.py",
):
    replace(path, '7.4.0', '7.5.0', 1)

# Candidate priorities: explicit router mappings still win, then authenticated
# VPS-observed WG mapping, then bounded predictions.
replace("p2p/wireguard-p2p/linux/candidates.py", '"observed4": 600,', '"observed4": 700,')
replace("p2p/wireguard-p2p/linux/candidates.py", '"predicted4": 400,', '"predicted4": 500,')
replace("p2p/wireguard-p2p-exe/candidate.go", 'candidatePriorityObserved4  = 600', 'candidatePriorityObserved4  = 700')
replace("p2p/wireguard-p2p-exe/candidate.go", 'candidatePriorityPredict4   = 400', 'candidatePriorityPredict4   = 500')

# Windows: observed4 gets the same overlapping punch treatment as reflexive6.
replace(
    "p2p/wireguard-p2p-exe/probe.go",
    'simultaneousIPv6Window = 8 * time.Second\n)',
    'simultaneousIPv6Window = 8 * time.Second\n\tsimultaneousIPv4Window = 8 * time.Second\n\tpredictedIPv4Window    = 1500 * time.Millisecond\n)',
)
replace(
    "p2p/wireguard-p2p-exe/probe.go",
    'func probeWindowForCandidate(candidate Candidate) time.Duration {\n\tif candidate.Type == "reflexive6" {\n\t\treturn simultaneousIPv6Window\n\t}\n\treturn candidateProbeWindow\n}',
    'func probeWindowForCandidate(candidate Candidate) time.Duration {\n\tswitch candidate.Type {\n\tcase "reflexive6":\n\t\treturn simultaneousIPv6Window\n\tcase "observed4":\n\t\treturn simultaneousIPv4Window\n\tcase "predicted4":\n\t\treturn predictedIPv4Window\n\tdefault:\n\t\treturn candidateProbeWindow\n\t}\n}',
)
replace(
    "p2p/wireguard-p2p-exe/probe.go",
    'candidateEndpointExists(candidates, local.Endpoint) || observedTypeForEndpoint(local.Endpoint) == "observed6")',
    'candidateEndpointExists(candidates, local.Endpoint) ||\n\t\t\t\t(observedTypeForEndpoint(local.Endpoint) == "observed6" || observedTypeForEndpoint(local.Endpoint) == "observed4"))',
)
replace(
    "p2p/wireguard-p2p-exe/probe.go",
    'if candidate.Type == "reflexive6" {\n\t\t\ta.log("Simultaneous IPv6 punch " + serverIP + " via " + candidate.Endpoint + ".")\n\t\t}',
    'if candidate.Type == "reflexive6" {\n\t\t\ta.log("Simultaneous IPv6 punch " + serverIP + " via " + candidate.Endpoint + ".")\n\t\t} else if candidate.Type == "observed4" {\n\t\t\ta.log("Simultaneous IPv4 punch " + serverIP + " via " + candidate.Endpoint + ".")\n\t\t} else if candidate.Type == "predicted4" {\n\t\t\ta.log("Bounded IPv4 port prediction " + serverIP + " via " + candidate.Endpoint + ".")\n\t\t}',
)

# Linux: overlapping observed4 window; predictions are intentionally short and bounded.
replace(
    "p2p/wireguard-p2p/linux/p2p_agent.py",
    'SIMULTANEOUS_IPV6_WINDOW = 8.0\nACTIVE_MONITOR_INTERVAL',
    'SIMULTANEOUS_IPV6_WINDOW = 8.0\nSIMULTANEOUS_IPV4_WINDOW = 8.0\nPREDICTED_IPV4_WINDOW = 1.5\nACTIVE_MONITOR_INTERVAL',
)
replace(
    "p2p/wireguard-p2p/linux/p2p_agent.py",
    '''def candidate_probe_window(candidate):
    if (
        isinstance(candidate, dict)
        and candidate.get("type") == "host6"
        and not global_ipv6_addresses()
    ):
        return SIMULTANEOUS_IPV6_WINDOW
    return CANDIDATE_PROBE_WINDOW
''',
    '''def candidate_probe_window(candidate):
    if not isinstance(candidate, dict):
        return CANDIDATE_PROBE_WINDOW
    candidate_type = candidate.get("type")
    if candidate_type == "host6" and not global_ipv6_addresses():
        return SIMULTANEOUS_IPV6_WINDOW
    if candidate_type == "observed4":
        return SIMULTANEOUS_IPV4_WINDOW
    if candidate_type == "predicted4":
        return PREDICTED_IPV4_WINDOW
    return CANDIDATE_PROBE_WINDOW
''',
)
replace(
    "p2p/wireguard-p2p/linux/p2p_agent.py",
    'or observed_type_for_endpoint(local.get("endpoint", "")) == "observed6"',
    'or observed_type_for_endpoint(local.get("endpoint", "")) in ("observed6", "observed4")',
)
replace(
    "p2p/wireguard-p2p/linux/p2p_agent.py",
    '    for candidate in candidates:\n        if not probe_generation_current(key, generation):\n            return\n        local = local_wg_peers().get(key, {})',
    '    for candidate in candidates:\n        if not probe_generation_current(key, generation):\n            return\n        if candidate.get("type") == "observed4":\n            log("Simultaneous IPv4 punch {} via {}".format(peer_ip, candidate.get("endpoint", "")))\n        elif candidate.get("type") == "predicted4":\n            log("Bounded IPv4 port prediction {} via {}".format(peer_ip, candidate.get("endpoint", "")))\n        local = local_wg_peers().get(key, {})',
)
replace(
    "p2p/wireguard-p2p/linux/p2p_agent.py",
    '''                selected_type = (
                    candidate_type_for_endpoint(
                        state.get("candidates", []), actual_endpoint
                    )
                    or candidate["type"]
                )''',
    '''                selected_type = (
                    candidate_type_for_endpoint(
                        state.get("candidates", []), actual_endpoint
                    )
                    or observed_type_for_endpoint(actual_endpoint)
                    or candidate["type"]
                )''',
)

# Coordinator: only coordinator may synthesize observed4/predicted4. Clients and
# agents may advertise lan4/host6/reflexive6/mapped4, never arbitrary predictions.
replace(
    "p2p/wireguard-p2p/vps/peers_api.py",
    'allowed_types = {"lan4", "host6", "reflexive6", "mapped4", "predicted4"}\n    if allow_observed:\n        allowed_types.add("observed4")',
    'allowed_types = {"lan4", "host6", "reflexive6", "mapped4"}\n    if allow_observed:\n        allowed_types.update(("observed4", "predicted4"))',
)
replace(
    "p2p/wireguard-p2p/vps/peers_api.py",
    '"priority": 600,\n        "verified": True,',
    '"priority": 700,\n        "verified": True,',
)
insert_after = '''def observed_candidate(endpoint):
    try:
        normalized, address, _port = parse_endpoint(endpoint)
    except (TypeError, ValueError):
        return None
    if address.version != 4:
        return None
    return {
        "type": "observed4",
        "family": "udp4",
        "endpoint": normalized,
        "priority": 700,
        "verified": True,
    }
'''
addition = insert_after + '''

PREDICTED4_DELTAS = (-2, -1, 1, 2)


def predicted_candidates(endpoint):
    """Generate a tiny same-IP neighborhood from a VPS-verified WG endpoint.

    This is deliberately bounded.  It is useful for sequential/port-preserving
    symmetric NATs, but never scans arbitrary addresses or the whole UDP range.
    """
    try:
        _normalized, address, port = parse_endpoint(endpoint)
    except (TypeError, ValueError):
        return []
    if address.version != 4 or not address.is_global or address.is_private:
        return []
    result = []
    for delta in PREDICTED4_DELTAS:
        candidate_port = port + delta
        if not 1 <= candidate_port <= 65535:
            continue
        result.append({
            "type": "predicted4",
            "family": "udp4",
            "endpoint": "{}:{}".format(address.compressed, candidate_port),
            "priority": 500,
            "verified": False,
        })
    return result
'''
replace("p2p/wireguard-p2p/vps/peers_api.py", insert_after, addition)
replace(
    "p2p/wireguard-p2p/vps/peers_api.py",
    '''            stored = NODE_CANDIDATES.get(peer["ip"], {}).get("candidates", [])
            peer["candidates"] = merge_candidates(
                legacy_lan,
                stored,
                [observed_candidate(peer.get("endpoint", ""))],
            )''',
    '''            stored = NODE_CANDIDATES.get(peer["ip"], {}).get("candidates", [])
            observed = observed_candidate(peer.get("endpoint", ""))
            predictions = [] if any(
                item.get("type") == "mapped4" for item in stored
            ) else predicted_candidates(peer.get("endpoint", ""))
            peer["candidates"] = merge_candidates(
                legacy_lan,
                stored,
                [observed],
                predictions,
            )''',
)
replace(
    "p2p/wireguard-p2p/vps/peers_api.py",
    '''    candidates = merge_candidates(
        legacy_lan,
        client_candidates,
        [observed_candidate(client.get("endpoint", ""))],
    )''',
    '''    observed = observed_candidate(client.get("endpoint", ""))
    predictions = [] if any(
        item.get("type") == "mapped4" for item in client_candidates
    ) else predicted_candidates(client.get("endpoint", ""))
    candidates = merge_candidates(
        legacy_lan,
        client_candidates,
        [observed],
        predictions,
    )''',
)

# Current tests that pin the release version.
for path in (
    "p2p/wireguard-p2p/tests/test_ipv6_punch.py",
    "p2p/wireguard-p2p/tests/test_runtime.py",
):
    p = ROOT / path
    text = p.read_text(encoding="utf-8").replace('"7.4.0"', '"7.5.0"')
    p.write_text(text, encoding="utf-8")

# Add focused regression tests.
(ROOT / "p2p/wireguard-p2p/tests/test_ipv4_punch.py").write_text(r'''import importlib.util
import os
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
os.environ.setdefault("P2P_LISTEN_ADDRESS", "10.0.0.5")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


candidates = load_module("candidates_ipv4", ROOT / "linux" / "candidates.py")
agent = load_module("agent_ipv4", ROOT / "linux" / "p2p_agent.py")
api = load_module("api_ipv4", ROOT / "vps" / "peers_api.py")


class IPv4PunchTests(unittest.TestCase):
    def test_release_versions(self):
        self.assertEqual(agent.VERSION, "7.5.0")
        self.assertEqual(api.VERSION, "7.5.0")

    def test_priorities(self):
        self.assertEqual(candidates.PRIORITY["mapped4"], 800)
        self.assertEqual(candidates.PRIORITY["observed4"], 700)
        self.assertEqual(candidates.PRIORITY["predicted4"], 500)

    def test_observed4_uses_simultaneous_window(self):
        self.assertEqual(
            agent.candidate_probe_window({"type": "observed4"}),
            agent.SIMULTANEOUS_IPV4_WINDOW,
        )
        self.assertEqual(agent.SIMULTANEOUS_IPV4_WINDOW, 8.0)
        self.assertEqual(
            agent.candidate_probe_window({"type": "predicted4"}),
            agent.PREDICTED_IPV4_WINDOW,
        )

    def test_predictions_are_bounded_to_verified_ip(self):
        values = api.predicted_candidates("211.71.91.89:38621")
        self.assertEqual(len(values), 4)
        self.assertEqual(
            {item["endpoint"] for item in values},
            {
                "211.71.91.89:38619",
                "211.71.91.89:38620",
                "211.71.91.89:38622",
                "211.71.91.89:38623",
            },
        )
        self.assertTrue(all(item["priority"] == 500 for item in values))
        self.assertTrue(all(not item["verified"] for item in values))

    def test_private_or_invalid_prediction_source_is_rejected(self):
        self.assertEqual(api.predicted_candidates("192.168.1.2:51820"), [])
        self.assertEqual(api.predicted_candidates("bad"), [])

    def test_nodes_cannot_self_advertise_predicted4(self):
        with self.assertRaises(ValueError):
            api.validate_candidates([
                {
                    "type": "predicted4",
                    "family": "udp4",
                    "endpoint": "211.71.91.89:38622",
                    "priority": 500,
                }
            ], allow_observed=False)

    def test_internal_predicted4_validation_is_allowed(self):
        result = api.validate_candidates([
            {
                "type": "predicted4",
                "family": "udp4",
                "endpoint": "211.71.91.89:38622",
                "priority": 500,
            }
        ], allow_observed=True)
        self.assertEqual(result[0]["type"], "predicted4")


if __name__ == "__main__":
    unittest.main()
''', encoding="utf-8")

(ROOT / "p2p/wireguard-p2p-exe/ipv4_punch_test.go").write_text(r'''package main

import (
    "testing"
    "time"
)

func TestIPv4PunchPriorities(t *testing.T) {
    if candidateDefaultPriority("mapped4") != 800 {
        t.Fatal("mapped4 priority changed")
    }
    if candidateDefaultPriority("observed4") != 700 {
        t.Fatal("observed4 priority must be 700")
    }
    if candidateDefaultPriority("predicted4") != 500 {
        t.Fatal("predicted4 priority must be 500")
    }
}

func TestIPv4PunchWindows(t *testing.T) {
    if probeWindowForCandidate(Candidate{Type: "observed4"}) != 8*time.Second {
        t.Fatal("observed4 must use the simultaneous IPv4 window")
    }
    if probeWindowForCandidate(Candidate{Type: "predicted4"}) != 1500*time.Millisecond {
        t.Fatal("predicted4 window must stay bounded")
    }
}
''', encoding="utf-8")

# Append current-architecture documentation, without reintroducing historical docs.
arch = ROOT / "p2p/wireguard-p2p/docs/architecture.md"
text = arch.read_text(encoding="utf-8")
if "## IPv4 direct path (v7.5)" not in text:
    text += '''\n\n## IPv4 direct path (v7.5)\n\nIPv4 direct traversal uses the actual WireGuard socket mapping observed by the VPS. `mapped4` remains preferred when PCP/NAT-PMP/UPnP succeeds. Otherwise both endpoints hold an overlapping 8-second `observed4` probe window; promotion still requires a fresh authenticated WireGuard handshake.\n\nFor sequential/port-preserving symmetric NATs, the coordinator may synthesize at most four `predicted4` candidates at observed-port offsets `-2,-1,+1,+2`. The public IPv4 address is never guessed: it must come from the VPS-verified WireGuard endpoint. Nodes cannot self-advertise `observed4` or `predicted4`. Predictions are skipped when a stable `mapped4` exists. Random endpoint-dependent NAT still falls back to the unchanged VPS `/24` relay.\n'''
    arch.write_text(text, encoding="utf-8")

ops = ROOT / "p2p/wireguard-p2p/docs/operations.md"
text = ops.read_text(encoding="utf-8")
if "Simultaneous IPv4 punch" not in text:
    text += '''\n\n## IPv4 P2P diagnostics\n\nWith Windows console output enabled, an IPv4 rendezvous attempt can show `Simultaneous IPv4 punch ... via A.B.C.D:PORT`. If the VPS-observed port does not work, up to four same-IP bounded predictions may be attempted. `P2P OK ... via observed4` confirms a fresh authenticated direct handshake. Failure removes the dynamic `/32` peer and leaves the VPS `/24` relay intact. No additional public STUN/observer port is required by v7.5.\n'''
    ops.write_text(text, encoding="utf-8")

readme = ROOT / "README.md"
text = readme.read_text(encoding="utf-8")
text = text.replace("v7.4.0", "v7.5.0")
if "IPv4 simultaneous" not in text:
    text += '''\n\n### IPv4 simultaneous direct\n\nv7.5 adds an 8-second simultaneous `observed4` WireGuard punch and bounded same-IP port prediction for sequential symmetric NAT. `mapped4` remains preferred and the VPS `/24` relay remains the connectivity baseline.\n'''
readme.write_text(text, encoding="utf-8")
