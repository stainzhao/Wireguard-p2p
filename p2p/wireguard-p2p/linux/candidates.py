#!/usr/bin/env python3
"""Candidate discovery and probe selection for the Linux WireGuard P2P agent."""

import ipaddress
import json
import os
import subprocess
import time

PRIORITY = {
    "lan4": 1000,
    "host6": 900,
    "mapped4": 800,
    "observed4": 600,
    "predicted4": 400,
}
MAX_PROBE_CANDIDATES = 5
PORTMAP_STATE_FILE = os.environ.get(
    "P2P_PORTMAP_STATE_FILE", "/var/lib/wireguard-p2p/mapped4.json"
)


def format_endpoint(address, port):
    ip = ipaddress.ip_address(address)
    if ip.version == 6:
        return "[{}]:{}".format(ip.compressed, int(port))
    return "{}:{}".format(ip.compressed, int(port))


def parse_endpoint(value):
    if not isinstance(value, str) or ":" not in value:
        raise ValueError("invalid endpoint")
    if value.startswith("["):
        closing = value.find("]")
        if closing <= 1 or closing + 1 >= len(value) or value[closing + 1] != ":":
            raise ValueError("invalid IPv6 endpoint")
        host = value[1:closing]
        port_text = value[closing + 2:]
    else:
        host, port_text = value.rsplit(":", 1)
        if ":" in host:
            raise ValueError("IPv6 endpoint must use brackets")
    ip = ipaddress.ip_address(host)
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("invalid endpoint port")
    if ip.is_unspecified or ip.is_multicast:
        raise ValueError("invalid endpoint address")
    return format_endpoint(ip, port), ip, port


def usable_global_ipv6(address):
    ip = ipaddress.ip_address(address)
    return (
        ip.version == 6
        and ip.is_global
        and not ip.is_private
        and not ip.is_link_local
        and not ip.is_loopback
        and not ip.is_multicast
    )


def global_ipv6_addresses():
    try:
        result = subprocess.run(
            ["ip", "-6", "-j", "addr", "show"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    try:
        interfaces = json.loads(result.stdout)
    except (TypeError, ValueError):
        return []

    addresses = []
    seen = set()
    for interface in interfaces:
        if interface.get("ifname") == "lo" or interface.get("operstate") == "DOWN":
            continue
        for info in interface.get("addr_info", []):
            if info.get("family") != "inet6" or info.get("scope") != "global":
                continue
            if "tentative" in info.get("flags", []) or "deprecated" in info.get("flags", []):
                continue
            address = info.get("local", "")
            try:
                if not usable_global_ipv6(address):
                    continue
            except ValueError:
                continue
            address = ipaddress.ip_address(address).compressed
            if address not in seen:
                seen.add(address)
                addresses.append(address)
    return addresses


def mapped_candidate_from_state(listen_port, lan_ip, state_file=None, now=None):
    """Return the daemon-maintained mapping only when it matches this WG socket."""
    state_file = state_file or PORTMAP_STATE_FILE
    now = time.time() if now is None else float(now)
    try:
        with open(state_file, "r", encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, ValueError, TypeError):
        return None

    try:
        if state.get("internal_ip") != str(ipaddress.ip_address(lan_ip)):
            return None
        if int(state.get("internal_port", 0)) != int(listen_port):
            return None
        if float(state.get("expires_at", 0)) <= now + 15:
            return None
        candidate = normalize_probe_candidate(state.get("candidate"))
    except (TypeError, ValueError):
        return None
    if candidate is None or candidate["type"] != "mapped4":
        return None
    candidate["priority"] = PRIORITY["mapped4"]
    return candidate


def gather_candidates(listen_port, lan_ip=""):
    port = int(listen_port)
    if not 1 <= port <= 65535:
        return []

    candidates = []
    if lan_ip:
        try:
            ip = ipaddress.ip_address(lan_ip)
            if ip.version == 4 and ip.is_private:
                candidates.append({
                    "type": "lan4",
                    "family": "udp4",
                    "endpoint": format_endpoint(ip, port),
                    "priority": PRIORITY["lan4"],
                    "verified": False,
                })
                mapped = mapped_candidate_from_state(port, str(ip))
                if mapped:
                    candidates.append(mapped)
        except ValueError:
            pass

    for address in global_ipv6_addresses():
        candidates.append({
            "type": "host6",
            "family": "udp6",
            "endpoint": format_endpoint(address, port),
            "priority": PRIORITY["host6"],
            "verified": False,
        })

    return _dedupe_and_sort(candidates, by_endpoint=False)


def normalize_probe_candidate(value):
    if not isinstance(value, dict):
        return None
    candidate_type = value.get("type", "")
    if candidate_type not in PRIORITY:
        return None
    try:
        endpoint, address, _port = parse_endpoint(value.get("endpoint", ""))
    except (TypeError, ValueError):
        return None

    if candidate_type == "lan4" and (address.version != 4 or not address.is_private):
        return None
    if candidate_type == "host6" and not usable_global_ipv6(address):
        return None
    if candidate_type in ("mapped4", "observed4", "predicted4") and address.version != 4:
        return None

    return {
        "type": candidate_type,
        "family": "udp6" if address.version == 6 else "udp4",
        "endpoint": endpoint,
        "priority": int(value.get("priority") or PRIORITY[candidate_type]),
        "verified": bool(value.get("verified", False)),
    }


def select_probe_candidates(values, legacy_endpoint="", endpoint_type="WAN", allow_ipv6=True):
    allow_lan = str(endpoint_type).lower() in ("lan", "lan4")
    candidates = []
    for value in values or []:
        candidate = normalize_probe_candidate(value)
        if candidate is None:
            continue
        if candidate["type"] == "lan4" and not allow_lan:
            continue
        if candidate["type"] == "host6" and not allow_ipv6:
            continue
        candidates.append(candidate)

    if legacy_endpoint:
        try:
            endpoint, address, _port = parse_endpoint(legacy_endpoint)
            if allow_lan and address.version == 4 and address.is_private:
                legacy_type = "lan4"
            elif address.version == 6 and usable_global_ipv6(address) and allow_ipv6:
                legacy_type = "host6"
            elif address.version == 4:
                legacy_type = "observed4"
            else:
                legacy_type = ""
            if legacy_type:
                candidates.append({
                    "type": legacy_type,
                    "family": "udp6" if address.version == 6 else "udp4",
                    "endpoint": endpoint,
                    "priority": PRIORITY[legacy_type],
                    "verified": legacy_type == "observed4",
                })
        except (TypeError, ValueError):
            pass

    candidates = _dedupe_and_sort(candidates, by_endpoint=True)
    if len(candidates) <= MAX_PROBE_CANDIDATES:
        return candidates

    selected = list(candidates[:MAX_PROBE_CANDIDATES])
    observed = next((item for item in candidates if item["type"] == "observed4"), None)
    if observed and not any(item["endpoint"] == observed["endpoint"] for item in selected):
        selected[-1] = observed
        selected.sort(key=lambda item: (-item["priority"], item["endpoint"]))
    return selected


def candidate_signature(candidates):
    return ";".join(
        "{}|{}".format(item.get("type", ""), item.get("endpoint", ""))
        for item in candidates or []
    )


def candidate_type_for_endpoint(candidates, endpoint):
    for candidate in candidates or []:
        if candidate.get("endpoint") == endpoint:
            return candidate.get("type", "")
    return ""


def candidate_endpoint_exists(candidates, endpoint):
    return bool(candidate_type_for_endpoint(candidates, endpoint))


def _dedupe_and_sort(candidates, by_endpoint):
    result = []
    seen = set()
    for candidate in sorted(
        candidates,
        key=lambda item: (-int(item.get("priority", 0)), item.get("endpoint", "")),
    ):
        key = (
            candidate.get("endpoint")
            if by_endpoint
            else (candidate.get("type"), candidate.get("endpoint"))
        )
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(candidate)
    return result
