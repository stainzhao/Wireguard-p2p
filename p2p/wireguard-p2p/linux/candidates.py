#!/usr/bin/env python3
"""Candidate discovery shared by the Linux WireGuard P2P agent."""

import ipaddress
import json
import subprocess

PRIORITY = {
    "lan4": 1000,
    "host6": 900,
    "mapped4": 800,
    "observed4": 600,
    "predicted4": 400,
}


def format_endpoint(address, port):
    ip = ipaddress.ip_address(address)
    if ip.version == 6:
        return "[{}]:{}".format(ip.compressed, int(port))
    return "{}:{}".format(ip.compressed, int(port))


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

    result = []
    seen = set()
    for candidate in sorted(candidates, key=lambda item: item["priority"], reverse=True):
        key = (candidate["type"], candidate["endpoint"])
        if key in seen:
            continue
        seen.add(key)
        result.append(candidate)
    return result
