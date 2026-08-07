#!/usr/bin/env python3
"""Maintain a public IPv4 UDP mapping for the kernel WireGuard listen port."""

import ipaddress
import json
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time

from portmap import PortMapper

INTERFACE = os.environ.get("P2P_INTERFACE", "wg0")
STATE_FILE = os.environ.get(
    "P2P_PORTMAP_STATE_FILE", "/run/wireguard-p2p/mapped4.json"
)
POLL_INTERVAL = int(os.environ.get("P2P_PORTMAP_POLL", "15"))
STOP = threading.Event()


def local_ipv4():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        address = sock.getsockname()[0]
        ip = ipaddress.ip_address(address)
        return str(ip) if ip.version == 4 and ip.is_private else ""
    except OSError:
        return ""
    finally:
        sock.close()


def listen_port():
    try:
        result = subprocess.run(
            ["wg", "show", INTERFACE, "listen-port"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    value = result.stdout.strip()
    return int(value) if result.returncode == 0 and value.isdigit() else 0


def write_state(candidate, internal_ip, internal_port, status):
    directory = os.path.dirname(STATE_FILE)
    os.makedirs(directory, exist_ok=True)
    payload = {
        "version": 1,
        "updated_at": int(time.time()),
        "internal_ip": internal_ip,
        "internal_port": int(internal_port),
        "method": status.get("method", ""),
        "expires_at": time.time() + int(status.get("expires_in", 0)),
        "candidate": candidate,
    }
    fd, temporary = tempfile.mkstemp(prefix="mapped4-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, STATE_FILE)
    finally:
        try:
            if os.path.exists(temporary):
                os.unlink(temporary)
        except OSError:
            pass


def clear_state():
    try:
        os.unlink(STATE_FILE)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def stop_handler(_signum, _frame):
    STOP.set()


def main():
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    mapper = PortMapper()

    while not STOP.is_set():
        ip = local_ipv4()
        port = listen_port()
        candidate = None
        if ip and port:
            candidate = mapper.current_candidate(port, ip)
            if mapper.should_refresh(port, ip):
                refreshed = mapper.refresh(port, ip)
                if refreshed:
                    candidate = refreshed
            if candidate:
                write_state(candidate, ip, port, mapper.status())
            else:
                clear_state()
        else:
            clear_state()
        STOP.wait(POLL_INTERVAL)

    clear_state()


if __name__ == "__main__":
    main()
