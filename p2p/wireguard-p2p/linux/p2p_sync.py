#!/usr/bin/env python3
"""Long-running WireGuard P2P peer synchronizer."""

import fcntl
import ipaddress
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request


VERSION = "6.1.0"
API_URL = os.environ.get("P2P_API_URL", "http://10.0.0.1:8899")
INTERFACE = os.environ.get("P2P_INTERFACE", "wg0")
STATE_FILE = os.environ.get(
    "P2P_STATE_FILE", "/run/wireguard-p2p/legacy-sync-state.json"
)
LOCK_FILE = os.environ.get("P2P_LOCK_FILE", "/run/wireguard-p2p/sync.lock")
KEEPALIVE = 25
ONLINE_MAX_AGE = 180
DIRECT_MAX_AGE = 180
SYNC_INTERVAL = 15
MAX_ERROR_INTERVAL = 300
PROBE_TIMEOUT = 90
RETRY_DELAYS = (60, 120, 300)

STOP = False
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def log(message):
    print("[{}] {}".format(time.strftime("%m-%d %H:%M:%S"), message), flush=True)


def log_error(message):
    print(
        "[{}] {}".format(time.strftime("%m-%d %H:%M:%S"), message),
        file=sys.stderr,
        flush=True,
    )


class ErrorReporter:
    def __init__(self):
        self.message = ""
        self.last_report = 0

    def report(self, message):
        now = time.time()
        if message != self.message or now - self.last_report >= MAX_ERROR_INTERVAL:
            log_error("sync failed: {}".format(message))
            self.message = message
            self.last_report = now

    def recovered(self):
        if self.message:
            log("sync recovered")
        self.message = ""
        self.last_report = 0


def run(command, timeout=10):
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "command failed: {}".format(command[0]))
    return result.stdout.strip()


def wg(*arguments):
    return run(["wg"] + list(arguments))


def wg_set(*arguments):
    wg("set", INTERFACE, *arguments)


def local_wg_peers():
    output = wg("show", INTERFACE, "dump")
    peers = {}
    for line in output.splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        key, _psk, endpoint, allowed_ips, handshake, _rx, _tx, keepalive = fields[:8]
        peers[key] = {
            "endpoint": "" if endpoint == "(none)" else endpoint,
            "allowed_ips": [] if allowed_ips == "(none)" else allowed_ips.split(","),
            "latest_handshake": int(handshake or 0),
            "keepalive": int(keepalive or 0),
        }
    return peers


def load_state():
    try:
        with open(STATE_FILE) as handle:
            state = json.load(handle)
        if isinstance(state, dict):
            return {key: value for key, value in state.items() if isinstance(value, dict)}
    except (OSError, ValueError):
        pass
    return {}


def save_state(state):
    directory = os.path.dirname(STATE_FILE)
    os.makedirs(directory, exist_ok=True)
    temporary = STATE_FILE + ".tmp"
    with open(temporary, "w") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
    os.replace(temporary, STATE_FILE)


def local_ipv4():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        address = sock.getsockname()[0]
        return address if ipaddress.ip_address(address).is_private else ""
    finally:
        sock.close()


def listen_port():
    value = wg("show", INTERFACE, "listen-port")
    return int(value) if value.isdigit() else 0


def public_key():
    return wg("show", INTERFACE, "public-key")


def api_request(path, payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(API_URL + path, data=data, headers=headers)
    with OPENER.open(request, timeout=7) as response:
        return json.loads(response.read().decode())


def sync_api(address, port):
    payload = {"lan_ip": address, "listen_port": port}
    try:
        response = api_request("/sync", payload)
        peers = response.get("peers") if isinstance(response, dict) else None
        if not isinstance(peers, list):
            raise RuntimeError("invalid /sync response")
        return peers
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise

    # Backward-compatible path for rolling upgrades.
    api_request("/announce", payload)
    peers = api_request("/")
    if not isinstance(peers, list):
        raise RuntimeError("invalid legacy API response")
    return peers


def endpoint_ip(endpoint):
    try:
        return endpoint.rsplit(":", 1)[0].strip("[]")
    except (AttributeError, ValueError):
        return ""


def role(peer):
    explicit = peer.get("role")
    if explicit in ("server", "client", "relay_only"):
        return explicit
    if peer.get("ip") in ("10.0.0.2", "10.0.0.5"):
        return "server"
    if peer.get("ip") == "10.0.0.8":
        return "relay_only"
    return "client"


def eligible_pair(own_role, peer_role):
    if "relay_only" in (own_role, peer_role):
        return False
    return (own_role == "server") != (peer_role == "server")


def retry_delay(failures):
    return RETRY_DELAYS[min(max(failures, 1), len(RETRY_DELAYS)) - 1]


def start_probe(key, state, candidate, now):
    wg_set("peer", key, "endpoint", candidate,
           "persistent-keepalive", str(KEEPALIVE))
    state.update({
        "mode": "probe",
        "endpoint": candidate,
        "started": now,
        "retry_after": 0,
    })


def sync_once(states):
    now = time.time()
    own_key = public_key()
    address = local_ipv4()
    port = listen_port()
    if not own_key or not address or not port:
        raise RuntimeError("local WireGuard identity is unavailable")

    vps_peers = sync_api(address, port)
    current = local_wg_peers()
    ours = next((peer for peer in vps_peers if peer.get("key") == own_key), None)
    if not ours or not ours.get("endpoint"):
        raise RuntimeError("cannot determine our VPS-observed endpoint")

    own_role = role(ours)
    our_nat_ip = endpoint_ip(ours["endpoint"])
    active_keys = set()
    api_keys = {peer.get("key") for peer in vps_peers}
    changed = False

    for peer in vps_peers:
        key = peer.get("key", "")
        peer_ip = peer.get("ip", "")
        public_endpoint = peer.get("endpoint", "")
        peer_role = role(peer)
        if not key or key == own_key or not peer_ip:
            continue
        if not eligible_pair(own_role, peer_role):
            continue

        handshake = int(peer.get("latest_handshake") or 0)
        if not public_endpoint or not handshake or now - handshake > ONLINE_MAX_AGE:
            continue

        same_nat = endpoint_ip(public_endpoint) == our_nat_ip
        candidate = peer.get("lan_endpoint", "") if same_nat else public_endpoint
        candidate_type = "LAN" if same_nat else "WAN"
        if not candidate:
            continue

        active_keys.add(key)
        state = states.setdefault(key, {
            "ip": peer_ip,
            "mode": "idle",
            "endpoint": "",
            "started": 0,
            "failures": 0,
            "retry_after": 0,
        })
        state["ip"] = peer_ip
        local_peer = current.get(key)

        # Recover direct mode after a daemon restart by inspecting AllowedIPs.
        if local_peer and peer_ip + "/32" in local_peer["allowed_ips"]:
            state["mode"] = "direct"

        if state.get("endpoint") and state.get("endpoint") != candidate:
            state["failures"] = 0
            state["retry_after"] = 0
            changed = True

        if local_peer and state.get("mode") == "direct":
            latest = local_peer["latest_handshake"]
            if latest and now - latest <= DIRECT_MAX_AGE:
                if local_peer.get("endpoint") != candidate:
                    wg_set("peer", key, "endpoint", candidate,
                           "persistent-keepalive", str(KEEPALIVE))
                    state["endpoint"] = candidate
                    changed = True
                continue
            wg_set("peer", key, "remove")
            start_probe(key, state, candidate, now)
            log("fallback {} to VPS; probing {} {}".format(
                peer_ip, candidate_type, candidate))
            changed = True
            continue

        if local_peer and state.get("mode") == "probe":
            if local_peer.get("endpoint") != candidate:
                wg_set("peer", key, "endpoint", candidate,
                       "persistent-keepalive", str(KEEPALIVE))
                state["endpoint"] = candidate
                state["started"] = now
                changed = True
            latest = local_peer["latest_handshake"]
            if latest and latest >= state.get("started", 0) - 2:
                wg_set("peer", key, "allowed-ips", peer_ip + "/32",
                       "endpoint", candidate,
                       "persistent-keepalive", str(KEEPALIVE))
                state.update({
                    "mode": "direct",
                    "endpoint": candidate,
                    "promoted": now,
                    "failures": 0,
                    "retry_after": 0,
                })
                log("P2P OK {} via {} {}".format(
                    peer_ip, candidate_type, candidate))
                changed = True
            elif now - state.get("started", now) >= PROBE_TIMEOUT:
                wg_set("peer", key, "remove")
                failures = int(state.get("failures", 0)) + 1
                delay = retry_delay(failures)
                state.update({
                    "mode": "idle",
                    "endpoint": candidate,
                    "failures": failures,
                    "retry_after": now + delay,
                })
                log("probe timeout {}; retry in {}s".format(peer_ip, delay))
                changed = True
            continue

        if local_peer:
            wg_set("peer", key, "remove")
            current.pop(key, None)

        if (state.get("endpoint") == candidate and
                now < state.get("retry_after", 0)):
            continue

        start_probe(key, state, candidate, now)
        log("probe {} via {} {}".format(peer_ip, candidate_type, candidate))
        changed = True

    peer_by_key = {peer.get("key"): peer for peer in vps_peers}
    for key, local_peer in list(current.items()):
        peer = peer_by_key.get(key)
        if not peer or not eligible_pair(own_role, role(peer)):
            continue
        if key not in active_keys and any(
                value.endswith("/32") for value in local_peer["allowed_ips"]):
            wg_set("peer", key, "remove")
            if key in states:
                states[key]["mode"] = "idle"
            changed = True

    for key in list(states):
        if key not in api_keys:
            del states[key]
            changed = True

    return changed


def fallback_stale_directs():
    now = time.time()
    for key, peer in local_wg_peers().items():
        if not any(value.endswith("/32") for value in peer["allowed_ips"]):
            continue
        latest = peer["latest_handshake"]
        if not latest or now - latest > DIRECT_MAX_AGE:
            wg_set("peer", key, "remove")
            log("removed stale direct peer during coordinator outage")


def cleanup_legacy_interfaces():
    output = run(["ip", "-o", "link", "show"])
    for line in output.splitlines():
        fields = line.split(":", 2)
        if len(fields) < 2:
            continue
        name = fields[1].strip().split("@", 1)[0]
        if name.startswith("p2p_"):
            run(["ip", "link", "delete", name])
            log("removed legacy interface {}".format(name))


def stop_handler(_signum, _frame):
    global STOP
    STOP = True


def main():
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    reporter = ErrorReporter()
    states = load_state()
    cleanup_legacy_interfaces()
    failure_delay = SYNC_INTERVAL

    while not STOP:
        started = time.monotonic()
        try:
            changed = sync_once(states)
            if changed:
                save_state(states)
            reporter.recovered()
            failure_delay = SYNC_INTERVAL
            delay = SYNC_INTERVAL
        except Exception as exc:
            reporter.report(str(exc))
            try:
                fallback_stale_directs()
            except Exception as fallback_exc:
                reporter.report("{}; fallback check: {}".format(exc, fallback_exc))
            delay = failure_delay
            failure_delay = min(60, failure_delay * 2)

        elapsed = time.monotonic() - started
        deadline = max(0, delay - elapsed)
        end = time.monotonic() + deadline
        while not STOP and time.monotonic() < end:
            time.sleep(min(1, end - time.monotonic()))


if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOCK_FILE), exist_ok=True)
    with open(LOCK_FILE, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit(0)
        main()
