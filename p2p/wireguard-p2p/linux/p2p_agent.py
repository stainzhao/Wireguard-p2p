#!/usr/bin/env python3
"""Event-driven WireGuard P2P server agent."""

import base64
import fcntl
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
from candidates import gather_candidates

VERSION = "7.0.0-alpha.1"
INTERFACE = os.environ.get("P2P_INTERFACE", "wg0")
LISTEN_ADDRESS = os.environ["P2P_LISTEN_ADDRESS"]
LISTEN_PORT = int(os.environ.get("P2P_LISTEN_PORT", "8898"))
VPS_ADDRESS = "10.0.0.1"
STATE_FILE = os.environ.get("P2P_STATE_FILE", "/var/lib/wireguard-p2p/state.json")
LOCK_FILE = os.environ.get("P2P_LOCK_FILE", "/run/wireguard-p2p/agent.lock")
NOTIFY_KEY_FILE = os.environ.get("P2P_NOTIFY_KEY_FILE", "/etc/wireguard-p2p/notify.key")
KEEPALIVE = 25
DIRECT_MAX_AGE = 180
PROBE_TIMEOUT = 90
RETRY_DELAYS = (60, 120)
FAILURE_COOLDOWN = 1800
MAX_REQUEST_SIZE = 16384
VERBOSE_LOG = os.environ.get("P2P_VERBOSE_LOG", "0") == "1"

STATES = {}
STATE_LOCK = threading.Lock()
WG_LOCK = threading.Lock()
STOP = threading.Event()
SERVER = None


def log(message):
    if VERBOSE_LOG:
        print("[{}] {}".format(time.strftime("%m-%d %H:%M:%S"), message), flush=True)


def log_error(message):
    print("[{}] {}".format(time.strftime("%m-%d %H:%M:%S"), message), file=sys.stderr, flush=True)


def load_notify_key():
    with open(NOTIFY_KEY_FILE, "rb") as handle:
        key = handle.read().strip()
    if len(key) < 32:
        raise RuntimeError("notification key is too short")
    return key


NOTIFY_KEY = None


def run(command, timeout=10):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "command failed: {}".format(command[0]))
    return result.stdout.strip()


def wg(*arguments):
    with WG_LOCK:
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


def save_state():
    directory = os.path.dirname(STATE_FILE)
    os.makedirs(directory, exist_ok=True)
    temporary = STATE_FILE + ".tmp"
    with open(temporary, "w") as handle:
        json.dump(STATES, handle, indent=2, sort_keys=True)
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


def validate_public_key(value):
    if not isinstance(value, str):
        raise ValueError("invalid peer key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception:
        raise ValueError("invalid peer key")
    if len(decoded) != 32:
        raise ValueError("invalid peer key")
    return value


def validate_peer_ip(value):
    address = ipaddress.ip_address(value)
    if address.version != 4 or address not in ipaddress.ip_network("10.0.0.0/24"):
        raise ValueError("invalid peer overlay IP")
    if str(address) in (VPS_ADDRESS, LISTEN_ADDRESS, "10.0.0.2", "10.0.0.5", "10.0.0.8"):
        raise ValueError("peer is not P2P eligible")
    return str(address)


def validate_endpoint(value):
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
    address = ipaddress.ip_address(host)
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("invalid endpoint port")
    if address.is_unspecified or address.is_multicast:
        raise ValueError("invalid endpoint address")
    if address.version == 6:
        return "[{}]:{}".format(address.compressed, port)
    return "{}:{}".format(address.compressed, port)


def validate_candidates(values):
    if values is None:
        return []
    if not isinstance(values, list) or len(values) > 16:
        raise ValueError("invalid candidates")
    allowed_types = {"lan4", "host6", "mapped4", "observed4", "predicted4"}
    result = []
    seen = set()
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("invalid candidate")
        candidate_type = value.get("type", "")
        if candidate_type not in allowed_types:
            raise ValueError("invalid candidate type")
        endpoint = validate_endpoint(value.get("endpoint", ""))
        address = ipaddress.ip_address(endpoint[1:endpoint.index("]")] if endpoint.startswith("[") else endpoint.rsplit(":", 1)[0])
        family = "udp6" if address.version == 6 else "udp4"
        if value.get("family") not in (None, "", family):
            raise ValueError("candidate family mismatch")
        priority = int(value.get("priority", 0))
        if not 0 <= priority <= 2000:
            raise ValueError("invalid candidate priority")
        key = (candidate_type, endpoint)
        if key in seen:
            continue
        seen.add(key)
        result.append({
            "type": candidate_type,
            "family": family,
            "endpoint": endpoint,
            "priority": priority,
            "verified": bool(value.get("verified", False)),
        })
    return sorted(result, key=lambda item: item["priority"], reverse=True)


def retry_delay(failures):
    if failures <= 0:
        failures = 1
    if failures <= len(RETRY_DELAYS):
        return RETRY_DELAYS[failures - 1]
    return FAILURE_COOLDOWN


def start_probe(key, state, now):
    wg_set("peer", key, "endpoint", state["endpoint"],
           "persistent-keepalive", str(KEEPALIVE))
    state.update({"mode": "probe", "started": now, "retry_after": 0})


def handle_offer(data):
    now = time.time()
    key = validate_public_key(data["peer_key"])
    peer_ip = validate_peer_ip(data["peer_ip"])
    candidates = validate_candidates(data.get("candidates", []))
    if data.get("endpoint"):
        endpoint = validate_endpoint(data["endpoint"])
        endpoint_type = data.get("endpoint_type", "WAN")
    elif candidates:
        endpoint = candidates[0]["endpoint"]
        endpoint_type = candidates[0]["type"]
    else:
        raise ValueError("peer endpoint unavailable")
    requested_expiry = float(data.get("lease_expires", now + 120))
    lease_expires = min(max(requested_expiry, now + 30), now + 180)

    with STATE_LOCK:
        current = local_wg_peers()
        state = STATES.get(key)
        changed_endpoint = state is None or state.get("endpoint") != endpoint
        if state is None:
            state = {
                "ip": peer_ip,
                "mode": "idle",
                "endpoint": endpoint,
                "endpoint_type": endpoint_type,
                "candidates": candidates,
                "started": 0,
                "failures": 0,
                "retry_after": 0,
            }
            STATES[key] = state
        state["ip"] = peer_ip
        state["endpoint_type"] = endpoint_type
        state["candidates"] = candidates
        state["lease_expires"] = lease_expires

        if changed_endpoint:
            if key in current:
                wg_set("peer", key, "remove")
            state.update({"endpoint": endpoint, "mode": "idle", "failures": 0, "retry_after": 0})
            start_probe(key, state, now)
            log("offer {} via {} {}; probing".format(peer_ip, endpoint_type, endpoint))
        elif key not in current and now >= state.get("retry_after", 0):
            start_probe(key, state, now)
            log("restored probe {} via {}".format(peer_ip, endpoint))
        save_state()

    lan_ip = local_ipv4()
    wg_port = listen_port()
    return {
        "ok": True,
        "version": VERSION,
        "protocol": 7,
        "key": public_key(),
        "ip": LISTEN_ADDRESS,
        "lan_ip": lan_ip,
        "listen_port": wg_port,
        "candidates": gather_candidates(wg_port, lan_ip),
    }


def handle_remove(data):
    key = validate_public_key(data["peer_key"])
    peer_ip = validate_peer_ip(data["peer_ip"])
    with STATE_LOCK:
        current = local_wg_peers()
        if key in current:
            wg_set("peer", key, "remove")
        if key in STATES:
            del STATES[key]
            save_state()
            log("removed expired peer {}".format(peer_ip))
    return {"ok": True, "version": VERSION}


def monitor_once():
    now = time.time()
    with STATE_LOCK:
        if not STATES:
            return
        current = local_wg_peers()
        changed = False
        for key, state in list(STATES.items()):
            peer_ip = state.get("ip", "?")
            local = current.get(key)

            if now >= state.get("lease_expires", 0):
                if local:
                    wg_set("peer", key, "remove")
                del STATES[key]
                log("lease expired {}; peer removed".format(peer_ip))
                changed = True
                continue

            mode = state.get("mode", "idle")
            if local and peer_ip + "/32" in local["allowed_ips"]:
                mode = "direct"
                state["mode"] = mode

            if mode == "direct":
                latest = local["latest_handshake"] if local else 0
                if latest and now - latest <= DIRECT_MAX_AGE:
                    continue
                if local:
                    wg_set("peer", key, "remove")
                start_probe(key, state, now)
                log("fallback {} to VPS; probing {}".format(peer_ip, state["endpoint"]))
                changed = True
                continue

            if mode == "probe":
                if not local:
                    start_probe(key, state, now)
                    changed = True
                    continue
                latest = local["latest_handshake"]
                if latest and latest >= state.get("started", 0) - 2:
                    wg_set("peer", key, "allowed-ips", peer_ip + "/32",
                           "endpoint", state["endpoint"],
                           "persistent-keepalive", str(KEEPALIVE))
                    state.update({"mode": "direct", "promoted": now, "failures": 0, "retry_after": 0})
                    log("P2P OK {} via {} {}".format(peer_ip, state.get("endpoint_type", "WAN"), state["endpoint"]))
                    changed = True
                elif now - state.get("started", now) >= PROBE_TIMEOUT:
                    wg_set("peer", key, "remove")
                    failures = int(state.get("failures", 0)) + 1
                    delay = retry_delay(failures)
                    state.update({"mode": "idle", "failures": failures, "retry_after": now + delay})
                    log("probe timeout {}; retry in {}s".format(peer_ip, delay))
                    changed = True
                continue

            if now >= state.get("retry_after", 0):
                start_probe(key, state, now)
                log("retry probe {} via {}".format(peer_ip, state["endpoint"]))
                changed = True

        if changed:
            save_state()


def monitor_loop():
    last_error = ""
    last_error_time = 0
    while not STOP.wait(5):
        try:
            monitor_once()
            if last_error:
                log("monitor recovered")
            last_error = ""
        except Exception as exc:
            message = str(exc)
            now = time.time()
            if message != last_error or now - last_error_time >= 300:
                log_error("monitor failed: {}".format(message))
                last_error = message
                last_error_time = now


def cleanup_orphans():
    with STATE_LOCK:
        current = local_wg_peers()
        for key, peer in current.items():
            if any(value.endswith("/32") for value in peer["allowed_ips"]) and key not in STATES:
                wg_set("peer", key, "remove")
                log("removed orphan dynamic peer")


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "WireGuardP2PAgent/{}".format(VERSION)
    sys_version = ""

    def setup(self):
        http.server.BaseHTTPRequestHandler.setup(self)
        self.connection.settimeout(10)

    def send_json(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_signed_json(self):
        if self.client_address[0] != VPS_ADDRESS:
            raise PermissionError("request is not from VPS")
        size = int(self.headers.get("Content-Length", "0"))
        if size <= 0 or size > MAX_REQUEST_SIZE:
            raise ValueError("invalid request size")
        body = self.rfile.read(size)
        timestamp_text = self.headers.get("X-P2P-Timestamp", "")
        signature = self.headers.get("X-P2P-Signature", "")
        timestamp = int(timestamp_text)
        if abs(time.time() - timestamp) > 30:
            raise PermissionError("expired notification")
        expected = hmac.new(NOTIFY_KEY, timestamp_text.encode() + b"\n" + body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise PermissionError("invalid notification signature")
        return json.loads(body.decode())

    def do_GET(self):
        if self.path != "/health":
            self.send_json(404, {"error": "not found"})
            return
        if self.client_address[0] not in (VPS_ADDRESS, LISTEN_ADDRESS):
            self.send_json(403, {"error": "forbidden"})
            return
        with STATE_LOCK:
            state_count = len(STATES)
        self.send_json(200, {"ok": True, "version": VERSION, "state_count": state_count})

    def do_POST(self):
        if self.path not in ("/offer", "/remove"):
            self.send_json(404, {"error": "not found"})
            return
        try:
            data = self.read_signed_json()
            result = handle_offer(data) if self.path == "/offer" else handle_remove(data)
            self.send_json(200, result)
        except PermissionError as exc:
            self.send_json(403, {"error": str(exc)})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self.send_json(400, {"error": str(exc)})
        except Exception as exc:
            log_error("request failed: {}".format(exc))
            self.send_json(503, {"error": "agent unavailable"})

    def log_message(self, _fmt, *_args):
        pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 8


def stop_handler(_signum, _frame):
    STOP.set()
    if SERVER is not None:
        threading.Thread(target=SERVER.shutdown, name="shutdown").start()


def main():
    global NOTIFY_KEY, STATES, SERVER
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    NOTIFY_KEY = load_notify_key()
    STATES = load_state()
    cleanup_orphans()
    monitor = threading.Thread(target=monitor_loop, name="peer-monitor")
    monitor.daemon = True
    monitor.start()
    SERVER = ThreadingHTTPServer((LISTEN_ADDRESS, LISTEN_PORT), Handler)
    log("event agent {} listening on {}:{}".format(VERSION, LISTEN_ADDRESS, LISTEN_PORT))
    try:
        SERVER.serve_forever()
    finally:
        STOP.set()
        SERVER.server_close()


if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOCK_FILE), exist_ok=True)
    with open(LOCK_FILE, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit(0)
        main()
