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
import uuid

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
from candidates import (
    candidate_endpoint_exists,
    candidate_signature,
    candidate_type_for_endpoint,
    gather_candidates,
    select_probe_candidates,
)

VERSION = "7.0.0"
INTERFACE = os.environ.get("P2P_INTERFACE", "wg0")
LISTEN_ADDRESS = os.environ["P2P_LISTEN_ADDRESS"]
LISTEN_PORT = int(os.environ.get("P2P_LISTEN_PORT", "8898"))
VPS_ADDRESS = "10.0.0.1"
STATE_FILE = os.environ.get("P2P_STATE_FILE", "/var/lib/wireguard-p2p/state.json")
LOCK_FILE = os.environ.get("P2P_LOCK_FILE", "/run/wireguard-p2p/agent.lock")
NOTIFY_KEY_FILE = os.environ.get("P2P_NOTIFY_KEY_FILE", "/etc/wireguard-p2p/notify.key")
KEEPALIVE = 25
PROBE_KEEPALIVE = 1
DIRECT_MAX_AGE = 180
CANDIDATE_PROBE_WINDOW = 2.0
PROBE_POLL_INTERVAL = 0.25
RETRY_DELAYS = (60, 120)
FAILURE_COOLDOWN = 1800
MAX_REQUEST_SIZE = 16384
NOTIFICATION_MAX_SKEW = 30
NONCE_TTL = 60
MAX_SEEN_NONCES = 4096
VERBOSE_LOG = os.environ.get("P2P_VERBOSE_LOG", "0") == "1"

STATES = {}
SEEN_NONCES = {}
STATE_LOCK = threading.Lock()
NONCE_LOCK = threading.Lock()
WG_LOCK = threading.Lock()
STOP = threading.Event()
SERVER = None


def log(message):
    if VERBOSE_LOG:
        print("[{}] {}".format(time.strftime("%m-%d %H:%M:%S"), message), flush=True)


def log_error(message):
    print(
        "[{}] {}".format(time.strftime("%m-%d %H:%M:%S"), message),
        file=sys.stderr,
        flush=True,
    )


def load_notify_key():
    with open(NOTIFY_KEY_FILE, "rb") as handle:
        key = handle.read().strip()
    if len(key) < 32:
        raise RuntimeError("notification key is too short")
    return key


NOTIFY_KEY = None


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
        raise RuntimeError(
            result.stderr.strip() or "command failed: {}".format(command[0])
        )
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
            result = {
                key: value for key, value in state.items() if isinstance(value, dict)
            }
            for item in result.values():
                item["worker_running"] = False
                item["generation"] = int(item.get("generation", 0)) + 1
                if item.get("mode") == "probe":
                    item["mode"] = "idle"
                item["started"] = 0
                item["baseline_handshake"] = 0
            return result
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
    if str(address) in (
        VPS_ADDRESS,
        LISTEN_ADDRESS,
        "10.0.0.2",
        "10.0.0.5",
        "10.0.0.8",
    ):
        raise ValueError("peer is not P2P eligible")
    return str(address)


def validate_session_id(value):
    if not isinstance(value, str):
        raise ValueError("invalid session id")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise ValueError("invalid session id")
    canonical = str(parsed)
    if value.lower() != canonical:
        raise ValueError("invalid session id")
    return canonical


def validate_session_started_ns(value):
    started = int(value)
    if started <= 0:
        raise ValueError("invalid session start")
    if started > time.time_ns() + 60_000_000_000:
        raise ValueError("session start is in the future")
    return started


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
        address = ipaddress.ip_address(
            endpoint[1:endpoint.index("]")]
            if endpoint.startswith("[")
            else endpoint.rsplit(":", 1)[0]
        )
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


def signature_payload(method, path, timestamp, nonce, body):
    return b"\n".join([
        method.upper().encode(),
        path.encode(),
        timestamp.encode(),
        nonce.encode(),
        body,
    ])


def validate_nonce(value):
    if not isinstance(value, str) or len(value) != 32:
        raise PermissionError("invalid notification nonce")
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        raise PermissionError("invalid notification nonce")
    if len(decoded) != 16:
        raise PermissionError("invalid notification nonce")
    return value.lower()


def consume_nonce(nonce, now=None):
    now = time.time() if now is None else float(now)
    with NONCE_LOCK:
        cutoff = now - NONCE_TTL
        for value, seen_at in list(SEEN_NONCES.items()):
            if seen_at < cutoff:
                del SEEN_NONCES[value]
        if nonce in SEEN_NONCES:
            raise PermissionError("replayed notification")
        if len(SEEN_NONCES) >= MAX_SEEN_NONCES:
            oldest = min(SEEN_NONCES, key=SEEN_NONCES.get)
            del SEEN_NONCES[oldest]
        SEEN_NONCES[nonce] = now


def verify_signed_notification(
    method, path, timestamp_text, nonce_text, signature, body, now=None
):
    if NOTIFY_KEY is None:
        raise RuntimeError("notification key is not loaded")
    now = time.time() if now is None else float(now)
    try:
        timestamp = int(timestamp_text)
    except (TypeError, ValueError):
        raise PermissionError("invalid notification timestamp")
    if abs(now - timestamp) > NOTIFICATION_MAX_SKEW:
        raise PermissionError("expired notification")
    nonce = validate_nonce(nonce_text)
    expected = hmac.new(
        NOTIFY_KEY,
        signature_payload(method, path, timestamp_text, nonce, body),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature or "", expected):
        raise PermissionError("invalid notification signature")
    consume_nonce(nonce, now)
    return json.loads(body.decode())


def probe_generation_current(key, generation):
    with STATE_LOCK:
        state = STATES.get(key)
        return bool(
            state
            and state.get("generation") == generation
            and state.get("worker_running")
        )


def probe_worker(key, generation):
    with STATE_LOCK:
        state = STATES.get(key)
        if (
            not state
            or state.get("generation") != generation
            or not state.get("worker_running")
        ):
            return
        candidates = list(state.get("candidates", []))
        peer_ip = state.get("ip", "")

    if not candidates or not peer_ip:
        with STATE_LOCK:
            state = STATES.get(key)
            if state and state.get("generation") == generation:
                state["worker_running"] = False
                state["mode"] = "idle"
                save_state()
        return

    for candidate in candidates:
        if not probe_generation_current(key, generation):
            return
        local = local_wg_peers().get(key, {})
        baseline = int(local.get("latest_handshake", 0) or 0)

        with STATE_LOCK:
            state = STATES.get(key)
            if (
                not state
                or state.get("generation") != generation
                or not state.get("worker_running")
            ):
                return
            try:
                wg_set(
                    "peer",
                    key,
                    "endpoint",
                    candidate["endpoint"],
                    "persistent-keepalive",
                    str(PROBE_KEEPALIVE),
                )
            except Exception as exc:
                log_error("probe candidate setup failed: {}".format(exc))
                continue
            state.update({
                "mode": "probe",
                "endpoint": candidate["endpoint"],
                "endpoint_type": candidate["type"],
                "selected_type": candidate["type"],
                "started": time.time(),
                "baseline_handshake": baseline,
            })
            save_state()

        deadline = time.monotonic() + CANDIDATE_PROBE_WINDOW
        while time.monotonic() < deadline:
            if STOP.wait(PROBE_POLL_INTERVAL):
                return
            if not probe_generation_current(key, generation):
                return
            local = local_wg_peers().get(key)
            if (
                not local
                or int(local.get("latest_handshake", 0) or 0) <= baseline
            ):
                continue

            actual_endpoint = local.get("endpoint") or candidate["endpoint"]
            with STATE_LOCK:
                state = STATES.get(key)
                if (
                    not state
                    or state.get("generation") != generation
                    or not state.get("worker_running")
                ):
                    return
                selected_type = (
                    candidate_type_for_endpoint(
                        state.get("candidates", []), actual_endpoint
                    )
                    or candidate["type"]
                )
                wg_set(
                    "peer",
                    key,
                    "allowed-ips",
                    peer_ip + "/32",
                    "endpoint",
                    actual_endpoint,
                    "persistent-keepalive",
                    str(KEEPALIVE),
                )
                state.update({
                    "mode": "direct",
                    "endpoint": actual_endpoint,
                    "endpoint_type": selected_type,
                    "selected_type": selected_type,
                    "promoted": time.time(),
                    "failures": 0,
                    "retry_after": 0,
                    "worker_running": False,
                    "started": 0,
                    "baseline_handshake": 0,
                })
                save_state()
            log(
                "P2P OK {} via {} {}".format(
                    peer_ip, selected_type, actual_endpoint
                )
            )
            return

    with STATE_LOCK:
        state = STATES.get(key)
        if (
            not state
            or state.get("generation") != generation
            or not state.get("worker_running")
        ):
            return
        try:
            wg_set("peer", key, "remove")
        except Exception:
            pass
        failures = int(state.get("failures", 0)) + 1
        delay = retry_delay(failures)
        state.update({
            "mode": "idle",
            "endpoint": "",
            "endpoint_type": "",
            "selected_type": "",
            "failures": failures,
            "retry_after": time.time() + delay,
            "worker_running": False,
            "started": 0,
            "baseline_handshake": 0,
        })
        save_state()
    log("candidate probe failed {}; retry in {}s".format(peer_ip, delay))


def launch_probe(key, generation):
    thread = threading.Thread(
        target=probe_worker,
        args=(key, generation),
        name="probe-{}".format(key[:8]),
    )
    thread.daemon = True
    thread.start()


def new_peer_state(peer_ip, session_id, session_started_ns):
    return {
        "session_id": session_id,
        "session_started_ns": session_started_ns,
        "ip": peer_ip,
        "mode": "idle",
        "endpoint": "",
        "endpoint_type": "",
        "selected_type": "",
        "candidates": [],
        "candidate_signature": "",
        "started": 0,
        "baseline_handshake": 0,
        "failures": 0,
        "retry_after": 0,
        "generation": 1,
        "worker_running": False,
    }


def handle_offer(data):
    now = time.time()
    key = validate_public_key(data["peer_key"])
    peer_ip = validate_peer_ip(data["peer_ip"])
    session_id = validate_session_id(data["session_id"])
    session_started_ns = validate_session_started_ns(data["session_started_ns"])
    advertised = validate_candidates(data.get("candidates", []))
    legacy_endpoint = (
        validate_endpoint(data["endpoint"]) if data.get("endpoint") else ""
    )
    endpoint_type = data.get("endpoint_type", "WAN")
    candidates = select_probe_candidates(
        advertised, legacy_endpoint, endpoint_type
    )
    if not candidates:
        raise ValueError("peer endpoint unavailable")
    candidate_sig = candidate_signature(candidates)
    requested_expiry = float(data.get("lease_expires", now + 120))
    lease_expires = min(max(requested_expiry, now + 30), now + 180)
    launch = False
    generation = 0

    with STATE_LOCK:
        current = local_wg_peers()
        local = current.get(key)
        state = STATES.get(key)

        if state is not None and state.get("session_id") != session_id:
            current_started = int(state.get("session_started_ns", 0) or 0)
            if current_started and session_started_ns <= current_started:
                return {
                    "ok": True,
                    "version": VERSION,
                    "protocol": 7,
                    "ignored": True,
                    "reason": "stale_session",
                }
            state["generation"] = int(state.get("generation", 0)) + 1
            state["worker_running"] = False
            if local:
                wg_set("peer", key, "remove")
                local = None
            state = new_peer_state(peer_ip, session_id, session_started_ns)
            STATES[key] = state
        elif state is None:
            state = new_peer_state(peer_ip, session_id, session_started_ns)
            STATES[key] = state
        else:
            current_started = int(state.get("session_started_ns", 0) or 0)
            if current_started and current_started != session_started_ns:
                raise ValueError("session start changed for active session")
            state["session_started_ns"] = session_started_ns

        state["session_id"] = session_id
        state["ip"] = peer_ip
        state["lease_expires"] = lease_expires
        direct = bool(
            local and peer_ip + "/32" in local.get("allowed_ips", [])
        )
        signature_changed = state.get("candidate_signature") != candidate_sig
        state["candidates"] = candidates

        if signature_changed:
            state["candidate_signature"] = candidate_sig
            state["generation"] = int(state.get("generation", 0)) + 1
            state["failures"] = 0
            state["retry_after"] = 0
            state["worker_running"] = False

            if (
                direct
                and local.get("latest_handshake")
                and now - local["latest_handshake"] <= DIRECT_MAX_AGE
                and candidate_endpoint_exists(
                    candidates, local.get("endpoint", "")
                )
            ):
                state.update({
                    "mode": "direct",
                    "endpoint": local.get("endpoint", ""),
                    "selected_type": candidate_type_for_endpoint(
                        candidates, local.get("endpoint", "")
                    ),
                })
                save_state()
            else:
                if local:
                    wg_set("peer", key, "remove")
                    local = None
                    direct = False
                state.update({
                    "mode": "idle",
                    "endpoint": "",
                    "selected_type": "",
                    "started": 0,
                })

        if direct:
            latest = int(local.get("latest_handshake", 0) or 0)
            if latest and now - latest <= DIRECT_MAX_AGE:
                state["mode"] = "direct"
                state["endpoint"] = local.get("endpoint", "")
                state["worker_running"] = False
                save_state()
            else:
                wg_set("peer", key, "remove")
                state["generation"] = int(state.get("generation", 0)) + 1
                state.update({
                    "mode": "idle",
                    "endpoint": "",
                    "selected_type": "",
                    "retry_after": 0,
                    "worker_running": False,
                })
                direct = False

        if (
            not direct
            and now >= float(state.get("retry_after", 0))
            and not state.get("worker_running")
        ):
            state["worker_running"] = True
            state["mode"] = "probe"
            generation = int(state.get("generation", 0))
            launch = True
        save_state()

    if launch:
        launch_probe(key, generation)

    lan_ip = local_ipv4()
    wg_port = listen_port()
    return {
        "ok": True,
        "version": VERSION,
        "protocol": 7,
        "session_id": session_id,
        "key": public_key(),
        "ip": LISTEN_ADDRESS,
        "lan_ip": lan_ip,
        "listen_port": wg_port,
        "candidates": gather_candidates(wg_port, lan_ip),
    }


def handle_remove(data):
    key = validate_public_key(data["peer_key"])
    peer_ip = validate_peer_ip(data["peer_ip"])
    session_id = validate_session_id(data["session_id"])
    with STATE_LOCK:
        state = STATES.get(key)
        if (
            state is None
            or state.get("session_id") != session_id
            or state.get("ip") != peer_ip
        ):
            return {
                "ok": True,
                "version": VERSION,
                "protocol": 7,
                "removed": False,
                "reason": "session_mismatch",
            }

        current = local_wg_peers()
        if key in current:
            wg_set("peer", key, "remove")
        state["generation"] = int(state.get("generation", 0)) + 1
        state["worker_running"] = False
        del STATES[key]
        save_state()
        log("removed session peer {} ({})".format(peer_ip, session_id))
    return {
        "ok": True,
        "version": VERSION,
        "protocol": 7,
        "removed": True,
    }


def monitor_once():
    now = time.time()
    launches = []
    with STATE_LOCK:
        if not STATES:
            return
        current = local_wg_peers()
        changed = False
        for key, state in list(STATES.items()):
            peer_ip = state.get("ip", "?")
            local = current.get(key)

            if now >= float(state.get("lease_expires", 0)):
                if local:
                    wg_set("peer", key, "remove")
                state["generation"] = int(state.get("generation", 0)) + 1
                state["worker_running"] = False
                del STATES[key]
                log("lease expired {}; peer removed".format(peer_ip))
                changed = True
                continue

            direct = bool(
                local and peer_ip + "/32" in local.get("allowed_ips", [])
            )
            if direct:
                latest = int(local.get("latest_handshake", 0) or 0)
                if latest and now - latest <= DIRECT_MAX_AGE:
                    state["mode"] = "direct"
                    state["endpoint"] = local.get("endpoint", "")
                    continue
                wg_set("peer", key, "remove")
                state["generation"] = int(state.get("generation", 0)) + 1
                state.update({
                    "mode": "idle",
                    "endpoint": "",
                    "selected_type": "",
                    "retry_after": 0,
                    "worker_running": False,
                })
                local = None
                changed = True
                log(
                    "fallback {} to VPS; restarting candidate probe".format(
                        peer_ip
                    )
                )

            if state.get("mode") == "probe" and state.get("worker_running"):
                continue
            if state.get("mode") == "probe":
                state["mode"] = "idle"
                changed = True

            if (
                now >= float(state.get("retry_after", 0))
                and not state.get("worker_running")
            ):
                candidates = state.get("candidates", [])
                if candidates:
                    state["worker_running"] = True
                    state["mode"] = "probe"
                    launches.append(
                        (key, int(state.get("generation", 0)))
                    )
                    changed = True

        if changed:
            save_state()

    for key, generation in launches:
        launch_probe(key, generation)


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
            if (
                any(value.endswith("/32") for value in peer["allowed_ips"])
                and key not in STATES
            ):
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
        return verify_signed_notification(
            self.command,
            self.path,
            self.headers.get("X-P2P-Timestamp", ""),
            self.headers.get("X-P2P-Nonce", ""),
            self.headers.get("X-P2P-Signature", ""),
            body,
        )

    def do_GET(self):
        if self.path != "/health":
            self.send_json(404, {"error": "not found"})
            return
        if self.client_address[0] not in (VPS_ADDRESS, LISTEN_ADDRESS):
            self.send_json(403, {"error": "forbidden"})
            return
        with STATE_LOCK:
            state_count = len(STATES)
            probing = sum(
                1 for item in STATES.values() if item.get("worker_running")
            )
        with NONCE_LOCK:
            nonce_count = len(SEEN_NONCES)
        self.send_json(200, {
            "ok": True,
            "version": VERSION,
            "protocol": 7,
            "security": "session-nonce-v1",
            "state_count": state_count,
            "probing": probing,
            "nonce_cache": nonce_count,
        })

    def do_POST(self):
        if self.path not in ("/offer", "/remove"):
            self.send_json(404, {"error": "not found"})
            return
        try:
            data = self.read_signed_json()
            result = (
                handle_offer(data)
                if self.path == "/offer"
                else handle_remove(data)
            )
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
    log(
        "event agent {} listening on {}:{}".format(
            VERSION, LISTEN_ADDRESS, LISTEN_PORT
        )
    )
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
