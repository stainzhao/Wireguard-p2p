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
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
from candidates import (
    candidate_endpoint_exists,
    candidate_signature,
    candidate_type_for_endpoint,
    gather_candidates,
    global_ipv6_addresses,
    observed_type_for_endpoint,
    reflexive6_candidate,
    select_probe_candidates,
    usable_global_ipv6,
)


def time_ns():
    native = getattr(time, "time_ns", None)
    if native is not None:
        return native()
    return int(time.time() * 1000000000)

VERSION = "7.13.0"
INSTANCE_ID = uuid.uuid4().hex
INTERFACE = os.environ.get("P2P_INTERFACE", "wg0")
LISTEN_ADDRESS = os.environ["P2P_LISTEN_ADDRESS"]
LISTEN_PORT = int(os.environ.get("P2P_LISTEN_PORT", "8898"))
VPS_ADDRESS = "10.0.0.1"
COORDINATOR_SYNC_URL = "http://10.0.0.1:8899/sync"
INITIATOR_SYNC_INTERVAL = 10
INITIATOR_ONLINE_MAX_AGE = 180
STATE_FILE = os.environ.get("P2P_STATE_FILE", "/run/wireguard-p2p/state.json")
LOCK_FILE = os.environ.get("P2P_LOCK_FILE", "/run/wireguard-p2p/agent.lock")
NOTIFY_KEY_FILE = os.environ.get("P2P_NOTIFY_KEY_FILE", "/etc/wireguard-p2p/notify.key")
KEEPALIVE = 25
PROBE_KEEPALIVE = 1
DIRECT_MAX_AGE = 180
CANDIDATE_PROBE_WINDOW = 2.0
PROBE_POLL_INTERVAL = 0.25
CONFIRMATION_REKEY_DELAY = 3.0
CONFIRMATION_REKEY_WINDOW = 8.0
SIMULTANEOUS_IPV6_WINDOW = 8.0
SIMULTANEOUS_IPV4_WINDOW = 8.0
PREDICTED_IPV4_WINDOW = 1.5
ACTIVE_MONITOR_INTERVAL = 5
DIRECT_MONITOR_INTERVAL = 20
IDLE_MONITOR_INTERVAL = 60
REFLEXIVE6_TTL = 1800
REFLEXIVE6_REFRESH_INTERVAL = 600
REFLEXIVE6_DISCOVERY_TIMEOUT = 1.5
REFLEXIVE6_DISCOVERY_URLS = (
    "https://api6.ipify.org",
    "https://6.ident.me",
    "https://ipv6.icanhazip.com",
)
RETRY_DELAYS = (3, 10, 30, 60)
FAILURE_COOLDOWN = 300
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
REFLEXIVE6_LOCK = threading.Lock()
REFLEXIVE6_ADDRESS = ""
REFLEXIVE6_UPDATED = 0
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
    if str(address) in (VPS_ADDRESS, LISTEN_ADDRESS):
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
    if started > time_ns() + 60_000_000_000:
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


def endpoint_address(value):
    try:
        endpoint = validate_endpoint(value)
    except (TypeError, ValueError):
        return ""
    if endpoint.startswith("["):
        return endpoint[1:endpoint.index("]")]
    return endpoint.rsplit(":", 1)[0]


def server_initiator_owns_pair(local_ip, remote_ip):
    try:
        local = ipaddress.ip_address(local_ip)
        remote = ipaddress.ip_address(remote_ip)
    except ValueError:
        return False
    return (
        local.version == 4
        and remote.version == 4
        and local != remote
        and int(local) < int(remote)
    )


def validate_candidates(values):
    if values is None:
        return []
    if not isinstance(values, list) or len(values) > 16:
        raise ValueError("invalid candidates")
    allowed_types = {"lan4", "host6", "reflexive6", "mapped4", "observed4", "predicted4"}
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


def discover_reflexive_ipv6():
    # Native host6 is already the preferred path; reflexive discovery is only
    # useful for nodes whose local IPv6 is special-use/NAT66 translated.
    if global_ipv6_addresses():
        return ""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for url in REFLEXIVE6_DISCOVERY_URLS:
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "wireguard-p2p/{}".format(VERSION)},
            )
            with opener.open(request, timeout=REFLEXIVE6_DISCOVERY_TIMEOUT) as response:
                value = response.read(128).decode("ascii", "strict").strip()
            if usable_global_ipv6(value):
                return str(ipaddress.ip_address(value))
        except Exception:
            continue
    return ""


def refresh_reflexive_ipv6():
    global REFLEXIVE6_ADDRESS, REFLEXIVE6_UPDATED
    now = time.time()
    address = discover_reflexive_ipv6()
    with REFLEXIVE6_LOCK:
        if address:
            REFLEXIVE6_ADDRESS = address
            REFLEXIVE6_UPDATED = now
        elif now - REFLEXIVE6_UPDATED > REFLEXIVE6_TTL:
            REFLEXIVE6_ADDRESS = ""
            REFLEXIVE6_UPDATED = 0


def current_reflexive6_candidate(listen_port_value):
    now = time.time()
    with REFLEXIVE6_LOCK:
        address = REFLEXIVE6_ADDRESS
        updated = REFLEXIVE6_UPDATED
    if not address or now - updated > REFLEXIVE6_TTL:
        return None
    return reflexive6_candidate(address, listen_port_value)


def local_candidate_snapshot():
    lan_ip = local_ipv4()
    wg_port = listen_port()
    if not lan_ip or not wg_port:
        raise RuntimeError("local WireGuard candidate is unavailable")
    local_candidates = gather_candidates(wg_port, lan_ip)
    reflexive = current_reflexive6_candidate(wg_port)
    if reflexive:
        local_candidates.append(reflexive)
        local_candidates.sort(
            key=lambda item: (
                -int(item.get("priority", 0)), item.get("endpoint", "")
            )
        )
    return lan_ip, wg_port, local_candidates


def coordinator_sync_once():
    lan_ip, wg_port, local_candidates = local_candidate_snapshot()
    payload = json.dumps({
        "protocol": 7,
        "instance_id": INSTANCE_ID,
        "lan_ip": lan_ip,
        "listen_port": wg_port,
        "candidates": local_candidates,
    }, separators=(",", ":")).encode()
    request = urllib.request.Request(
        COORDINATOR_SYNC_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=5) as response:
        result = json.loads(response.read().decode())
    if int(result.get("protocol", 0) or 0) != 7:
        raise RuntimeError("Coordinator protocol mismatch")
    return result


def eligible_initiator_server(peer, now=None):
    if not isinstance(peer, dict) or peer.get("role") != "server":
        return False
    if not peer.get("key") or not peer.get("ip") or not peer.get("endpoint"):
        return False
    if not server_initiator_owns_pair(LISTEN_ADDRESS, peer.get("ip", "")):
        return False
    now = time.time() if now is None else float(now)
    latest = int(peer.get("latest_handshake", 0) or 0)
    return bool(latest and now - latest <= INITIATOR_ONLINE_MAX_AGE)


def cleanup_initiator_states(active_keys):
    active_keys = set(active_keys or ())
    with STATE_LOCK:
        current = local_wg_peers()
        changed = False
        for key, state in list(STATES.items()):
            if state.get("controller") != "initiator" or key in active_keys:
                continue
            state["generation"] = int(state.get("generation", 0)) + 1
            state["worker_running"] = False
            if key in current:
                try:
                    wg_set("peer", key, "remove")
                except Exception as exc:
                    log_error("initiator peer cleanup failed: {}".format(exc))
            del STATES[key]
            changed = True
        if changed:
            save_state()


def server_initiator_once():
    result = coordinator_sync_once()
    peers = result.get("peers", [])
    if not isinstance(peers, list):
        raise RuntimeError("Coordinator returned invalid peers")
    ours = next(
        (peer for peer in peers if peer.get("ip") == LISTEN_ADDRESS), None
    )
    if ours is None or ours.get("role") != "server":
        cleanup_initiator_states(set())
        return

    session_id = result.get("session_id", "")
    session_started_ns = int(result.get("session_started_ns", 0) or 0)
    if not session_id or session_started_ns <= 0:
        cleanup_initiator_states(set())
        return

    our_wan = endpoint_address(ours.get("endpoint", ""))
    now = time.time()
    active_keys = set()
    for peer in peers:
        if not eligible_initiator_server(peer, now):
            continue
        key = peer.get("key")
        active_keys.add(key)
        peer_wan = endpoint_address(peer.get("endpoint", ""))
        same_nat = bool(our_wan and peer_wan and our_wan == peer_wan)
        lan_endpoint = peer.get("lan_endpoint", "")
        endpoint_type = "LAN" if same_nat and lan_endpoint else "WAN"
        endpoint = lan_endpoint if endpoint_type == "LAN" else peer.get("endpoint", "")
        try:
            handle_offer({
                "peer_key": key,
                "peer_ip": peer.get("ip", ""),
                "peer_instance_id": peer.get("instance_id", ""),
                "session_id": session_id,
                "session_started_ns": session_started_ns,
                "endpoint": endpoint,
                "endpoint_type": endpoint_type,
                "candidates": peer.get("candidates", []),
                "lease_expires": int(now) + 180,
            }, controller="initiator")
        except Exception as exc:
            log_error(
                "server initiator reconcile failed for {}: {}".format(
                    peer.get("ip", "?"), exc
                )
            )
    cleanup_initiator_states(active_keys)


def coordinator_disconnect():
    request = urllib.request.Request(
        "http://10.0.0.1:8899/disconnect",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=3) as response:
        response.read()


def server_initiator_loop():
    last_error = ""
    last_error_time = 0
    while not STOP.is_set():
        try:
            server_initiator_once()
            if last_error:
                log("server initiator recovered")
            last_error = ""
        except Exception as exc:
            message = str(exc)
            now = time.time()
            if message != last_error or now - last_error_time >= 300:
                log_error("server initiator sync failed: {}".format(message))
                last_error = message
                last_error_time = now
        if STOP.wait(INITIATOR_SYNC_INTERVAL):
            return


def reflexive6_loop():
    while not STOP.wait(REFLEXIVE6_REFRESH_INTERVAL):
        refresh_reflexive_ipv6()


def direct_peer_healthy(local, peer_ip, now=None):
    if not local or not peer_ip:
        return False
    now = time.time() if now is None else float(now)
    latest = int(local.get("latest_handshake", 0) or 0)
    return bool(
        peer_ip + "/32" in local.get("allowed_ips", [])
        and latest
        and now - latest <= DIRECT_MAX_AGE
    )


def candidate_probe_window(candidate):
    if not isinstance(candidate, dict):
        return CANDIDATE_PROBE_WINDOW
    candidate_type = candidate.get("type")
    if candidate_type == "host6" and (
        int(candidate.get("priority", 0) or 0) > 900
        or not global_ipv6_addresses()
    ):
        return SIMULTANEOUS_IPV6_WINDOW
    if candidate_type == "observed4":
        return SIMULTANEOUS_IPV4_WINDOW
    if candidate_type == "predicted4":
        return PREDICTED_IPV4_WINDOW
    return CANDIDATE_PROBE_WINDOW

def should_confirmation_rekey(candidate):
    return bool(
        isinstance(candidate, dict)
        and candidate.get("type") == "host6"
        and not global_ipv6_addresses()
    )


def trigger_overlay_packet(peer_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(b"\x00", (peer_ip, 9))
    except OSError:
        pass
    finally:
        sock.close()


def confirmation_rekey_worker(key, generation, peer_ip, endpoint):
    if STOP.wait(CONFIRMATION_REKEY_DELAY):
        return

    with STATE_LOCK:
        state = STATES.get(key)
        if (
            not state
            or state.get("generation") != generation
            or state.get("mode") != "direct"
            or state.get("endpoint") != endpoint
        ):
            return
        state["mode"] = "confirm6"
        state["worker_running"] = True
        state["started"] = time.time()
        state["baseline_handshake"] = 0
        try:
            wg_set("peer", key, "remove")
            wg_set(
                "peer",
                key,
                "allowed-ips",
                peer_ip + "/32",
                "endpoint",
                endpoint,
                "persistent-keepalive",
                str(PROBE_KEEPALIVE),
            )
        except Exception as exc:
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
            log_error("IPv6 confirmation rekey setup failed: {}".format(exc))
            return
        save_state()

    # Recreating the peer clears the old WireGuard session.  A packet to the
    # overlay address then forces a fresh authenticated handshake immediately.
    trigger_overlay_packet(peer_ip)

    deadline = time.monotonic() + CONFIRMATION_REKEY_WINDOW
    while time.monotonic() < deadline:
        if STOP.wait(PROBE_POLL_INTERVAL):
            return
        local = local_wg_peers().get(key)
        latest = int((local or {}).get("latest_handshake", 0) or 0)
        if not latest or time.time() - latest > 5:
            continue
        actual_endpoint = (local or {}).get("endpoint") or endpoint
        with STATE_LOCK:
            state = STATES.get(key)
            if (
                not state
                or state.get("generation") != generation
                or state.get("mode") != "confirm6"
                or not state.get("worker_running")
            ):
                return
            try:
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
            except Exception as exc:
                log_error("IPv6 confirmation rekey finalize failed: {}".format(exc))
                return
            state.update({
                "mode": "direct",
                "endpoint": actual_endpoint,
                "endpoint_type": "host6",
                "selected_type": "host6",
                "failures": 0,
                "retry_after": 0,
                "worker_running": False,
                "started": 0,
                "baseline_handshake": 0,
            })
            save_state()
        log("IPv6 confirmation rekey OK {} via host6 {}".format(peer_ip, actual_endpoint))
        return

    with STATE_LOCK:
        state = STATES.get(key)
        if (
            not state
            or state.get("generation") != generation
            or state.get("mode") != "confirm6"
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
    log("IPv6 confirmation rekey failed {}; fallback to VPS; retry in {}s".format(peer_ip, delay))


def launch_confirmation_rekey(key, generation, peer_ip, endpoint):
    thread = threading.Thread(
        target=confirmation_rekey_worker,
        args=(key, generation, peer_ip, endpoint),
        name="confirm6-{}".format(key[:8]),
    )
    thread.daemon = True
    thread.start()


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
        if candidate.get("type") == "host6":
            if int(candidate.get("priority", 0) or 0) > 900:
                log("Preferred IPv6 punch {} via {}".format(peer_ip, candidate.get("endpoint", "")))
            else:
                log("Backup IPv6 probe {} via {}".format(peer_ip, candidate.get("endpoint", "")))
        elif candidate.get("type") == "observed4":
            log("Simultaneous IPv4 punch {} via {}".format(peer_ip, candidate.get("endpoint", "")))
        elif candidate.get("type") == "predicted4":
            log("Bounded IPv4 port prediction {} via {}".format(peer_ip, candidate.get("endpoint", "")))
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

        deadline = time.monotonic() + candidate_probe_window(candidate)
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
                    or observed_type_for_endpoint(actual_endpoint)
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
            if should_confirmation_rekey(candidate):
                launch_confirmation_rekey(
                    key, generation, peer_ip, actual_endpoint
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


def new_peer_state(peer_ip, session_id, session_started_ns, controller="responder", peer_instance_id=""):
    return {
        "controller": controller,
        "session_id": session_id,
        "session_started_ns": session_started_ns,
        "peer_instance_id": peer_instance_id,
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
        "control_expired": False,
    }


def handle_offer(data, controller="responder"):
    now = time.time()
    key = validate_public_key(data["peer_key"])
    peer_ip = validate_peer_ip(data["peer_ip"])
    session_id = validate_session_id(data["session_id"])
    session_started_ns = validate_session_started_ns(data["session_started_ns"])
    peer_instance_id = ""
    if data.get("peer_instance_id"):
        try:
            peer_instance_id = uuid.UUID(str(data.get("peer_instance_id"))).hex
        except (ValueError, AttributeError, TypeError):
            raise ValueError("invalid peer instance id")
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
        instance_changed = bool(
            state is not None
            and peer_instance_id
            and state.get("peer_instance_id", "") != peer_instance_id
        )

        if instance_changed:
            state["generation"] = int(state.get("generation", 0)) + 1
            state["worker_running"] = False
            if local:
                wg_set("peer", key, "remove")
                local = None
            state = new_peer_state(
                peer_ip, session_id, session_started_ns, controller, peer_instance_id
            )
            STATES[key] = state
            log("peer instance changed {}; retrying P2P now".format(peer_ip))
        elif state is not None and state.get("session_id") != session_id:
            current_started = int(state.get("session_started_ns", 0) or 0)
            if current_started and session_started_ns <= current_started:
                return {
                    "ok": True,
                    "version": VERSION,
                    "protocol": 7,
                    "ignored": True,
                    "reason": "stale_session",
                }
            preserve_direct = direct_peer_healthy(local, peer_ip, now)
            state["generation"] = int(state.get("generation", 0)) + 1
            state["worker_running"] = False
            if not preserve_direct:
                if local:
                    wg_set("peer", key, "remove")
                    local = None
                state = new_peer_state(peer_ip, session_id, session_started_ns, controller, peer_instance_id)
                STATES[key] = state
            else:
                state["mode"] = "direct"
                state["endpoint"] = local.get("endpoint", "")
                state["failures"] = 0
                state["retry_after"] = 0
        elif state is None:
            state = new_peer_state(peer_ip, session_id, session_started_ns, controller, peer_instance_id)
            STATES[key] = state
        else:
            current_started = int(state.get("session_started_ns", 0) or 0)
            if current_started and current_started != session_started_ns:
                raise ValueError("session start changed for active session")
            state["session_started_ns"] = session_started_ns

        state["session_id"] = session_id
        state["session_started_ns"] = session_started_ns
        if peer_instance_id:
            state["peer_instance_id"] = peer_instance_id
        state["ip"] = peer_ip
        state["controller"] = controller
        state["lease_expires"] = lease_expires
        state["control_expired"] = False
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
                    "selected_type": (
                        candidate_type_for_endpoint(
                            candidates, local.get("endpoint", "")
                        )
                        or observed_type_for_endpoint(local.get("endpoint", ""))
                        or state.get("selected_type", "")
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
                if not state.get("selected_type"):
                    state["selected_type"] = (
                        candidate_type_for_endpoint(
                            candidates, local.get("endpoint", "")
                        )
                        or observed_type_for_endpoint(local.get("endpoint", ""))
                    )
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
    local_candidates = gather_candidates(wg_port, lan_ip)
    reflexive = current_reflexive6_candidate(wg_port)
    if reflexive:
        local_candidates.append(reflexive)
        local_candidates.sort(key=lambda item: (-int(item.get("priority", 0)), item.get("endpoint", "")))
    return {
        "ok": True,
        "version": VERSION,
        "protocol": 7,
        "session_id": session_id,
        "instance_id": INSTANCE_ID,
        "key": public_key(),
        "ip": LISTEN_ADDRESS,
        "lan_ip": lan_ip,
        "listen_port": wg_port,
        "candidates": local_candidates,
    }


def handle_remove(data):
    key = validate_public_key(data["peer_key"])
    peer_ip = validate_peer_ip(data["peer_ip"])
    session_id = validate_session_id(data["session_id"])
    remove_reason = str(data.get("reason", "disconnect"))
    if remove_reason not in ("disconnect", "superseded", "expired"):
        raise ValueError("invalid remove reason")
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
        local = current.get(key)
        if remove_reason == "expired" and direct_peer_healthy(local, peer_ip):
            state["control_expired"] = True
            state["lease_expires"] = 0
            state["worker_running"] = False
            state["mode"] = "direct"
            state["endpoint"] = local.get("endpoint", "")
            if not state.get("selected_type"):
                state["selected_type"] = observed_type_for_endpoint(
                    local.get("endpoint", "")
                )
            save_state()
            log("control session expired {}; healthy direct preserved".format(peer_ip))
            return {
                "ok": True,
                "version": VERSION,
                "protocol": 7,
                "removed": False,
                "preserved_direct": True,
                "reason": "control_expired",
            }

        if key in current:
            wg_set("peer", key, "remove")
        state["generation"] = int(state.get("generation", 0)) + 1
        state["worker_running"] = False
        del STATES[key]
        save_state()
        log("removed session peer {} ({}) reason={}".format(
            peer_ip, session_id, remove_reason
        ))
    return {
        "ok": True,
        "version": VERSION,
        "protocol": 7,
        "removed": True,
        "reason": remove_reason,
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

            lease_expires = float(state.get("lease_expires", 0) or 0)
            if (
                not state.get("control_expired")
                and lease_expires
                and now >= lease_expires
            ):
                if direct_peer_healthy(local, peer_ip, now):
                    state["control_expired"] = True
                    state["lease_expires"] = 0
                    state["worker_running"] = False
                    state["mode"] = "direct"
                    state["endpoint"] = local.get("endpoint", "")
                    changed = True
                    log("control lease expired {}; healthy direct preserved".format(peer_ip))
                else:
                    if local:
                        wg_set("peer", key, "remove")
                    state["generation"] = int(state.get("generation", 0)) + 1
                    state["worker_running"] = False
                    del STATES[key]
                    log("lease expired {}; peer removed".format(peer_ip))
                    changed = True
                    continue

            if state.get("mode") == "confirm6" and state.get("worker_running"):
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
                if state.get("control_expired"):
                    state["worker_running"] = False
                    del STATES[key]
                    changed = True
                    log(
                        "fallback {} to VPS; direct stale while coordinator unavailable".format(
                            peer_ip
                        )
                    )
                    continue
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


def monitor_interval():
    with STATE_LOCK:
        if not STATES:
            return IDLE_MONITOR_INTERVAL
        if all(
            item.get("mode") == "direct" and not item.get("worker_running")
            for item in STATES.values()
        ):
            return DIRECT_MONITOR_INTERVAL
    return ACTIVE_MONITOR_INTERVAL


def monitor_loop():
    last_error = ""
    last_error_time = 0
    while not STOP.wait(monitor_interval()):
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
        with REFLEXIVE6_LOCK:
            reflexive6_address = REFLEXIVE6_ADDRESS
            reflexive6_updated = REFLEXIVE6_UPDATED
        reflexive6_age = (
            max(0, int(time.time() - reflexive6_updated))
            if reflexive6_address and reflexive6_updated
            else None
        )
        self.send_json(200, {
            "ok": True,
            "version": VERSION,
            "protocol": 7,
            "security": "session-nonce-v1",
            "state_count": state_count,
            "probing": probing,
            "nonce_cache": nonce_count,
            "reflexive6": reflexive6_address,
            "reflexive6_age": reflexive6_age,
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
    refresh_reflexive_ipv6()
    reflexive_monitor = threading.Thread(target=reflexive6_loop, name="reflexive6-monitor")
    reflexive_monitor.daemon = True
    reflexive_monitor.start()
    monitor = threading.Thread(target=monitor_loop, name="peer-monitor")
    monitor.daemon = True
    monitor.start()
    SERVER = ThreadingHTTPServer((LISTEN_ADDRESS, LISTEN_PORT), Handler)
    initiator = threading.Thread(
        target=server_initiator_loop, name="server-initiator"
    )
    initiator.daemon = True
    initiator.start()
    log(
        "event agent {} listening on {}:{}".format(
            VERSION, LISTEN_ADDRESS, LISTEN_PORT
        )
    )
    try:
        SERVER.serve_forever()
    finally:
        STOP.set()
        try:
            coordinator_disconnect()
        except Exception:
            pass
        try:
            cleanup_initiator_states(set())
        except Exception:
            pass
        SERVER.server_close()


if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOCK_FILE), exist_ok=True)
    with open(LOCK_FILE, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit(0)
        main()
