#!/usr/bin/env python3
"""Event-driven WireGuard P2P coordinator, reachable only through wg0."""

import concurrent.futures
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import secrets
import socketserver
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid

VERSION = "7.10.1"
LISTEN_ADDRESS = "10.0.0.1"
LISTEN_PORT = 8899
AGENT_PORT = 8898
ANNOUNCE_TTL = 300
SESSION_TTL = 180
OFFER_REFRESH = 120
PUSH_TIMEOUT = 2
MAX_REQUEST_SIZE = 16384
MAX_CANDIDATES = 16
NOTIFY_KEY_FILE = os.environ.get("P2P_NOTIFY_KEY_FILE", "/etc/wireguard-p2p/notify.key")
UPDATE_DIR = os.environ.get("P2P_UPDATE_DIR", "/var/lib/wireguard-p2p/updates/current")
UPDATE_MAX_FILE_SIZE = 128 * 1024 * 1024
SERVER_REGISTRY_FILE = os.environ.get("P2P_SERVER_REGISTRY_FILE", "/etc/wireguard-p2p/servers.conf")
RELAY_ONLY_REGISTRY_FILE = os.environ.get("P2P_RELAY_ONLY_REGISTRY_FILE", "/etc/wireguard-p2p/relay-only.conf")
OVERLAY_NETWORK = ipaddress.ip_network("10.0.0.0/24")

LAN_CANDIDATES = {}
NODE_CANDIDATES = {}
SESSIONS = {}
SERVER_PUSH_STATUS = {}
STATE_LOCK = threading.Lock()
COORDINATE_LOCK = threading.Lock()
WG_QUERY_SLOTS = threading.BoundedSemaphore(4)
STOP = threading.Event()


def load_notify_key():
    with open(NOTIFY_KEY_FILE, "rb") as handle:
        key = handle.read().strip()
    if len(key) < 32:
        raise RuntimeError("notification key is too short")
    return key


NOTIFY_KEY = None


def log(message):
    print("[{}] {}".format(time.strftime("%m-%d %H:%M:%S"), message), flush=True)


def record_push_result(server_ip, ok, error=""):
    now = time.time()
    message_to_log = ""
    with STATE_LOCK:
        status = SERVER_PUSH_STATUS.setdefault(server_ip, new_push_status())
        previous_failures = int(status.get("consecutive_failures", 0))
        if ok:
            status.update({
                "ok": True,
                "last_success": int(now),
                "last_error_message": "",
                "consecutive_failures": 0,
            })
            if previous_failures:
                message_to_log = "push to {} recovered after {} failure(s)".format(
                    server_ip, previous_failures
                )
        else:
            error = str(error)[:160]
            status.update({
                "ok": False,
                "last_error": int(now),
                "last_error_message": error,
                "consecutive_failures": previous_failures + 1,
            })
            if previous_failures == 0 or now - status.get("last_error_log", 0) >= 300:
                status["last_error_log"] = now
                message_to_log = "push to {} failed: {}".format(server_ip, error)
    if message_to_log:
        log(message_to_log)


def load_role_registry(filename):
    try:
        with open(filename, "r", encoding="utf-8") as handle:
            raw = [line.split("#", 1)[0].strip() for line in handle]
    except OSError:
        return set()
    result = set()
    for value in raw:
        if not value:
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        normalized = str(address)
        if (
            address.version == 4
            and address in OVERLAY_NETWORK
            and address not in (OVERLAY_NETWORK.network_address, OVERLAY_NETWORK.broadcast_address)
            and normalized != LISTEN_ADDRESS
        ):
            result.add(normalized)
    return result


def server_ips():
    return load_role_registry(SERVER_REGISTRY_FILE)


def relay_only_ips():
    return load_role_registry(RELAY_ONLY_REGISTRY_FILE)

def new_push_status():
    return {
        "ok": None,
        "last_success": 0,
        "last_error": 0,
        "last_error_message": "",
        "consecutive_failures": 0,
        "last_error_log": 0,
    }


def peer_role(overlay_ip):
    if overlay_ip in relay_only_ips():
        return "relay_only"
    if overlay_ip in server_ips():
        return "server"
    return "client"


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
    address = ipaddress.ip_address(host)
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("invalid endpoint port")
    if address.is_unspecified or address.is_multicast:
        raise ValueError("invalid endpoint address")
    endpoint = (
        "[{}]:{}".format(address.compressed, port)
        if address.version == 6
        else "{}:{}".format(address.compressed, port)
    )
    return endpoint, address, port


def endpoint_ip(endpoint):
    try:
        _endpoint, address, _port = parse_endpoint(endpoint)
        return address.compressed
    except (TypeError, ValueError):
        return ""


def validate_candidates(values, allow_observed=False):
    if values is None:
        return []
    if not isinstance(values, list) or len(values) > MAX_CANDIDATES:
        raise ValueError("invalid candidates")
    allowed_types = {"lan4", "host6", "reflexive6", "mapped4"}
    if allow_observed:
        allowed_types.update(("observed4", "predicted4"))
    result = []
    seen = set()
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("invalid candidate")
        candidate_type = value.get("type", "")
        if candidate_type not in allowed_types:
            raise ValueError("invalid candidate type")
        endpoint, address, _port = parse_endpoint(value.get("endpoint", ""))
        if candidate_type == "lan4" and (address.version != 4 or not address.is_private):
            raise ValueError("lan4 candidate must be private IPv4")
        if candidate_type in ("host6", "reflexive6") and (
            address.version != 6
            or not address.is_global
            or address.is_private
            or address.is_link_local
        ):
            raise ValueError("host6 candidate must be global IPv6")
        if candidate_type in ("mapped4", "observed4", "predicted4") and address.version != 4:
            raise ValueError("IPv4 candidate has non-IPv4 endpoint")
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
            "verified": bool(value.get("verified", False)) if allow_observed else False,
        })
    return sorted(result, key=lambda item: item["priority"], reverse=True)


def lan_candidate(lan_ip, listen_port):
    address = ipaddress.ip_address(lan_ip)
    if address.version != 4 or not address.is_private:
        return None
    return {
        "type": "lan4",
        "family": "udp4",
        "endpoint": "{}:{}".format(address.compressed, int(listen_port)),
        "priority": 1000,
        "verified": False,
    }


def observed_candidate(endpoint):
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


def merge_candidates(*groups):
    result = []
    seen = set()
    for group in groups:
        for candidate in group or []:
            if not candidate:
                continue
            key = (candidate.get("type"), candidate.get("endpoint"))
            if not all(key) or key in seen:
                continue
            seen.add(key)
            result.append(dict(candidate))
    return sorted(
        result, key=lambda item: int(item.get("priority", 0)), reverse=True
    )[:MAX_CANDIDATES]


def wg_peers():
    if not WG_QUERY_SLOTS.acquire(timeout=2):
        raise RuntimeError("WireGuard query limit reached")
    try:
        result = subprocess.run(
            ["wg", "show", "wg0", "dump"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=5,
            check=False,
        )
    finally:
        WG_QUERY_SLOTS.release()
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "wg show failed")

    peers = []
    for line in result.stdout.splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        key, _psk, endpoint, allowed_ips, handshake, _rx, _tx, _keepalive = fields[:8]
        first_allowed = allowed_ips.split(",")[0].strip()
        try:
            overlay_ip = str(ipaddress.ip_interface(first_allowed).ip)
        except ValueError:
            continue
        handshake = int(handshake or 0)
        peers.append({
            "key": key,
            "ip": overlay_ip,
            "role": peer_role(overlay_ip),
            "endpoint": "" if endpoint == "(none)" else endpoint,
            "latest_handshake": handshake,
            "hs": max(0, int(time.time()) - handshake) if handshake else None,
        })
    return peers


def peer_payload(peers=None):
    now = time.time()
    peers = peers if peers is not None else wg_peers()
    active_ips = {peer["ip"] for peer in peers}
    with STATE_LOCK:
        for overlay_ip in list(LAN_CANDIDATES):
            candidate = LAN_CANDIDATES[overlay_ip]
            if overlay_ip not in active_ips or now - candidate["seen"] > ANNOUNCE_TTL:
                del LAN_CANDIDATES[overlay_ip]
        for overlay_ip in list(NODE_CANDIDATES):
            candidate = NODE_CANDIDATES[overlay_ip]
            if overlay_ip not in active_ips or now - candidate["seen"] > ANNOUNCE_TTL:
                del NODE_CANDIDATES[overlay_ip]

        for peer in peers:
            lan = LAN_CANDIDATES.get(peer["ip"])
            if lan:
                peer["lan_endpoint"] = "{}:{}".format(
                    lan["lan_ip"], lan["listen_port"]
                )
                peer["lan_seen"] = int(lan["seen"])
                legacy_lan = [lan_candidate(lan["lan_ip"], lan["listen_port"])]
            else:
                peer["lan_endpoint"] = ""
                peer["lan_seen"] = 0
                legacy_lan = []
            stored = NODE_CANDIDATES.get(peer["ip"], {}).get("candidates", [])
            observed = observed_candidate(peer.get("endpoint", ""))
            predictions = [] if any(
                item.get("type") == "mapped4" for item in stored
            ) else predicted_candidates(peer.get("endpoint", ""))
            peer["candidates"] = merge_candidates(
                legacy_lan,
                stored,
                [observed],
                predictions,
            )
    return peers


def validate_announcement(data):
    lan_ip = ipaddress.ip_address(data["lan_ip"])
    listen_port = int(data["listen_port"])
    if lan_ip.version != 4 or not lan_ip.is_private:
        raise ValueError("LAN address must be private IPv4")
    if not 1 <= listen_port <= 65535:
        raise ValueError("invalid listen port")
    return str(lan_ip), listen_port


def record_candidate(overlay_ip, lan_ip, listen_port):
    with STATE_LOCK:
        LAN_CANDIDATES[overlay_ip] = {
            "lan_ip": lan_ip,
            "listen_port": listen_port,
            "seen": time.time(),
        }


def record_node_candidates(overlay_ip, candidates):
    with STATE_LOCK:
        NODE_CANDIDATES[overlay_ip] = {
            "candidates": list(candidates),
            "seen": time.time(),
        }


def find_source_peer(source_ip, peers):
    return next((peer for peer in peers if peer["ip"] == source_ip), None)


def signature_payload(method, path, timestamp, nonce, body):
    return b"\n".join([
        method.upper().encode(),
        path.encode(),
        timestamp.encode(),
        nonce.encode(),
        body,
    ])


def signed_post(server_ip, path, payload):
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    signed = signature_payload("POST", path, timestamp, nonce, body)
    signature = hmac.new(NOTIFY_KEY, signed, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        "http://{}:{}{}".format(server_ip, AGENT_PORT, path),
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-P2P-Timestamp": timestamp,
            "X-P2P-Nonce": nonce,
            "X-P2P-Signature": signature,
        },
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=PUSH_TIMEOUT) as response:
        return json.loads(response.read().decode())


def offer_fingerprint(client, client_lan_endpoint, client_candidates, server, session_id=""):
    return "|".join([
        session_id,
        client.get("key", ""),
        client.get("endpoint", ""),
        client_lan_endpoint,
        json.dumps(client_candidates, separators=(",", ":"), sort_keys=True),
        server.get("key", ""),
        server.get("endpoint", ""),
    ])


def push_offer(server, client, client_lan_endpoint, client_candidates, session_id, session_started_ns):
    same_nat = endpoint_ip(server.get("endpoint", "")) == endpoint_ip(
        client.get("endpoint", "")
    )
    candidate = client_lan_endpoint if same_nat else client.get("endpoint", "")
    if not candidate:
        raise RuntimeError("client endpoint unavailable")
    legacy_lan = []
    if client_lan_endpoint:
        try:
            _endpoint, address, port = parse_endpoint(client_lan_endpoint)
            if address.version == 4 and address.is_private:
                legacy_lan = [lan_candidate(address.compressed, port)]
        except ValueError:
            pass
    observed = observed_candidate(client.get("endpoint", ""))
    predictions = [] if any(
        item.get("type") == "mapped4" for item in client_candidates
    ) else predicted_candidates(client.get("endpoint", ""))
    candidates = merge_candidates(
        legacy_lan,
        client_candidates,
        [observed],
        predictions,
    )
    return signed_post(server["ip"], "/offer", {
        "protocol": 7,
        "session_id": session_id,
        "session_started_ns": session_started_ns,
        "peer_key": client["key"],
        "peer_ip": client["ip"],
        "endpoint": candidate,
        "endpoint_type": "LAN" if same_nat else "WAN",
        "candidates": candidates,
        "lease_expires": int(time.time()) + SESSION_TTL,
    })


def coordinate_client(client, client_lan_endpoint, peers, client_candidates=None, force=False):
    now = time.time()
    client_candidates = client_candidates or []
    servers = [peer for peer in peers if peer.get("role") == "server"]
    stale_session = None

    with COORDINATE_LOCK:
        with STATE_LOCK:
            existing = SESSIONS.get(client["ip"])
            is_new_session = existing is None or existing.get("key") != client["key"]
            if is_new_session:
                stale_session = existing
                session = {
                    "session_id": str(uuid.uuid4()),
                    "session_started_ns": time.time_ns(),
                    "key": client["key"],
                    "ip": client["ip"],
                    "last_seen": now,
                    "last_push": {},
                    "fingerprints": {},
                    "server_info": {},
                    "candidates": list(client_candidates),
                }
                SESSIONS[client["ip"]] = session
            else:
                session = existing
                if not session.get("session_id"):
                    session["session_id"] = str(uuid.uuid4())
                if not session.get("session_started_ns"):
                    session["session_started_ns"] = time.time_ns()
                session["key"] = client["key"]
                session["last_seen"] = now
                session["candidates"] = list(client_candidates)

            session_id = session["session_id"]
            session_started_ns = int(session["session_started_ns"])
            last_push = dict(session.get("last_push", {}))
            fingerprints = dict(session.get("fingerprints", {}))

        if stale_session and stale_session.get("session_id"):
            push_remove(stale_session, reason="superseded")

        if is_new_session:
            log("session opened for {} ({})".format(client["ip"], session_id))

        pending = []
        for server in servers:
            fingerprint = offer_fingerprint(
                client,
                client_lan_endpoint,
                client_candidates,
                server,
                session_id,
            )
            server_ip = server["ip"]
            refresh_due = now - float(last_push.get(server_ip, 0)) >= OFFER_REFRESH
            if force or fingerprints.get(server_ip) != fingerprint or refresh_due:
                pending.append((server, fingerprint))

        results = {}
        if pending:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                future_map = {
                    executor.submit(
                        push_offer,
                        server,
                        client,
                        client_lan_endpoint,
                        client_candidates,
                        session_id,
                        session_started_ns,
                    ): (server, fingerprint)
                    for server, fingerprint in pending
                }
                for future, item in future_map.items():
                    server, fingerprint = item
                    try:
                        info = future.result()
                        if info.get("ok"):
                            results[server["ip"]] = (fingerprint, info)
                            record_push_result(server["ip"], True)
                        else:
                            record_push_result(
                                server["ip"], False, "negative response"
                            )
                    except Exception as exc:
                        record_push_result(server["ip"], False, exc)

        with STATE_LOCK:
            session = SESSIONS.get(client["ip"])
            if session is None or session.get("session_id") != session_id:
                return session_id
            session["last_seen"] = now
            for server_ip, item in results.items():
                fingerprint, info = item
                session["last_push"][server_ip] = now
                session["fingerprints"][server_ip] = fingerprint
                session["server_info"][server_ip] = info
                try:
                    lan_ip, listen_port = validate_announcement(info)
                    LAN_CANDIDATES[server_ip] = {
                        "lan_ip": lan_ip,
                        "listen_port": listen_port,
                        "seen": now,
                    }
                except (KeyError, TypeError, ValueError):
                    pass
                try:
                    server_candidates = validate_candidates(
                        info.get("candidates", []), allow_observed=False
                    )
                    NODE_CANDIDATES[server_ip] = {
                        "candidates": server_candidates,
                        "seen": now,
                    }
                except (TypeError, ValueError):
                    pass
        return session_id


def push_remove(session, reason="disconnect"):
    if reason not in ("disconnect", "superseded", "expired"):
        raise ValueError("invalid remove reason")
    session_id = session.get("session_id", "")
    if not session_id:
        return
    payload = {
        "session_id": session_id,
        "peer_key": session["key"],
        "peer_ip": session["ip"],
        "reason": reason,
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_map = {
            executor.submit(signed_post, server_ip, "/remove", payload): server_ip
            for server_ip in server_ips()
        }
        for future, server_ip in future_map.items():
            try:
                result = future.result()
                if result.get("ok"):
                    record_push_result(server_ip, True)
                else:
                    record_push_result(server_ip, False, "negative response")
            except Exception as exc:
                record_push_result(server_ip, False, exc)


def disconnect_client(client):
    with STATE_LOCK:
        session = SESSIONS.pop(client["ip"], None)
        LAN_CANDIDATES.pop(client["ip"], None)
        NODE_CANDIDATES.pop(client["ip"], None)
        if not SESSIONS:
            for server_ip in server_ips():
                LAN_CANDIDATES.pop(server_ip, None)
                NODE_CANDIDATES.pop(server_ip, None)
    if session:
        log("session closed for {} ({})".format(
            client["ip"], session.get("session_id", "legacy")
        ))
        push_remove(session)


def session_reaper():
    while not STOP.wait(15):
        now = time.time()
        expired = []
        with STATE_LOCK:
            for overlay_ip, session in list(SESSIONS.items()):
                if now - session.get("last_seen", 0) > SESSION_TTL:
                    expired.append(session)
                    del SESSIONS[overlay_ip]
                    LAN_CANDIDATES.pop(overlay_ip, None)
                    NODE_CANDIDATES.pop(overlay_ip, None)
            if not SESSIONS:
                for server_ip in server_ips():
                    LAN_CANDIDATES.pop(server_ip, None)
                    NODE_CANDIDATES.pop(server_ip, None)
        for session in expired:
            log("session expired for {} ({})".format(
                session["ip"], session.get("session_id", "legacy")
            ))
            push_remove(session, reason="expired")


def bootstrap_server_key(source_ip):
    if source_ip not in server_ips():
        raise PermissionError("server bootstrap key is restricted to server peers")
    if not NOTIFY_KEY or len(NOTIFY_KEY) < 32:
        raise RuntimeError("notification key unavailable")
    return NOTIFY_KEY + b"\n"


def update_asset_path(request_path):
    prefix = "/updates/"
    if not request_path.startswith(prefix):
        raise ValueError("invalid update path")
    name = urllib.parse.unquote(request_path[len(prefix):].split("?", 1)[0])
    if not name or name != os.path.basename(name) or name in (".", ".."):
        raise ValueError("invalid update filename")
    root = os.path.realpath(UPDATE_DIR)
    candidate = os.path.realpath(os.path.join(root, name))
    if os.path.dirname(candidate) != root:
        raise ValueError("invalid update path")
    return candidate


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "WireGuardP2P/{}".format(VERSION)
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

    def read_json(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size <= 0 or size > MAX_REQUEST_SIZE:
            raise ValueError("invalid request size")
        return json.loads(self.rfile.read(size).decode())

    def send_update_file(self, path):
        size = os.path.getsize(path)
        if size < 0 or size > UPDATE_MAX_FILE_SIZE:
            self.send_json(413, {"error": "update file too large"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        with open(path, "rb") as handle:
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                self.wfile.write(block)

    def do_GET(self):
        try:
            if self.path == "/bootstrap/server-key":
                try:
                    body = bootstrap_server_key(self.client_address[0])
                except PermissionError as exc:
                    self.send_json(403, {"error": str(exc)})
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path.startswith("/updates/"):
                try:
                    path = update_asset_path(self.path)
                except ValueError as exc:
                    self.send_json(400, {"error": str(exc)})
                    return
                if not os.path.isfile(path):
                    self.send_json(404, {"error": "update asset not found"})
                    return
                self.send_update_file(path)
                return
            if self.path == "/":
                self.send_json(200, peer_payload())
                return
            if self.path == "/health":
                peers = wg_peers()
                with STATE_LOCK:
                    session_count = len(SESSIONS)
                    server_push = {
                        server_ip: {
                            key: value
                            for key, value in status.items()
                            if key != "last_error_log"
                        }
                        for server_ip, status in SERVER_PUSH_STATUS.items()
                    }
                self.send_json(200, {
                    "ok": True,
                    "version": VERSION,
                    "protocol": 7,
                    "security": "session-nonce-v1",
                    "peer_count": len(peers),
                    "session_count": session_count,
                    "server_push": server_push,
                    "update_ready": os.path.isfile(os.path.join(UPDATE_DIR, "manifest.json")),
                })
                return
            self.send_json(404, {"error": "not found"})
        except Exception:
            self.send_json(503, {"error": "WireGuard state unavailable"})

    def do_POST(self):
        if self.path not in ("/announce", "/sync", "/connect", "/disconnect"):
            self.send_json(404, {"error": "not found"})
            return
        try:
            data = self.read_json()
            peers = wg_peers()
            source = find_source_peer(self.client_address[0], peers)
            if source is None:
                self.send_json(403, {"error": "source is not a WireGuard peer"})
                return

            if self.path == "/disconnect":
                if source.get("role") == "client":
                    disconnect_client(source)
                self.send_json(200, {
                    "ok": True,
                    "version": VERSION,
                    "protocol": 7,
                })
                return

            lan_ip, listen_port = validate_announcement(data)
            record_candidate(source["ip"], lan_ip, listen_port)
            advertised = validate_candidates(
                data.get("candidates", []), allow_observed=False
            )
            if not advertised:
                advertised = [lan_candidate(lan_ip, listen_port)]
            record_node_candidates(source["ip"], advertised)
            lan_endpoint = "{}:{}".format(lan_ip, listen_port)
            session_id = ""
            if source.get("role") == "client":
                session_id = coordinate_client(
                    source, lan_endpoint, peers, advertised
                )

            if self.path in ("/sync", "/connect"):
                response = {
                    "version": VERSION,
                    "protocol": 7,
                    "peers": peer_payload(peers),
                }
                if session_id:
                    response["session_id"] = session_id
                self.send_json(200, response)
            else:
                response = {
                    "ok": True,
                    "version": VERSION,
                    "protocol": 7,
                }
                if session_id:
                    response["session_id"] = session_id
                self.send_json(200, response)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self.send_json(400, {"error": str(exc)})
        except Exception:
            self.send_json(503, {"error": "coordinator unavailable"})

    def log_message(self, _fmt, *_args):
        pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16


if __name__ == "__main__":
    NOTIFY_KEY = load_notify_key()
    reaper = threading.Thread(target=session_reaper, name="session-reaper")
    reaper.daemon = True
    reaper.start()
    try:
        ThreadingHTTPServer((LISTEN_ADDRESS, LISTEN_PORT), Handler).serve_forever()
    finally:
        STOP.set()
