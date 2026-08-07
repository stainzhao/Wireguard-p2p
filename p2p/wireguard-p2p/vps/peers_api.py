#!/usr/bin/env python3
"""Event-driven WireGuard P2P coordinator, reachable only through wg0."""

import concurrent.futures
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import socketserver
import subprocess
import threading
import time
import urllib.request


VERSION = "6.2.0"
LISTEN_ADDRESS = "10.0.0.1"
LISTEN_PORT = 8899
AGENT_PORT = 8898
ANNOUNCE_TTL = 150
SESSION_TTL = 120
OFFER_REFRESH = 60
PUSH_TIMEOUT = 2
MAX_REQUEST_SIZE = 4096
NOTIFY_KEY_FILE = os.environ.get(
    "P2P_NOTIFY_KEY_FILE", "/etc/wireguard-p2p/notify.key"
)
SERVER_IPS = {"10.0.0.2", "10.0.0.5"}
RELAY_ONLY_IPS = {"10.0.0.8"}

LAN_CANDIDATES = {}
SESSIONS = {}
SERVER_PUSH_STATUS = {
    server_ip: {
        "ok": None,
        "last_success": 0,
        "last_error": 0,
        "last_error_message": "",
        "consecutive_failures": 0,
        "last_error_log": 0,
    }
    for server_ip in SERVER_IPS
}
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
        status = SERVER_PUSH_STATUS[server_ip]
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


def peer_role(overlay_ip):
    if overlay_ip in SERVER_IPS:
        return "server"
    if overlay_ip in RELAY_ONLY_IPS:
        return "relay_only"
    return "client"


def endpoint_ip(endpoint):
    try:
        return endpoint.rsplit(":", 1)[0].strip("[]")
    except (AttributeError, ValueError):
        return ""


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

        for peer in peers:
            candidate = LAN_CANDIDATES.get(peer["ip"])
            if candidate:
                peer["lan_endpoint"] = "{}:{}".format(
                    candidate["lan_ip"], candidate["listen_port"]
                )
                peer["lan_seen"] = int(candidate["seen"])
            else:
                peer["lan_endpoint"] = ""
                peer["lan_seen"] = 0
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


def find_source_peer(source_ip, peers):
    return next((peer for peer in peers if peer["ip"] == source_ip), None)


def signed_post(server_ip, path, payload):
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    timestamp = str(int(time.time()))
    signed = timestamp.encode() + b"\n" + body
    signature = hmac.new(NOTIFY_KEY, signed, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        "http://{}:{}{}".format(server_ip, AGENT_PORT, path),
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-P2P-Timestamp": timestamp,
            "X-P2P-Signature": signature,
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=PUSH_TIMEOUT) as response:
        return json.loads(response.read().decode())


def offer_fingerprint(client, client_lan_endpoint, server):
    return "|".join([
        client.get("key", ""),
        client.get("endpoint", ""),
        client_lan_endpoint,
        server.get("key", ""),
        server.get("endpoint", ""),
    ])


def push_offer(server, client, client_lan_endpoint):
    same_nat = endpoint_ip(server.get("endpoint", "")) == endpoint_ip(
        client.get("endpoint", "")
    )
    candidate = client_lan_endpoint if same_nat else client.get("endpoint", "")
    if not candidate:
        raise RuntimeError("client endpoint unavailable")
    return signed_post(server["ip"], "/offer", {
        "peer_key": client["key"],
        "peer_ip": client["ip"],
        "endpoint": candidate,
        "endpoint_type": "LAN" if same_nat else "WAN",
        "lease_expires": int(time.time()) + SESSION_TTL,
    })


def coordinate_client(client, client_lan_endpoint, peers, force=False):
    now = time.time()
    servers = [peer for peer in peers if peer.get("role") == "server"]
    with COORDINATE_LOCK:
        with STATE_LOCK:
            is_new_session = client["ip"] not in SESSIONS
            session = SESSIONS.setdefault(client["ip"], {
                "key": client["key"],
                "ip": client["ip"],
                "last_seen": now,
                "last_push": {},
                "fingerprints": {},
                "server_info": {},
            })
            session["key"] = client["key"]
            session["last_seen"] = now
            last_push = dict(session.get("last_push", {}))
            fingerprints = dict(session.get("fingerprints", {}))

        if is_new_session:
            log("session opened for {}".format(client["ip"]))

        pending = []
        for server in servers:
            fingerprint = offer_fingerprint(client, client_lan_endpoint, server)
            server_ip = server["ip"]
            refresh_due = now - float(last_push.get(server_ip, 0)) >= OFFER_REFRESH
            if force or fingerprints.get(server_ip) != fingerprint or refresh_due:
                pending.append((server, fingerprint))

        results = {}
        if pending:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                future_map = {
                    executor.submit(push_offer, server, client, client_lan_endpoint):
                    (server, fingerprint)
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
                            record_push_result(server["ip"], False, "negative response")
                    except Exception as exc:
                        record_push_result(server["ip"], False, exc)
                        continue

        with STATE_LOCK:
            session = SESSIONS.get(client["ip"])
            if session is None:
                return
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


def push_remove(client):
    payload = {"peer_key": client["key"], "peer_ip": client["ip"]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_map = {
            executor.submit(signed_post, server_ip, "/remove", payload): server_ip
            for server_ip in SERVER_IPS
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
        existed = SESSIONS.pop(client["ip"], None) is not None
        LAN_CANDIDATES.pop(client["ip"], None)
        if not SESSIONS:
            for server_ip in SERVER_IPS:
                LAN_CANDIDATES.pop(server_ip, None)
    if existed:
        log("session closed for {}".format(client["ip"]))
    push_remove(client)


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
            if not SESSIONS:
                for server_ip in SERVER_IPS:
                    LAN_CANDIDATES.pop(server_ip, None)
        for session in expired:
            log("session expired for {}".format(session["ip"]))
            push_remove(session)


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

    def do_GET(self):
        try:
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
                    "peer_count": len(peers),
                    "session_count": session_count,
                    "server_push": server_push,
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
                self.send_json(200, {"ok": True, "version": VERSION})
                return

            lan_ip, listen_port = validate_announcement(data)
            record_candidate(source["ip"], lan_ip, listen_port)
            lan_endpoint = "{}:{}".format(lan_ip, listen_port)
            if source.get("role") == "client":
                coordinate_client(source, lan_endpoint, peers)

            if self.path in ("/sync", "/connect"):
                self.send_json(200, {
                    "version": VERSION,
                    "peers": peer_payload(peers),
                })
            else:
                self.send_json(200, {"ok": True, "version": VERSION})
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
