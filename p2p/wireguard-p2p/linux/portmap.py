#!/usr/bin/env python3
"""Best-effort IPv4 UDP port mapping for the WireGuard listen port.

Protocol order: PCP -> NAT-PMP -> UPnP-IGD.  The manager is deliberately
best-effort: a mapping failure never affects the VPS relay path.
"""

import ipaddress
import os
import secrets
import socket
import struct
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

PCP_PORT = 5351
NATPMP_PORT = 5351
SSDP_ADDRESS = ("239.255.255.250", 1900)
DEFAULT_LIFETIME = int(os.environ.get("P2P_PORTMAP_LIFETIME", "3600"))
FAILURE_RETRY = int(os.environ.get("P2P_PORTMAP_RETRY", "60"))
NETWORK_TIMEOUT = float(os.environ.get("P2P_PORTMAP_TIMEOUT", "0.8"))
UPNP_TIMEOUT = float(os.environ.get("P2P_UPNP_TIMEOUT", "1.2"))


def _public_ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and address.is_global


def default_gateway_ipv4():
    """Return the lowest-metric IPv4 default gateway from /proc/net/route."""
    best = None
    try:
        with open("/proc/net/route", "r", encoding="ascii") as handle:
            next(handle, None)
            for line in handle:
                fields = line.split()
                if len(fields) < 8 or fields[1] != "00000000":
                    continue
                flags = int(fields[3], 16)
                if not flags & 0x2:
                    continue
                gateway_raw = struct.pack("<I", int(fields[2], 16))
                gateway = socket.inet_ntoa(gateway_raw)
                metric = int(fields[6])
                candidate = (metric, gateway)
                if best is None or candidate < best:
                    best = candidate
    except (OSError, ValueError):
        return ""
    return best[1] if best else ""


def _ipv4_mapped(address):
    packed = ipaddress.ip_address(address).packed
    return b"\x00" * 10 + b"\xff\xff" + packed


def build_pcp_map_request(local_ip, internal_port, lifetime, nonce=None):
    nonce = nonce or secrets.token_bytes(12)
    if len(nonce) != 12:
        raise ValueError("PCP nonce must be 12 bytes")
    packet = bytearray(60)
    packet[0] = 2
    packet[1] = 1  # MAP opcode
    struct.pack_into("!I", packet, 4, int(lifetime))
    packet[8:24] = _ipv4_mapped(local_ip)
    packet[24:36] = nonce
    packet[36] = socket.IPPROTO_UDP
    struct.pack_into("!H", packet, 40, int(internal_port))
    struct.pack_into("!H", packet, 42, int(internal_port))
    return bytes(packet), nonce


def parse_pcp_map_response(packet, nonce, internal_port):
    if len(packet) < 60 or packet[0] != 2 or packet[1] != 0x81:
        raise ValueError("invalid PCP MAP response")
    if packet[2] != 0:
        raise RuntimeError("PCP result {}".format(packet[2]))
    if packet[24:36] != nonce or packet[36] != socket.IPPROTO_UDP:
        raise ValueError("PCP response mismatch")
    returned_internal = struct.unpack_from("!H", packet, 40)[0]
    if returned_internal != int(internal_port):
        raise ValueError("PCP internal port mismatch")
    lifetime = struct.unpack_from("!I", packet, 4)[0]
    external_port = struct.unpack_from("!H", packet, 42)[0]
    external_raw = packet[44:60]
    if external_raw[:12] == b"\x00" * 10 + b"\xff\xff":
        external_ip = socket.inet_ntoa(external_raw[12:16])
    else:
        address = ipaddress.ip_address(external_raw)
        if address.version != 4:
            raise ValueError("PCP returned non-IPv4 address")
        external_ip = str(address)
    if not _public_ipv4(external_ip) or not external_port:
        raise ValueError("PCP returned non-public mapping")
    return external_ip, external_port, lifetime


def try_pcp(gateway, local_ip, internal_port, lifetime=DEFAULT_LIFETIME):
    request, nonce = build_pcp_map_request(local_ip, internal_port, lifetime)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((local_ip, 0))
        sock.settimeout(NETWORK_TIMEOUT)
        sock.sendto(request, (gateway, PCP_PORT))
        packet, source = sock.recvfrom(1024)
        if source[0] != gateway:
            raise ValueError("unexpected PCP responder")
        return parse_pcp_map_response(packet, nonce, internal_port)
    finally:
        sock.close()


def build_natpmp_map_request(internal_port, lifetime):
    return struct.pack("!BBHHHI", 0, 1, 0, int(internal_port), int(internal_port), int(lifetime))


def parse_natpmp_public_response(packet):
    if len(packet) < 12 or packet[0] != 0 or packet[1] != 128:
        raise ValueError("invalid NAT-PMP public address response")
    result = struct.unpack_from("!H", packet, 2)[0]
    if result != 0:
        raise RuntimeError("NAT-PMP public result {}".format(result))
    address = socket.inet_ntoa(packet[8:12])
    if not _public_ipv4(address):
        raise ValueError("NAT-PMP returned non-public address")
    return address


def parse_natpmp_map_response(packet, internal_port):
    if len(packet) < 16 or packet[0] != 0 or packet[1] != 129:
        raise ValueError("invalid NAT-PMP mapping response")
    result = struct.unpack_from("!H", packet, 2)[0]
    if result != 0:
        raise RuntimeError("NAT-PMP map result {}".format(result))
    returned_internal, external_port = struct.unpack_from("!HH", packet, 8)
    lifetime = struct.unpack_from("!I", packet, 12)[0]
    if returned_internal != int(internal_port) or not external_port:
        raise ValueError("NAT-PMP mapping mismatch")
    return external_port, lifetime


def try_natpmp(gateway, local_ip, internal_port, lifetime=DEFAULT_LIFETIME):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((local_ip, 0))
        sock.settimeout(NETWORK_TIMEOUT)
        sock.sendto(b"\x00\x00", (gateway, NATPMP_PORT))
        public_packet, source = sock.recvfrom(1024)
        if source[0] != gateway:
            raise ValueError("unexpected NAT-PMP responder")
        external_ip = parse_natpmp_public_response(public_packet)

        sock.sendto(build_natpmp_map_request(internal_port, lifetime), (gateway, NATPMP_PORT))
        map_packet, source = sock.recvfrom(1024)
        if source[0] != gateway:
            raise ValueError("unexpected NAT-PMP responder")
        external_port, granted_lifetime = parse_natpmp_map_response(map_packet, internal_port)
        return external_ip, external_port, granted_lifetime
    finally:
        sock.close()


def _header_value(data, name):
    prefix = name.lower() + ":"
    for line in data.decode("iso-8859-1", "replace").splitlines():
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return ""


def _xml_local(tag):
    return tag.rsplit("}", 1)[-1]


def _discover_upnp_locations(local_ip):
    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
    ).encode("ascii")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    locations = []
    seen = set()
    try:
        sock.bind((local_ip, 0))
        sock.settimeout(UPNP_TIMEOUT)
        sock.sendto(request, SSDP_ADDRESS)
        deadline = time.monotonic() + UPNP_TIMEOUT
        while time.monotonic() < deadline:
            try:
                data, _source = sock.recvfrom(8192)
            except socket.timeout:
                break
            location = _header_value(data, "location")
            if location and location not in seen:
                seen.add(location)
                locations.append(location)
    finally:
        sock.close()
    return locations


def _http_open(request, timeout=UPNP_TIMEOUT):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return opener.open(request, timeout=timeout)


def _find_upnp_service(location):
    request = urllib.request.Request(location, headers={"User-Agent": "WireGuard-P2P/7.1"})
    with _http_open(request) as response:
        root = ET.fromstring(response.read())
    for service in root.iter():
        if _xml_local(service.tag) != "service":
            continue
        values = {_xml_local(child.tag): (child.text or "").strip() for child in service}
        service_type = values.get("serviceType", "")
        if "WANIPConnection" not in service_type and "WANPPPConnection" not in service_type:
            continue
        control = values.get("controlURL", "")
        if control:
            return service_type, urllib.parse.urljoin(location, control)
    return None


def _soap_call(control_url, service_type, action, arguments):
    argument_xml = "".join("<{}>{}</{}>".format(name, value, name) for name, value in arguments)
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        '<s:Body><u:{action} xmlns:u="{service}">{args}</u:{action}></s:Body></s:Envelope>'
    ).format(action=action, service=service_type, args=argument_xml).encode("utf-8")
    request = urllib.request.Request(
        control_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": '"{}#{}"'.format(service_type, action),
            "User-Agent": "WireGuard-P2P/7.1",
        },
    )
    with _http_open(request) as response:
        return response.read()


def _upnp_external_ip(control_url, service_type):
    payload = _soap_call(control_url, service_type, "GetExternalIPAddress", [])
    root = ET.fromstring(payload)
    for element in root.iter():
        if _xml_local(element.tag) == "NewExternalIPAddress":
            address = (element.text or "").strip()
            if _public_ipv4(address):
                return address
    raise ValueError("UPnP returned no public IPv4")


def try_upnp(local_ip, internal_port, lifetime=DEFAULT_LIFETIME):
    last_error = None
    for location in _discover_upnp_locations(local_ip):
        try:
            service = _find_upnp_service(location)
            if not service:
                continue
            service_type, control_url = service
            _soap_call(control_url, service_type, "AddPortMapping", [
                ("NewRemoteHost", ""),
                ("NewExternalPort", str(int(internal_port))),
                ("NewProtocol", "UDP"),
                ("NewInternalPort", str(int(internal_port))),
                ("NewInternalClient", local_ip),
                ("NewEnabled", "1"),
                ("NewPortMappingDescription", "WireGuard-P2P"),
                ("NewLeaseDuration", str(int(lifetime))),
            ])
            external_ip = _upnp_external_ip(control_url, service_type)
            return external_ip, int(internal_port), int(lifetime)
        except Exception as exc:
            last_error = exc
    if last_error:
        raise last_error
    raise RuntimeError("UPnP IGD not found")


class PortMapper:
    def __init__(self):
        self._lock = threading.Lock()
        self._candidate = None
        self._internal = None
        self._expires_at = 0.0
        self._next_attempt = 0.0
        self._method = ""
        self._last_error = ""

    def current_candidate(self, internal_port, local_ip):
        now = time.time()
        key = (str(local_ip), int(internal_port))
        with self._lock:
            if self._internal != key or self._candidate is None or now >= self._expires_at:
                return None
            return dict(self._candidate)

    def should_refresh(self, internal_port, local_ip):
        now = time.time()
        key = (str(local_ip), int(internal_port))
        with self._lock:
            if now < self._next_attempt:
                return False
            if self._internal != key or self._candidate is None:
                return True
            return self._expires_at - now <= max(300, DEFAULT_LIFETIME // 3)

    def refresh(self, internal_port, local_ip):
        port = int(internal_port)
        if not 1 <= port <= 65535:
            return None
        try:
            local = ipaddress.ip_address(local_ip)
        except ValueError:
            return None
        if local.version != 4 or not local.is_private:
            return None
        gateway = default_gateway_ipv4()
        if not gateway:
            self._record_failure((str(local), port), "default gateway unavailable")
            return None

        errors = []
        for method, function in (("pcp", try_pcp), ("natpmp", try_natpmp)):
            try:
                external_ip, external_port, lifetime = function(gateway, str(local), port)
                return self._record_success((str(local), port), method, external_ip, external_port, lifetime)
            except Exception as exc:
                errors.append("{}: {}".format(method, exc))
        try:
            external_ip, external_port, lifetime = try_upnp(str(local), port)
            return self._record_success((str(local), port), "upnp", external_ip, external_port, lifetime)
        except Exception as exc:
            errors.append("upnp: {}".format(exc))

        self._record_failure((str(local), port), "; ".join(errors)[-512:])
        return None

    def _record_success(self, key, method, external_ip, external_port, lifetime):
        lifetime = max(60, int(lifetime or DEFAULT_LIFETIME))
        candidate = {
            "type": "mapped4",
            "family": "udp4",
            "endpoint": "{}:{}".format(external_ip, int(external_port)),
            "priority": 800,
            "verified": False,
        }
        now = time.time()
        with self._lock:
            self._internal = key
            self._candidate = candidate
            self._expires_at = now + lifetime
            self._next_attempt = now + min(lifetime * 2 / 3, max(60, lifetime - 300))
            self._method = method
            self._last_error = ""
        return dict(candidate)

    def _record_failure(self, key, error):
        now = time.time()
        with self._lock:
            if self._internal != key:
                self._candidate = None
                self._expires_at = 0
            self._internal = key
            self._next_attempt = now + FAILURE_RETRY
            self._last_error = str(error)

    def status(self):
        now = time.time()
        with self._lock:
            endpoint = self._candidate.get("endpoint", "") if self._candidate and now < self._expires_at else ""
            return {
                "method": self._method if endpoint else "",
                "endpoint": endpoint,
                "expires_in": max(0, int(self._expires_at - now)) if endpoint else 0,
                "last_error": self._last_error,
            }
