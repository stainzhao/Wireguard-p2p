import importlib.util
import json
import pathlib
import socket
import struct
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LINUX = ROOT / "linux"
if str(LINUX) not in sys.path:
    sys.path.insert(0, str(LINUX))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


portmap = load_module("portmap_v71", LINUX / "portmap.py")
candidates = load_module("candidates_v71", LINUX / "candidates.py")


class PortMapProtocolTests(unittest.TestCase):
    def test_pcp_request_and_response(self):
        nonce = bytes(range(12))
        request, returned_nonce = portmap.build_pcp_map_request(
            "192.168.1.10", 51820, 3600, nonce=nonce
        )
        self.assertEqual(len(request), 60)
        self.assertEqual(returned_nonce, nonce)
        self.assertEqual(request[0], 2)
        self.assertEqual(request[1], 1)
        self.assertEqual(request[24:36], nonce)
        self.assertEqual(request[36], socket.IPPROTO_UDP)
        self.assertEqual(struct.unpack_from("!H", request, 40)[0], 51820)

        response = bytearray(60)
        response[0] = 2
        response[1] = 0x81
        response[2] = 0
        struct.pack_into("!I", response, 4, 3600)
        response[24:36] = nonce
        response[36] = socket.IPPROTO_UDP
        struct.pack_into("!H", response, 40, 51820)
        struct.pack_into("!H", response, 42, 62000)
        response[44:60] = b"\x00" * 10 + b"\xff\xff" + socket.inet_aton("8.8.8.8")

        external_ip, external_port, lifetime = portmap.parse_pcp_map_response(
            bytes(response), nonce, 51820
        )
        self.assertEqual(external_ip, "8.8.8.8")
        self.assertEqual(external_port, 62000)
        self.assertEqual(lifetime, 3600)

    def test_natpmp_request_and_responses(self):
        request = portmap.build_natpmp_map_request(51820, 3600)
        self.assertEqual(len(request), 12)
        self.assertEqual(request[:2], b"\x00\x01")

        public_response = bytearray(12)
        public_response[0] = 0
        public_response[1] = 128
        struct.pack_into("!H", public_response, 2, 0)
        public_response[8:12] = socket.inet_aton("8.8.4.4")
        self.assertEqual(
            portmap.parse_natpmp_public_response(bytes(public_response)), "8.8.4.4"
        )

        map_response = bytearray(16)
        map_response[0] = 0
        map_response[1] = 129
        struct.pack_into("!H", map_response, 2, 0)
        struct.pack_into("!HHI", map_response, 8, 51820, 62001, 3600)
        external_port, lifetime = portmap.parse_natpmp_map_response(
            bytes(map_response), 51820
        )
        self.assertEqual(external_port, 62001)
        self.assertEqual(lifetime, 3600)

    def test_non_public_mapping_is_rejected(self):
        self.assertFalse(portmap._public_ipv4("192.168.1.1"))
        self.assertFalse(portmap._public_ipv4("100.64.0.1"))
        self.assertTrue(portmap._public_ipv4("8.8.8.8"))

    def test_mapper_honors_short_granted_lifetime(self):
        mapper = portmap.PortMapper()
        mapper._record_success(
            ("192.168.1.10", 51820), "pcp", "8.8.8.8", 62000, 30
        )
        status = mapper.status()
        self.assertGreater(status["expires_in"], 0)
        self.assertLessEqual(status["expires_in"], 30)
        with mapper._lock:
            mapper._next_attempt = time.time() - 1
        self.assertTrue(mapper.should_refresh(51820, "192.168.1.10"))

    def test_zero_lifetime_is_not_published(self):
        mapper = portmap.PortMapper()
        with self.assertRaises(ValueError):
            mapper._record_success(
                ("192.168.1.10", 51820), "pcp", "8.8.8.8", 62000, 0
            )


class MappedCandidateCacheTests(unittest.TestCase):
    def write_state(self, path, **changes):
        payload = {
            "internal_ip": "192.168.1.10",
            "internal_port": 51820,
            "expires_at": time.time() + 600,
            "candidate": {
                "type": "mapped4",
                "family": "udp4",
                "endpoint": "8.8.8.8:62000",
                "priority": 800,
                "verified": False,
            },
        }
        payload.update(changes)
        path.write_text(json.dumps(payload), encoding="utf-8")

    def test_matching_cache_is_published(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "mapped4.json"
            self.write_state(path)
            candidate = candidates.mapped_candidate_from_state(
                51820, "192.168.1.10", str(path)
            )
            self.assertEqual(candidate["type"], "mapped4")
            self.assertEqual(candidate["endpoint"], "8.8.8.8:62000")

    def test_wrong_internal_port_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "mapped4.json"
            self.write_state(path)
            self.assertIsNone(
                candidates.mapped_candidate_from_state(
                    33967, "192.168.1.10", str(path)
                )
            )

    def test_expired_cache_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "mapped4.json"
            self.write_state(path, expires_at=time.time() - 1)
            self.assertIsNone(
                candidates.mapped_candidate_from_state(
                    51820, "192.168.1.10", str(path)
                )
            )


if __name__ == "__main__":
    unittest.main()
