#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def write(path, text):
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit("{}: expected one match, got {}".format(label, count))
    return text.replace(old, new, 1)


# Go client: rank the IPv6 source that the OS would actually select above backup GUAs.
path = "p2p/wireguard-p2p-client/candidate.go"
text = read(path)
text = replace_once(
    text,
    "\tcandidatePriorityLAN4       = 1000\n\tcandidatePriorityHost6      = 900\n",
    "\tcandidatePriorityLAN4           = 1000\n\tcandidatePriorityPreferredHost6 = 910\n\tcandidatePriorityHost6          = 900\n",
    "go priority constants",
)
text = replace_once(
    text,
    "var nonHostIPv6CIDRs = []string{",
    "var preferredIPv6ProbeTargets = []string{\n\t\"2606:4700:4700::1111\",\n\t\"2001:4860:4860::8888\",\n}\n\nvar nonHostIPv6CIDRs = []string{",
    "go preferred targets",
)
pattern = re.compile(r"func gatherLocalCandidates\(listenPort int, lanIP string\) \[\]Candidate \{.*?\n\}\n\nfunc globalIPv6Addresses", re.S)
replacement = r'''func gatherLocalCandidates(listenPort int, lanIP string) []Candidate {
	result := make([]Candidate, 0, 4)
	if ip := net.ParseIP(lanIP); ip != nil && ip.To4() != nil && ip.IsPrivate() {
		result = append(result, Candidate{
			Type:     "lan4",
			Family:   "udp4",
			Endpoint: net.JoinHostPort(ip.String(), strconv.Itoa(listenPort)),
			Priority: candidatePriorityLAN4,
		})
	}

	preferred := preferredGlobalIPv6Address()
	for _, ip := range globalIPv6Addresses() {
		priority := candidatePriorityHost6
		if preferred != nil && ip.Equal(preferred) {
			priority = candidatePriorityPreferredHost6
		}
		result = append(result, Candidate{
			Type:     "host6",
			Family:   "udp6",
			Endpoint: net.JoinHostPort(ip.String(), strconv.Itoa(listenPort)),
			Priority: priority,
		})
	}

	result = dedupeCandidates(result)
	sortCandidates(result)
	return result
}

func preferredGlobalIPv6Address() net.IP {
	for _, target := range preferredIPv6ProbeTargets {
		remote := net.ParseIP(target)
		if remote == nil {
			continue
		}
		conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: remote, Port: 53})
		if err != nil {
			continue
		}
		local, _ := conn.LocalAddr().(*net.UDPAddr)
		_ = conn.Close()
		if local == nil || !isUsableGlobalIPv6(local.IP) {
			continue
		}
		return append(net.IP(nil), local.IP...)
	}
	return nil
}

func globalIPv6Addresses'''
text, count = pattern.subn(replacement, text, count=1)
if count != 1:
    raise SystemExit("go gatherLocalCandidates replacement failed")
write(path, text)

# Go probe: give the preferred host6 pair a real overlap window and make every IPv6 attempt visible.
path = "p2p/wireguard-p2p-client/probe.go"
text = read(path)
text = replace_once(
    text,
    '''func probeWindowForCandidate(candidate Candidate) time.Duration {
\tswitch candidate.Type {
\tcase "reflexive6":
\t\treturn simultaneousIPv6Window
''',
    '''func probeWindowForCandidate(candidate Candidate) time.Duration {
\tswitch candidate.Type {
\tcase "host6":
\t\tif candidate.Priority > candidatePriorityHost6 {
\t\t\treturn simultaneousIPv6Window
\t\t}
\tcase "reflexive6":
\t\treturn simultaneousIPv6Window
''',
    "go preferred host6 window",
)
text = replace_once(
    text,
    '''\t\tif candidate.Type == "reflexive6" {
\t\t\ta.log("Simultaneous IPv6 punch " + serverIP + " via " + candidate.Endpoint + ".")
\t\t} else if candidate.Type == "observed4" {
''',
    '''\t\tif candidate.Type == "host6" {
\t\t\tif candidate.Priority > candidatePriorityHost6 {
\t\t\t\ta.log("Preferred IPv6 punch " + serverIP + " via " + candidate.Endpoint + ".")
\t\t\t} else {
\t\t\t\ta.log("Backup IPv6 probe " + serverIP + " via " + candidate.Endpoint + ".")
\t\t\t}
\t\t} else if candidate.Type == "reflexive6" {
\t\t\ta.log("Simultaneous IPv6 punch " + serverIP + " via " + candidate.Endpoint + ".")
\t\t} else if candidate.Type == "observed4" {
''',
    "go IPv6 probe logging",
)
write(path, text)

# Linux Agent candidate discovery: source-aware preferred host6 and robust deprecated filtering.
path = "p2p/wireguard-p2p/linux/candidates.py"
text = read(path)
text = replace_once(text, "import os\nimport subprocess\n", "import os\nimport socket\nimport subprocess\n", "python socket import")
text = replace_once(
    text,
    '''PRIORITY = {
    "lan4": 1000,
    "host6": 900,
''',
    '''PRIORITY = {
    "lan4": 1000,
    "host6": 900,
''',
    "python priority anchor",
)
text = replace_once(
    text,
    '''}
MAX_PROBE_CANDIDATES = 5
''',
    '''}
PREFERRED_HOST6_PRIORITY = 910
PREFERRED_IPV6_PROBE_TARGETS = (
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
)
MAX_PROBE_CANDIDATES = 5
''',
    "python preferred constants",
)
anchor = '''def global_ipv6_addresses():
'''
helpers = '''def ipv6_address_info_unusable(info):
    flags = set(info.get("flags", []) or [])
    if "tentative" in flags or "deprecated" in flags:
        return True
    for key in ("preferred_life_time", "preferred_lft"):
        if key not in info:
            continue
        value = info.get(key)
        if value == 0 or str(value).strip().lower() in ("0", "0sec"):
            return True
    return False


def preferred_source_ipv6():
    for target in PREFERRED_IPV6_PROBE_TARGETS:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            sock.connect((target, 53, 0, 0))
            address = sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()
        try:
            if usable_global_ipv6(address):
                return ipaddress.ip_address(address).compressed
        except ValueError:
            continue
    return ""


'''
text = replace_once(text, anchor, helpers + anchor, "python IPv6 helpers")
text = replace_once(
    text,
    '''            if "tentative" in info.get("flags", []) or "deprecated" in info.get("flags", []):
                continue
            address = info.get("local", "")
''',
    '''            if ipv6_address_info_unusable(info):
                continue
            address = info.get("local", "")
''',
    "python deprecated filter",
)
text = replace_once(
    text,
    '''    for address in global_ipv6_addresses():
        candidates.append({
            "type": "host6",
            "family": "udp6",
            "endpoint": format_endpoint(address, port),
            "priority": PRIORITY["host6"],
            "verified": False,
        })
''',
    '''    preferred = preferred_source_ipv6()
    for address in global_ipv6_addresses():
        candidates.append({
            "type": "host6",
            "family": "udp6",
            "endpoint": format_endpoint(address, port),
            "priority": (
                PREFERRED_HOST6_PRIORITY
                if address == preferred
                else PRIORITY["host6"]
            ),
            "verified": False,
        })
''',
    "python preferred host6 ranking",
)
write(path, text)

# Linux Agent: preferred host6 gets the same 8 s overlap window and explicit logs.
path = "p2p/wireguard-p2p/linux/p2p_agent.py"
text = read(path)
text = replace_once(
    text,
    '''    if candidate_type == "host6" and not global_ipv6_addresses():
        return SIMULTANEOUS_IPV6_WINDOW
''',
    '''    if candidate_type == "host6" and (
        int(candidate.get("priority", 0) or 0) > 900
        or not global_ipv6_addresses()
    ):
        return SIMULTANEOUS_IPV6_WINDOW
''',
    "agent preferred host6 window",
)
text = replace_once(
    text,
    '''        if candidate.get("type") == "observed4":
            log("Simultaneous IPv4 punch {} via {}".format(peer_ip, candidate.get("endpoint", "")))
        elif candidate.get("type") == "predicted4":
''',
    '''        if candidate.get("type") == "host6":
            if int(candidate.get("priority", 0) or 0) > 900:
                log("Preferred IPv6 punch {} via {}".format(peer_ip, candidate.get("endpoint", "")))
            else:
                log("Backup IPv6 probe {} via {}".format(peer_ip, candidate.get("endpoint", "")))
        elif candidate.get("type") == "observed4":
            log("Simultaneous IPv4 punch {} via {}".format(peer_ip, candidate.get("endpoint", "")))
        elif candidate.get("type") == "predicted4":
''',
    "agent IPv6 probe logging",
)
write(path, text)

# Regression tests.
path = "p2p/wireguard-p2p-client/candidate_test.go"
text = read(path)
if "TestPreferredHost6GetsOverlapWindow" not in text:
    text += r'''

func TestPreferredHost6GetsOverlapWindow(t *testing.T) {
	candidate := Candidate{
		Type:     "host6",
		Family:   "udp6",
		Endpoint: "[2001:da8:216:191a::1]:51820",
		Priority: candidatePriorityPreferredHost6,
	}
	if got := probeWindowForCandidate(candidate); got != simultaneousIPv6Window {
		t.Fatalf("preferred host6 window=%v want %v", got, simultaneousIPv6Window)
	}
	candidate.Priority = candidatePriorityHost6
	if got := probeWindowForCandidate(candidate); got != candidateProbeWindow {
		t.Fatalf("backup host6 window=%v want %v", got, candidateProbeWindow)
	}
}

func TestPreferredHost6SortsBeforeBackup(t *testing.T) {
	candidates := []Candidate{
		{Type: "host6", Endpoint: "[2001:da8::2]:51820", Priority: candidatePriorityHost6},
		{Type: "host6", Endpoint: "[2001:da8::1]:51820", Priority: candidatePriorityPreferredHost6},
	}
	sortCandidates(candidates)
	if candidates[0].Priority != candidatePriorityPreferredHost6 {
		t.Fatalf("preferred host6 was not first: %+v", candidates)
	}
}
'''
write(path, text)

path = "p2p/wireguard-p2p/tests/test_ipv6_punch.py"
text = read(path)
marker = '''    def test_confirmation_rekey_only_for_nat66_server_to_host6(self):
'''
new_tests = '''    def test_deprecated_ipv6_lifetime_is_rejected(self):
        self.assertTrue(candidates.ipv6_address_info_unusable({
            "flags": [], "preferred_life_time": 0,
        }))
        self.assertTrue(candidates.ipv6_address_info_unusable({
            "flags": ["deprecated"], "preferred_life_time": 120,
        }))
        self.assertFalse(candidates.ipv6_address_info_unusable({
            "flags": [], "preferred_life_time": "forever",
        }))

    def test_preferred_source_is_ranked_above_backup_host6(self):
        original_global = candidates.global_ipv6_addresses
        original_preferred = candidates.preferred_source_ipv6
        try:
            candidates.global_ipv6_addresses = lambda: [
                "2001:da8:216:191a::1",
                "2001:da8:216:191a::2",
            ]
            candidates.preferred_source_ipv6 = lambda: "2001:da8:216:191a::2"
            result = candidates.gather_candidates(51820)
            host6 = [item for item in result if item["type"] == "host6"]
            self.assertEqual(host6[0]["endpoint"], "[2001:da8:216:191a::2]:51820")
            self.assertEqual(host6[0]["priority"], candidates.PREFERRED_HOST6_PRIORITY)
            self.assertEqual(host6[1]["priority"], candidates.PRIORITY["host6"])
        finally:
            candidates.global_ipv6_addresses = original_global
            candidates.preferred_source_ipv6 = original_preferred

    def test_preferred_native_host6_gets_overlap_window(self):
        original = agent.global_ipv6_addresses
        try:
            agent.global_ipv6_addresses = lambda: ["2001:da8::1"]
            self.assertEqual(
                agent.candidate_probe_window({"type": "host6", "priority": 910}),
                agent.SIMULTANEOUS_IPV6_WINDOW,
            )
            self.assertEqual(
                agent.candidate_probe_window({"type": "host6", "priority": 900}),
                agent.CANDIDATE_PROBE_WINDOW,
            )
        finally:
            agent.global_ipv6_addresses = original

'''
if "test_deprecated_ipv6_lifetime_is_rejected" not in text:
    text = replace_once(text, marker, new_tests + marker, "python IPv6 regression tests")
write(path, text)

# Version bump runtime and current-version assertions, without rewriting historical release notes.
version_files = [
    "p2p/wireguard-p2p-client/main.go",
    "p2p/wireguard-p2p/vps/peers_api.py",
    "p2p/wireguard-p2p/linux/p2p_agent.py",
    "p2p/wireguard-p2p/manage/wireguard-p2p.py",
    "p2p/wireguard-p2p/tests/test_ipv6_punch.py",
    "p2p/wireguard-p2p/tests/test_ipv4_punch.py",
    "p2p/wireguard-p2p/tests/test_runtime.py",
    "p2p/wireguard-p2p-client/cross_platform_test.go",
]
for item in version_files:
    current = read(item)
    if "7.10.1" not in current:
        raise SystemExit("{}: expected v7.10.1 marker".format(item))
    write(item, current.replace("7.10.1", "7.11.0"))

# Current docs plus architecture description of the new candidate ranking.
path = "README.md"
text = read(path)
text = replace_once(text, "当前生产版本：**v7.10.1**，协议版本 7。", "当前生产版本：**v7.11.0**，协议版本 7。", "README current version")
anchor = "**v7.10 的核心变化：节点编号不再具有任何内置含义。**"
paragraph = "**v7.11 的 IPv6 变化：多 GUA 主机不再把所有 `host6` 当成完全等价。Client/Server 会询问操作系统实际的 IPv6 源地址选择，将该地址以更高优先级发布，并给首选 `host6` 8 秒重叠打洞窗口；deprecated/tentative IPv6 不再发布，IPv6 Probe 会明确写入日志。**\n\n"
if paragraph not in text:
    text = replace_once(text, anchor, paragraph + anchor, "README v7.11 note")
write(path, text)

path = "p2p/wireguard-p2p/docs/operations.md"
text = read(path)
text = replace_once(text, "当前版本：**v7.10.1**。", "当前版本：**v7.11.0**。", "operations current version")
write(path, text)

path = "p2p/wireguard-p2p/docs/architecture.md"
text = read(path)
text = replace_once(text, "# Current architecture — v7.10.1", "# Current architecture — v7.11.0", "architecture version")
text = replace_once(
    text,
    '''lan4        1000
host6        900
observed6    850
''',
    '''lan4                  1000
preferred host6          910
backup host6             900
observed6                850
''',
    "architecture candidate priority",
)
text = replace_once(
    text,
    "IPv6 NAT66 simultaneous punch、IPv4 observed4 simultaneous punch、bounded predicted4、PCP/NAT-PMP/UPnP mapped4 均继续遵守 fresh-handshake promotion。",
    "Native IPv6 会先按 OS 实际 source-address selection 选出 preferred host6；首选地址对使用 8 秒 overlap window，备用 GUA 再按顺序探测。deprecated/tentative 地址不发布。IPv6 NAT66 simultaneous punch、IPv4 observed4 simultaneous punch、bounded predicted4、PCP/NAT-PMP/UPnP mapped4 均继续遵守 fresh-handshake promotion。",
    "architecture source-aware description",
)
write(path, text)

print("v7.11 source-aware IPv6 transformation applied")
