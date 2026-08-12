#!/usr/bin/env python3
from pathlib import Path

path = Path("p2p/wireguard-p2p-client/probe.go")
text = path.read_text(encoding="utf-8")
old = '''\tcase "host6":\n\t\tif candidate.Priority > candidatePriorityHost6 {\n\t\t\treturn simultaneousIPv6Window\n\t\t}\n\tcase "reflexive6":\n'''
new = '''\tcase "host6":\n\t\tif candidate.Priority > candidatePriorityHost6 {\n\t\t\treturn simultaneousIPv6Window\n\t\t}\n\t\treturn candidateProbeWindow\n\tcase "reflexive6":\n'''
if text.count(old) != 1:
    raise SystemExit("expected generated host6 window block exactly once")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
