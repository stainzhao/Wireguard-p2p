# WireGuard P2P v7.0-alpha protocol

## Goal
Upgrade the coordinator from single endpoint exchange to candidate based path selection.

## Candidate types

- `lan4`: same LAN IPv4 candidate
- `host6`: global IPv6 candidate
- `mapped4`: PCP/NAT-PMP/UPnP mapping candidate (reserved for v7.1)
- `observed4`: endpoint observed by VPS

## Priority

```
lan4       1000
host6       900
mapped4     800
observed4   600
```

## Transition

v7 keeps the current relay-first architecture:

1. VPS `/24` route remains available.
2. Candidates are exchanged through VPS control plane.
3. Successful WireGuard handshake promotes `/32` direct routing.
4. Failed direct paths return to VPS automatically.
