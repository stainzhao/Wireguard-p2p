# WireGuard P2P v7.0 protocol

## 1. Design goal

v7.0 keeps the existing kernel/official WireGuard data plane and upgrades only the P2P control plane.

The permanent invariant is relay-first:

```text
VPS /24 relay remains available
        |
        +-- candidate probe runs in background
                |
                +-- new authenticated WG handshake -> install /32
                |
                +-- failure/stale direct -> remove dynamic peer -> VPS
```

A direct `/32` is never installed from coordinator metadata alone.

## 2. Candidate model

```text
lan4       priority 1000
host6       priority 900
mapped4     priority 800   reserved for v7.1
observed4   priority 600
predicted4  priority 400   reserved for v7.2
```

`observed4` is generated only by the VPS from `wg show wg0 dump` and is not accepted from node advertisements.

IPv6 endpoints use `[IPv6]:port`.

## 3. Probe model

Windows and Linux use asynchronous candidate workers.

- per-candidate window: about 2 seconds
- maximum candidates: 5
- probe keepalive: 1 second
- established direct keepalive: 25 seconds

Before each candidate is installed, the worker records the current WireGuard handshake timestamp as `baseline_handshake`.

Success requires:

```text
latest_handshake > baseline_handshake
```

After success, the endpoint actually learned by WireGuard is retained and the target overlay `/32` is installed.

## 4. Session identity

Every client session created by the VPS receives:

```json
{
  "session_id": "UUIDv4",
  "session_started_ns": 1786090000000000000
}
```

The pair is included in `/offer`.

Linux Agent stores it with dynamic peer state. A newer session can replace an older session, but an `/offer` carrying an older `session_started_ns` is ignored.

This prevents a delayed old offer from replacing a newly established session.

## 5. Session-scoped removal

`/remove` contains:

```json
{
  "session_id": "...",
  "peer_key": "...",
  "peer_ip": "10.0.0.x"
}
```

The Agent removes a dynamic peer only when all three values match current state.

A delayed `/remove` from an old session therefore returns success with `removed=false` and cannot delete the new peer.

## 6. Signed server notifications

VPS -> Linux Agent notification authentication uses a shared HMAC-SHA256 key.

Signed bytes are:

```text
METHOD\n
PATH\n
TIMESTAMP\n
NONCE\n
BODY
```

Headers:

```text
X-P2P-Timestamp
X-P2P-Nonce
X-P2P-Signature
```

Nonce is 128 random bits encoded as 32 hexadecimal characters.

Agent requirements:

- source overlay address must be `10.0.0.1`
- timestamp skew <= 30 seconds
- HMAC must match
- nonce must not have been seen before
- nonce cache TTL = 60 seconds
- cache is bounded to 4096 entries

The nonce is consumed only after HMAC verification succeeds.

## 7. Lease and stale direct handling

- coordinator session lease: 120 seconds
- Agent local lease is independently enforced
- direct handshake stale threshold: 180 seconds
- candidate failure backoff: 60 s, 120 s, then 30 min

Candidate signature changes reset cooldown and start a new worker generation.

## 8. API compatibility fields

v7 still exposes legacy endpoint fields alongside `candidates[]`:

```text
endpoint
endpoint_type
lan_endpoint
lan_ip
listen_port
```

They remain for protocol observability and migration, but v7 path selection uses the candidate list.

## 9. Security test requirements

CI must verify at minimum:

- identical signed notification cannot be accepted twice
- signature is bound to HTTP path
- old session `/remove` cannot remove current session
- delayed older `/offer` cannot replace current session
- coordinator refresh reuses the current session ID
- Candidate/IPv6/probe tests remain green
