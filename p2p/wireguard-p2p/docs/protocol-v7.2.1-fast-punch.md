# WireGuard P2P v7.2.1 fast IPv6 punch

## Purpose

v7.2 proved that a router-translated server can establish WireGuard P2P through IPv6 without an IPv6 VPS. The first real-world run took about 73 seconds because the Linux server agent waited 60 seconds before its second active candidate probe.

v7.2.1 keeps the same verified `observed6` design and removes that delay.

## Fast retry schedule

The event agent now uses:

```text
failure 1 -> retry after 3 s
failure 2 -> retry after 10 s
failure 3+ -> 30 min cooldown
```

This gives the NAT66/stateful router a second WireGuard handshake attempt almost immediately, while still entering a long cooldown when direct connectivity is genuinely unavailable.

## Windows passive watcher

When Windows has native IPv6 and the remote server has no usable `host6`, failed active probes leave a route-less passive WireGuard peer armed.

v7.2.1 adds a 15-second watcher that polls WireGuard state every 250 ms. If an authenticated inbound handshake creates a fresh global IPv6 endpoint, Windows immediately classifies it as `observed6` and installs the remote `/32` route.

The watcher accepts only:

```text
fresh authenticated handshake <= 5 s old
+ usable global IPv6 endpoint
+ unchanged peer generation
+ passive6 state
```

Special-use IPv6 such as `2001:3::/32` is still rejected.

## Expected timing

For the observed campus topology:

```text
T+0 s    Windows active candidates fail; passive6 armed
T+3 s    router-side Linux server retries Windows host6
T+3.x s  Windows receives authenticated WireGuard handshake
T+3.x s  learned NAT66 endpoint promoted as observed6
```

The practical target is approximately 3-5 seconds instead of roughly 60-75 seconds.

If the fast retry also fails, a second attempt occurs after 10 seconds. Repeated failures then enter the normal 30-minute cooldown, so the optimization does not create continuous UDP traffic.

## Path policy

```text
same-LAN lan4
-> native host6
-> learned observed6
-> mapped4
-> observed4
-> predicted4
-> IPv4 VPS relay
```

The VPS remains control-plane and fallback infrastructure. Successful `host6` or `observed6` paths carry the application data directly over IPv6.
