# Linux low-write runtime policy

This policy is operational only. It does **not** change Candidate selection, IPv6 simultaneous punch, WireGuard peer promotion, Direct/VPS lease behavior, or the baseline VPS relay route (`AllowedIPs = 10.0.0.0/24`).

## Runtime state

Linux runtime state is kept under `/run/wireguard-p2p`, which is normally tmpfs-backed RAM on systemd Linux systems:

- Agent state: `/run/wireguard-p2p/state.json`
- mapped4 cache: `/run/wireguard-p2p/mapped4.json`
- legacy sync compatibility state: `/run/wireguard-p2p/legacy-sync-state.json`
- process locks: `/run/wireguard-p2p/*.lock`

These files are small snapshots that are replaced/updated in place. They do not accumulate with uptime and are intentionally lost at reboot. The network state is rebuilt from WireGuard plus the coordinator after restart.

The mapped4 cache does not call `fsync()` because durability of a tmpfs runtime cache is unnecessary.

## Journald policy

The Linux service units use:

```ini
StandardOutput=null
StandardError=journal
LogRateLimitIntervalSec=5min
LogRateLimitBurst=20
```

Normal event/status output therefore does not enter the persistent journal. Actual stderr diagnostics and Python tracebacks remain available, while repeated failures are rate-limited to prevent a fault loop from generating excessive journal writes.

Systemd's own unit start/stop messages can still appear in the journal; those are infrequent lifecycle records rather than steady-state P2P writes.

## Debugging

The normal production units intentionally discard stdout. For detailed temporary debugging, run the Agent manually in a shell with `P2P_VERBOSE_LOG=1`, or temporarily override the unit's output policy and restore it after diagnosis. Do not enable verbose logging permanently on long-running servers.

## Legacy synchronizer

`p2p_sync.py` is retained for compatibility with older deployments. Its runtime state is also RAM-backed. Its routine stdout is discarded by the compatibility unit, while synchronization errors are emitted to stderr so they remain diagnosable.
