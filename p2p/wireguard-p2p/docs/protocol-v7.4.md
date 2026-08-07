# WireGuard P2P v7.4 — Connectivity-first runtime

v7.4 不改变 v7.3 已验证的候选优先级、simultaneous IPv6 punch 或 VPS `/24` relay 基线；目标是降低稳定运行成本并解除已建立 Direct 对 VPS control lease 的硬依赖。

## 不变量

1. VPS relay `10.0.0.0/24` 保持可用。
2. 动态 `/32` 仍只能在 fresh authenticated WireGuard handshake 后安装。
3. `PersistentKeepalive=25` 暂不优化，优先保证 NAT66/stateful firewall 稳定。
4. 显式客户端 disconnect 与 superseded session 必须立即撤销动态 peer。

## 自适应周期

- Windows discovery/recovery sync: 15 s。
- Windows stable direct sync: 60 s，仅 coordinator >=7.4 时启用。
- Linux active monitor: 5 s。
- Linux stable direct monitor: 30 s。
- Linux idle monitor: 60 s。
- reflexive6 refresh: 600 s，cache TTL 1800 s。
- mapped4 local check: 60 s；只有映射变化/续租时写 RAM state。

## Control lease 与 Direct 分离

VPS session TTL 为 180 s。reaper 对 Agent 发送 `/remove` 时携带 reason：

- `disconnect`: 显式退出，立即删除。
- `superseded`: 旧 key/session 被替代，立即删除。
- `expired`: 仅 control session 超时。若当前 `/32` peer 的 latest handshake 仍在 `DIRECT_MAX_AGE=180 s` 内，则设置 `control_expired=true` 并保留 Direct。

如果 VPS 完全不可达，Agent 本地 lease 到期执行相同逻辑：健康 Direct 保留；Direct 之后真正变 stale 才删除并自然回到 VPS `/24` 基线。

VPS 恢复或重启后会创建新 session。Agent 只要确认新的 `session_started_ns` 更新且现有 Direct 健康，就更新 control session 元数据而不删除 WireGuard peer。

## Runtime state

运行态文件：

```text
/run/wireguard-p2p/state.json
/run/wireguard-p2p/mapped4.json
```

这些文件允许重启后丢失；程序会重新通过 VPS 建链。永久材料仍只放在 `/etc`、程序安装目录和 WireGuard 配置中。
