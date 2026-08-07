# Current architecture

本文档描述 `main` 当前唯一实现（v7.4.0），不记录历史版本演进。

## 1. 拓扑与不变量

VPS `10.0.0.1` 同时承担 rendezvous/control plane 和 WireGuard `/24` relay。Windows 与 Linux server 在后台尝试 direct candidate；只有 fresh authenticated WireGuard handshake 成功后才给目标安装更具体的 `10.0.0.x/32`。

因此：

- probe 期间业务仍走 VPS `/24`；
- probe 失败只删除动态 peer，不破坏 relay；
- direct stale 后删除 `/32`，内核路由自然回到 `/24`；
- 不允许“仅因为 Candidate 看起来合理”就切换业务路由。

## 2. Candidate

```text
lan4        1000
host6        900
observed6    850
reflexive6   825
mapped4      800
observed4    600
predicted4   400
```

`2001:3::/32` 等特殊用途 IPv6 不作为普通 `host6` 发布。

`reflexive6` 是 Linux server 无可用 native host6 时发现的 NAT66 外部 IPv6，再与当前 WireGuard ListenPort 组合出的**未验证**候选。它永远不能仅凭控制面信息提升为 direct。

## 3. IPv6 simultaneous punch

当 server 需要 NAT66 穿透时：

1. Windows 对 server `reflexive6` 主动发送 WireGuard handshake；
2. Linux server 同时对 Windows `host6` 主动发送 handshake；
3. 两侧 outbound UDP 状态形成重叠窗口；
4. 任一 fresh authenticated WireGuard handshake 成功后读取 WireGuard 实际 roaming endpoint；
5. 安装目标 `/32`，恢复 `PersistentKeepalive=25`。

Windows passive IPv6 watcher 与 Linux confirmation rekey 仍是当前机制的一部分，用于处理首次握手早于另一侧就绪的竞态。

## 4. IPv4 direct

Linux 可按 PCP -> NAT-PMP -> UPnP 尝试显式 UDP 映射并发布 `mapped4`。若没有显式映射，则仍可尝试 VPS 观察到的 `observed4`。所有 IPv4 direct 与 IPv6 direct 使用相同的 fresh-handshake promotion 原则。

## 5. 控制面安全

每个客户端控制 session 使用 UUID `session_id` 和可比较的 `session_started_ns`。VPS -> Agent 请求使用 HMAC-SHA256：

```text
METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY
```

Agent 校验时间窗口、随机 nonce 和重放缓存。旧 session 不能覆盖更新 session；remove 必须匹配 peer key、overlay IP 和 session。

## 6. Direct/control 解耦

协调器 control lease 与已认证 WireGuard direct 不再是同一生命周期。control lease 到期时，如果 `/32` peer 仍存在且最近 handshake 不超过 180 秒，则 Agent 标记 control expired 但保留 direct。

显式 disconnect/superseded 仍会立即删除动态 peer。若 direct handshake 自身超过 180 秒，动态 `/32` 被删除并回退 VPS relay。

## 7. 稳定态资源策略

- Windows：恢复态 15 秒 control sync；稳定 direct 60 秒。
- Linux：恢复态 5 秒检查；稳定 direct 30 秒；无 session 60 秒。
- reflexive6：600 秒刷新，1800 秒缓存 TTL。
- mapped4 daemon：60 秒后台检查，仅在映射建立/续租/变化/失效时更新 RAM 状态。
- NAT/stateful 路径继续使用 `PersistentKeepalive=25`。
