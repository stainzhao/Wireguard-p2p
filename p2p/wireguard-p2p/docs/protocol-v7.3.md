# WireGuard P2P v7.3 — Simultaneous IPv6 NAT Traversal

## 目标

v7.3 解决以下已实测拓扑：

- `10.0.0.2` 直连校园网，拥有原生 `2001:da8:...`，`host6` 可直接 P2P；
- `10.0.0.5` 位于路由器后，本机看到 `2001:3::/32`，对外被转换为 `2001:da8:...`；
- 某些客户端（例如部分家用 IPv6 路由器）允许出站 IPv6，但拒绝未经状态匹配的新入站 UDP；
- 因此 v7.2.2 的“Windows passive6 + 服务器主动打入”能在手机热点成功，但在双边都有 stateful firewall 时仍可能失败。

v7.3 不要求 VPS 拥有 IPv6，也不要求 `10.0.0.2` 常在线。

## Candidate 优先级

```text
lan4        1000   同 LAN IPv4
host6        900   本机真实原生公网 IPv6
observed6    850   WireGuard 已认证握手学习到的公网 IPv6 Endpoint
reflexive6   825   NAT66 外部 IPv6 + WireGuard ListenPort（未验证）
mapped4      800   PCP/NAT-PMP/UPnP IPv4 显式映射
observed4    600   VPS 观察到的 IPv4 NAT Endpoint
predicted4   400   预留
```

`reflexive6` 永远以 `verified=false` 发布，且优先级低于已认证学习得到的 `observed6`。

## reflexive6 发现

Linux Agent 启动时：

1. 先检查是否存在可用 `host6`；若存在则不做 reflexive discovery；
2. 若只有特殊用途/内部 IPv6（例如 `2001:3::/32`），通过 IPv6-only 地址回显服务查询 NAT66 后的外部 IPv6；
3. 将外部 IPv6 与**当前 WireGuard 内核 ListenPort**组合为 `reflexive6`；
4. 缓存 10 分钟，每 5 分钟后台刷新。

当前发现服务按顺序尝试：

```text
https://api6.ipify.org
https://6.ident.me
https://ipv6.icanhazip.com
```

所有请求禁用系统 HTTP 代理，以避免把代理出口地址误认为本机 NAT66 地址。

### 端口假设

`reflexive6` 假设 NAT66 对 WireGuard UDP 端口保持不变。该假设在当前 `10.0.0.5` 实测中成立：

```text
内部 WG ListenPort: 33967
外部 observed6 port: 33967
```

如果路由器改写 UDP 端口，`reflexive6` 只会探测失败；因为 fresh WireGuard handshake 是提升 `/32` 的必要条件，所以不会产生错误直连路由。

## simultaneous punch 时序

客户端 `/connect` 到 VPS 后：

```text
                 IPv4 VPS control plane
                 /connect + /offer
                     /        \
                    /          \
              Windows          Linux .5
              host6            NAT66
                |                |
                |---- WG ------->|  probe reflexive6
                |<---- WG -------|  probe Windows host6
                |                |
          client firewall    server firewall
             state open         state open
                \                /
                 \              /
               authenticated WG handshake
                         |
                  Endpoint roaming
                         |
                       /32
```

VPS 只协调 Candidate，不承载 IPv6 P2P 数据面。

## 时间窗口

普通 Candidate 仍使用约 2 秒探测窗口。

对于 simultaneous IPv6：

- Windows 探测 `reflexive6`：最多 8 秒；
- NAT66 Linux 节点探测客户端 `host6`：最多 8 秒；
- 两个方向因此有充分重叠时间建立各自路由器/防火墙状态。

成功判定仍必须满足：

```text
LatestHandshake > baseline handshake
```

只有成功后才：

```text
AllowedIPs += peer_overlay_ip/32
PersistentKeepalive = 25
```

## v7.2.2 compatibility path

如果 reflexive IPv6 发现失败，或路由器并非端口保持型：

1. `reflexive6` 不发布或探测失败；
2. v7.2.2 `passive6 + confirmation rekey` 仍保留；
3. IPv4 mapped/observed Candidate 仍继续尝试；
4. VPS `/24` relay 始终是最终兜底。

因此 v7.3 是增量能力，不删除原有成功路径。

## 诊断

在 Linux server 本机：

```bash
curl http://10.0.0.5:8898/health
```

应能看到 Agent 版本和 reflexive6 状态。对于当前 `.5`，理想值应类似：

```text
2001:da8:216:191a:5ad9:d5ff:fe0d:dcf1
```

Windows 成功尝试时会输出：

```text
Simultaneous IPv6 punch 10.0.0.5 via [2001:da8:...]:33967.
P2P OK 10.0.0.5 via reflexive6/observed6 ...
```

最终 `wg show` 中看到的实际 Endpoint 才是权威结果。

## 安全不变量

- `2001:3::/32` 等特殊用途前缀不得作为 `host6`；
- `reflexive6` 不是可信路由，只是 Candidate；
- Candidate 自报不能绕过 WireGuard 密钥认证；
- 没有 fresh authenticated handshake 就不能安装 `/32`；
- session-scoped `/remove`、HMAC timestamp/nonce 防重放机制保持不变；
- P2P 失败不能破坏 VPS relay。
