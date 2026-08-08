# Current architecture — v7.10.1

## 1. Control/relay baseline

VPS `10.0.0.1` 同时承担 Coordinator/control plane 和 WireGuard `/24` Relay。P2P 只是增强层；只有 fresh authenticated WireGuard handshake 成功后才安装目标 `/32` Direct route。失败或 Direct stale 时删除动态 `/32`，自然回退 `/24`。

## 2. Generic node roles

具体 IP 尾号不再进入程序逻辑。除 Coordinator/network/broadcast 地址外，Overlay Peer 默认是 `client`；VPS 可显式配置：

```text
server       -> Linux Python Agent，可被 Client 动态发现
relay_only   -> 不参与 P2P 协调，只保留基础 Relay
client       -> 默认，无需注册
```

角色文件：

```text
/etc/wireguard-p2p/servers.conf
/etc/wireguard-p2p/relay-only.conf
```

Coordinator 的 `peer_payload()` 将实时角色返回给 Go Client，因此新增/删除 Server 不要求重编译 Client。Server bootstrap key 只向当前 `server` 角色 IP 返回。

## 3. Candidate priority

```text
lan4        1000
host6        900
observed6    850
reflexive6   825
mapped4      800
observed4    700
predicted4   500
VPS /24      baseline
```

IPv6 NAT66 simultaneous punch、IPv4 observed4 simultaneous punch、bounded predicted4、PCP/NAT-PMP/UPnP mapped4 均继续遵守 fresh-handshake promotion。

## 4. Security and lifecycle

VPS -> Server Agent 使用 HMAC-SHA256，带 timestamp、128-bit nonce 和 session identity。旧 session 不能覆盖新 session。Control lease 与健康 Direct 解耦；Direct 健康由真实 WireGuard handshake 和 `/32` route 判断。

## 5. Cross-platform Client

Windows amd64、Linux amd64、Linux arm64 使用同一 Go core。Client 从 Coordinator 返回的 `role=server` 动态构造目标集合，不包含固定 Server 公钥/IP 表。

## 6. Genericity boundary

v7.10 去除了具体节点 `.2/.5/.8` 的硬编码。默认网络拓扑仍为 `10.0.0.0/24`、Coordinator `10.0.0.1`、接口 `wg0`；这是下一层可参数化配置，不影响当前任意 `.x` 节点的动态角色能力。
