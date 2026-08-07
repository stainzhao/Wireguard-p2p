# WireGuard P2P v7.0-alpha protocol

## Goal

v7 将控制面从“单 Endpoint 交换”升级为“Candidate 列表交换”。
alpha 阶段只建立候选发现、校验和交换协议，仍保留 v6.2 的单 Endpoint 探测行为，
因此可以滚动升级而不改变现有 P2P / VPS fallback 逻辑。

## Candidate schema

```json
{
  "type": "host6",
  "family": "udp6",
  "endpoint": "[2001:db8::1]:51820",
  "priority": 900,
  "verified": false
}
```

IPv6 Endpoint 必须使用 `[address]:port` 格式。

## Candidate types and priority

```text
lan4       1000   private LAN IPv4
host6       900   global-unicast IPv6
mapped4     800   PCP/NAT-PMP/UPnP mapping (reserved for v7.1)
observed4   600   public IPv4 endpoint observed by VPS
predicted4  400   symmetric-NAT prediction (reserved for v7.2)
```

`observed4` 是可信候选，只能由 VPS 根据 `wg show wg0 dump` 的实际 Endpoint 生成。
客户端/Agent 上报 `observed4` 会被拒绝。

## POST /connect and /sync

v7 客户端继续发送 v6 的兼容字段，同时增加 `protocol` 与 `candidates`：

```json
{
  "protocol": 7,
  "lan_ip": "192.168.1.13",
  "listen_port": 58442,
  "candidates": [
    {
      "type": "lan4",
      "family": "udp4",
      "endpoint": "192.168.1.13:58442",
      "priority": 1000
    },
    {
      "type": "host6",
      "family": "udp6",
      "endpoint": "[2001:db8::13]:58442",
      "priority": 900
    }
  ]
}
```

VPS 响应中的每个 peer 同时保留：

- `endpoint`: v6 兼容的 WG-observed Endpoint
- `lan_endpoint`: v6 兼容 LAN Endpoint
- `candidates[]`: v7 候选列表

## VPS -> Linux Agent /offer

`/offer` 继续携带旧 `endpoint` / `endpoint_type`，同时增加完整候选列表：

```json
{
  "protocol": 7,
  "peer_key": "...",
  "peer_ip": "10.0.0.4",
  "endpoint": "8.8.8.8:40000",
  "endpoint_type": "WAN",
  "candidates": [],
  "lease_expires": 1786082000
}
```

alpha Agent 仍优先使用旧 `endpoint` 进行探测，但会保存 `candidates[]`，并在响应中返回服务器自身的 LAN4 / host6 candidates。

## IPv6 discovery

Windows 和 Linux 只发布公网可路由 IPv6：

- 排除 loopback
- 排除 `fe80::/10`
- 排除 ULA `fc00::/7`
- 排除 multicast
- Linux 排除 tentative/deprecated 地址

公网 VPS 本身没有 IPv6也不影响 host6 candidate 的交换；VPS 只承担 IPv4 控制面。

## Relay-first invariant

v7 保持现有安全回退模型：

1. VPS `/24` 路由始终存在。
2. Candidate 探测期间不抢占真实业务流量。
3. WireGuard 握手成功后才添加目标 `/32`。
4. 直连失效后删除 `/32`，立即恢复 VPS 路径。

## Compatibility

v7.0-alpha intentionally keeps legacy fields. Upgrade order can therefore be:

1. VPS
2. Linux Agents
3. Windows client

v6.2 Windows/Linux 节点仍可继续使用旧 `endpoint` / `lan_endpoint` 字段。

## Next stages

- v7.0-beta: candidate probe state machine; LAN4 / host6 / observed4 快速切换
- v7.0: session nonce / strict replay protection; stable candidate path selection
- v7.1: PCP -> NAT-PMP -> UPnP `mapped4`
- v7.2: NAT behavior probing and conditional `predicted4`
