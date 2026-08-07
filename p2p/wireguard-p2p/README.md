# WireGuard P2P v7.0-beta

该项目在保留 VPS `10.0.0.1` 中转路由的同时，为 Windows 客户端与 GPU `10.0.0.2`、2696 `10.0.0.5` 建立动态 `/32` P2P 路由。

v7.0-beta 已从 v6 的“单 Endpoint 长时间探测”升级为 **Candidate 列表 + 后台快速路径探测**。VPS 中转始终保持可用；只有候选路径产生新的 WireGuard 认证握手后，才安装对应 `/32` 直连路由。

## 运行结构

- VPS：`peers-api.service`，`10.0.0.1:8899`，负责会话、候选汇聚、`/offer`/`/remove` 协调。
- GPU、2696：`wireguard-p2p-agent.service`，分别监听 `10.0.0.2:8898`、`10.0.0.5:8898`。
- Windows：`wireguard-p2p.exe`，负责候选上报、路径探测和 `/32` 路由升级。
- 手机 `10.0.0.8`：固定 VPS 中转，不参与 P2P。

## Candidate 类型

```text
lan4       1000   同局域网私有 IPv4
host6       900   公网可路由 IPv6
mapped4     800   PCP/NAT-PMP/UPnP（v7.1 预留）
observed4   600   VPS 从 WireGuard 实际观察到的公网 IPv4
predicted4  400   对称 NAT 预测端口（v7.2 预留）
```

Windows 和 Linux Agent 自动上报 `lan4` 与可用 `host6`。VPS 根据 `wg show wg0 dump` 生成可信 `observed4`，节点不能自行声明 `observed4`。IPv6 Endpoint 统一使用 `[IPv6]:port`。

协议文档：

- `docs/protocol-v7-alpha.md`：Candidate 交换阶段
- `docs/protocol-v7-beta.md`：当前快速探测状态机

## 当前路径选择

```text
同 NAT / 同 LAN时： lan4
                     ↓
                 host6 IPv6
                     ↓
                 mapped4（预留）
                     ↓
                 observed4 IPv4 打洞
                     ↓
                 predicted4（预留）

任何阶段失败：VPS /24 路由始终仍可用
```

远端 `lan4` 只有在两端被 VPS 观察为同一公网 IPv4/NAT 时才会尝试，避免把不可路由的私网地址当作互联网候选。

Windows 端会在本机没有公网 IPv6 能力时跳过远端 `host6`。Linux 候选模块也支持该能力过滤；当前 beta Agent 在少数无 IPv6 环境下仍可能额外花约 2 秒尝试一个 `host6`，不会影响 VPS 回退。

## 快速探测状态机

每个候选默认探测约 2 秒，最多选择 5 个候选，因此一次完整候选轮换通常不超过约 10 秒。

探测阶段：

```text
PersistentKeepalive = 1
AllowedIPs 不添加目标 /32
真实流量继续走 VPS
```

成功条件不是“已有握手还很新”，而是：

```text
latest_handshake > candidate 安装前记录的 baseline handshake
```

成功后：

```text
读取 WireGuard 实际学习到的 Endpoint
添加目标 10.0.0.x/32
PersistentKeepalive = 25
```

全部候选失败后动态 Peer 被删除，仍走 VPS，并采用：

```text
第 1 次失败：60 秒
第 2 次失败：120 秒
第 3 次及以后：30 分钟
```

Candidate 列表、IPv6 地址或公网 Endpoint 发生变化时会立即解除旧冷却并重新评估。

## Relay-first 不变量

项目始终遵循：

```text
VPS /24 始终可用
       |
       +-- 后台 candidate probe
               |
               +-- 新认证握手成功 -> 添加 /32
               |
               +-- 失败/失效 -> 删除动态 Peer -> VPS
```

**没有新的认证直连握手，就不会创建动态 `/32`。**

这保证了 P2P 优化失败不会把正常中转连接一起切断。

## 直连健康检查

已建立直连后，WireGuard 握手超过 180 秒未更新时：

1. 删除动态 `/32` Peer；
2. 流量立即回到 VPS；
3. 后台重新启动 Candidate 探测。

180 秒阈值用于避开 WireGuard 正常约 120 秒 rekey 周期造成的误判。

## Candidate worker 取消机制

Windows 与 Linux beta 状态机均维护 generation/session-like generation 标识。候选变化、直连失效、Peer 删除或程序退出会使旧 generation 失效，后台 worker 检测到后立即停止，避免旧网络上的探测结果覆盖新网络状态。

## 兼容策略

v7 继续保留旧字段：

```text
endpoint
endpoint_type
lan_endpoint
lan_ip
listen_port
```

`candidates[]` 是增量字段，因此仍支持滚动升级。推荐顺序：

```text
VPS -> Linux Agents -> Windows client
```

## 日志与诊断

Linux Agent 默认保持安静，只记录异常；临时诊断：

```bash
P2P_VERBOSE_LOG=1
systemctl restart wireguard-p2p-agent.service
journalctl -u wireguard-p2p-agent.service -f
```

VPS：

```bash
systemctl status peers-api.service
curl --noproxy '*' http://10.0.0.1:8899/health
```

Agent `/health` 会返回当前 `state_count` 和 `probing` 数量。

## 文件结构

```text
wireguard-p2p/
├── docs/
│   ├── protocol-v7-alpha.md
│   └── protocol-v7-beta.md
├── linux/
│   ├── candidates.py
│   ├── p2p_agent.py
│   └── wireguard-p2p-agent.service
├── tests/
│   ├── test_peer_logic.py
│   └── test_protocol_v7.py
└── vps/
    ├── peers_api.py
    └── peers-api.service

wireguard-p2p-exe/
├── candidate.go
├── candidate_test.go
├── probe.go
├── main.go
└── main_test.go
```

`.github/workflows/v7-tests.yml` 会在 `main` 每次提交后自动运行 Python 与 Go 测试。

## 回滚点

```text
backup/pre-v7-alpha-20260807
backup/pre-v7-beta-20260807
```

## 后续路线

```text
v7.0
  session_id + nonce 严格防重放
  /remove 与 session 绑定
  Linux host6 本地能力过滤收尾
  实网路径统计与重评估

v7.1
  PCP -> NAT-PMP -> UPnP
  mapped4 映射续期与健康检查

v7.2
  NAT 行为探测
  仅在端口分配可预测时生成 predicted4

v8（如确有需要）
  userspace WireGuard + UDP mux / ICE
```
