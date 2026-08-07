# WireGuard P2P v7.0

该项目在保留 VPS `10.0.0.1` 中转路由的同时，为 Windows 客户端与 GPU `10.0.0.2`、2696 `10.0.0.5` 建立动态 `/32` P2P 路由。

v7.0 已完成从“单 Endpoint 长时间探测”到 **Candidate 列表 + 后台快速路径探测 + 会话隔离安全控制面** 的升级。VPS 中转始终保持可用；只有候选路径产生新的 WireGuard 认证握手后，才安装对应 `/32` 直连路由。

## 运行结构

- VPS：`peers-api.service`，`10.0.0.1:8899`，负责 session、候选汇聚、`/offer`/`/remove` 协调。
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

- `docs/protocol-v7.md`：v7.0 正式协议
- `docs/protocol-v7-beta.md`：快速探测阶段历史文档
- `docs/protocol-v7-alpha.md`：Candidate 交换阶段历史文档

## 路径选择

```text
同 NAT / 同 LAN：lan4
                  ↓
              host6 IPv6
                  ↓
              mapped4（v7.1）
                  ↓
              observed4 IPv4 打洞
                  ↓
              predicted4（v7.2）

任何阶段失败：VPS /24 路由始终仍可用
```

远端 `lan4` 只有在两端被 VPS 观察为同一公网 IPv4/NAT 时才会尝试，避免把不可路由的私网地址当作互联网候选。

Windows 在本机没有公网 IPv6 能力时会跳过远端 `host6`。Linux 候选模块也已具备 `allow_ipv6` 过滤能力；当前 Agent 在少数本机无 IPv6 的环境中仍可能额外花约 2 秒尝试一个 `host6`，但不会影响 VPS 回退。

## 快速探测状态机

每个候选默认探测约 2 秒，最多选择 5 个候选，因此一次完整候选轮换通常不超过约 10 秒。

探测阶段：

```text
PersistentKeepalive = 1
AllowedIPs 不添加目标 /32
真实流量继续走 VPS
```

成功要求产生新的认证握手：

```text
latest_handshake > candidate 安装前记录的 baseline_handshake
```

成功后：

```text
读取 WireGuard 实际学习到的 Endpoint
添加目标 10.0.0.x/32
PersistentKeepalive = 25
```

全部候选失败后删除动态 Peer，继续使用 VPS，并进入：

```text
第 1 次失败：60 秒
第 2 次失败：120 秒
第 3 次及以后：30 分钟
```

Candidate 列表、IPv6 地址或公网 Endpoint 变化会立即解除旧冷却并重新评估。

## Relay-first 不变量

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

因此候选探测、版本升级或控制面异常都不会切断 VPS 中转通路。

## v7.0 会话安全

VPS 为每个客户端连接创建：

```text
session_id         UUIDv4
session_started_ns 单调用于比较的新会话创建时间
```

两者随 `/offer` 下发并由 Linux Agent 保存。

### 防止旧 offer 覆盖新会话

如果一个迟到的 `/offer` 携带不同 `session_id`，且 `session_started_ns` 不新于当前状态，Agent 会直接忽略。

### `/remove` 与 session 绑定

`/remove` 必须同时匹配：

```text
peer_key
peer_ip
session_id
```

旧 session 的迟到 `/remove` 返回 `removed=false`，不能删除新 session 的动态 Peer。

### nonce 防重放

VPS -> Agent 的 `/offer`、`/remove` 使用 HMAC-SHA256，签名内容为：

```text
METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY
```

其中：

```text
nonce：128 bit 随机值
时间窗口：±30 秒
nonce 缓存：60 秒
最大 nonce 缓存：4096
```

同一个合法请求即使在 30 秒窗口内再次发送，也会因为 nonce 已使用而被拒绝。

`/health` 会返回：

```text
security: session-nonce-v1
```

Agent 还会显示当前 `nonce_cache` 数量。

## 直连健康检查

已建立直连后，WireGuard 握手超过 180 秒未更新时：

1. 删除动态 `/32` Peer；
2. 流量立即回到 VPS；
3. 后台重新启动 Candidate 探测。

180 秒阈值用于避开 WireGuard 正常约 120 秒 rekey 周期造成的误判。

## Candidate worker 取消机制

Windows 与 Linux 状态机均维护 generation。候选变化、直连失效、Peer 删除、session 替换或程序退出会使旧 generation 失效，后台 worker 检测到后立即停止，避免旧网络上的探测结果覆盖新状态。

## 升级兼容

v7 继续保留：

```text
endpoint
endpoint_type
lan_endpoint
lan_ip
listen_port
```

`candidates[]` 是增量字段。

从 v7.0-beta 升级到 v7.0 时，VPS-Agent HMAC 格式增加了 `method/path/nonce`，因此在所有节点完成升级前，旧/新控制面之间可能暂时无法建立新的 P2P 动态 Peer；**VPS `/24` 中转不受影响**。建议在同一维护窗口升级 VPS 与两台 Linux Agent，Windows 客户端可随后升级。

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

## 文件结构

```text
wireguard-p2p/
├── docs/
│   ├── protocol-v7.md
│   ├── protocol-v7-alpha.md
│   └── protocol-v7-beta.md
├── linux/
│   ├── candidates.py
│   ├── p2p_agent.py
│   └── wireguard-p2p-agent.service
├── tests/
│   ├── test_peer_logic.py
│   ├── test_protocol_v7.py
│   └── test_security_v7.py
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
backup/pre-v7-stable-20260807
```

## 后续路线

```text
v7.0.1
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
