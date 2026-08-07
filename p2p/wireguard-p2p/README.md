# WireGuard P2P v7.0-alpha

该项目在保留 VPS `10.0.0.1` 中转路由的同时，为客户端与 GPU
`10.0.0.2`、2696 `10.0.0.5` 建立动态 `/32` P2P 路由。

v7.0-alpha 将控制面从“单 Endpoint 交换”升级为“Candidate 列表交换”。
当前阶段仍保留 v6.2 的单 Endpoint 探测逻辑，因此现有直连、回退和滚动升级行为不变；
新增的 `candidates[]` 为后续 IPv6 优先、多候选快速探测、PCP/UPnP 和对称 NAT 预测提供统一协议基础。

## 运行结构

- VPS：`peers-api.service`，监听 `10.0.0.1:8899`，接收外部设备连接事件并汇聚候选。
- GPU、2696：`wireguard-p2p-agent.service`，分别监听 `10.0.0.2:8898`
  和 `10.0.0.5:8898`，不轮询 VPS。
- Windows：`wireguard-p2p.exe`，窗口打开期间运行。
- 手机 `10.0.0.8`：固定使用 VPS 中转，不参与 P2P。

## v7 Candidate

当前支持/预留的候选类型：

```text
lan4       1000   同局域网私有 IPv4
host6       900   公网 IPv6
mapped4     800   PCP/NAT-PMP/UPnP（v7.1）
observed4   600   VPS 实际观察到的公网 IPv4
predicted4  400   对称 NAT 预测端口（v7.2）
```

Windows 与 Linux Agent 已开始自动上报 `lan4` 和可用的 `host6`。
VPS 会根据 `wg show wg0 dump` 自动生成可信 `observed4`；节点不能自行声明 `observed4`。
IPv6 Endpoint 使用 `[IPv6]:port` 格式。

详细协议见：`docs/protocol-v7-alpha.md`。

## 兼容策略

v7.0-alpha 仍保留：

- `endpoint`
- `endpoint_type`
- `lan_endpoint`
- `lan_ip`
- `listen_port`

因此推荐滚动升级顺序：

```text
VPS -> Linux Agents -> Windows client
```

旧 v6.2 节点仍可通过旧字段工作。

## Relay-first 路由模型

项目继续遵循：

```text
VPS /24 始终可用
        |
        +-- 后台尝试 P2P
                |
                +-- WireGuard 新握手成功 -> 添加目标 /32
                |
                +-- 失败/失效 -> 删除 /32 -> 立即回 VPS
```

Candidate 探测不会先切断 VPS 通路。

## 当前 alpha 行为

v7.0-alpha **只完成 Candidate 的发现、校验、交换和持久化基础**。
Linux Agent 和 Windows 当前仍使用 v6.2 的旧 `endpoint` 作为实际探测目标，
尚未启用 LAN4/IPv6/observed4 的快速候选轮换。

这一限制是刻意保留的，用于先验证协议升级不会破坏现有稳定连接。

## 状态与日志

两台服务器 Agent 默认不记录候选、探测、直连和回退等正常事件，只把监控或
请求处理异常写入 stderr，由 systemd journal 接收。临时诊断时可设置：

```bash
P2P_VERBOSE_LOG=1
```

查看：

```bash
systemctl status wireguard-p2p-agent.service
journalctl -u wireguard-p2p-agent.service -n 50 --no-pager
```

VPS：

```bash
systemctl status peers-api.service
curl --noproxy '*' http://10.0.0.1:8899/health
```

`/health` 在 v7 返回 `protocol: 7`。

## 故障策略

当前仍沿用 v6.2：

- 直连握手超过 180 秒未更新：删除 `/32` 并回退 VPS。
- 探测 90 秒未成功：前两次按 60、120 秒退避；第 3 次起进入 30 分钟冷却。
- Endpoint 发生变化：立即解除退避并重新探测。
- 外部设备超过 120 秒未续租：VPS 通知服务器清理动态 Peer。
- VPS 通知丢失时：服务器本地 lease 独立清理。

## 文件

```text
wireguard-p2p/
├── docs/
│   └── protocol-v7-alpha.md
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
├── main.go
└── main_test.go
```

`linux/p2p_sync.py` 仅保留用于历史源码审计，运行服务器不再依赖它。

## 后续路线

```text
v7.0-beta
  LAN4 -> IPv6 -> observed4 快速候选探测状态机

v7.0
  session ID + nonce 严格防重放
  稳定路径选择与网络变化重评估

v7.1
  PCP -> NAT-PMP -> UPnP mapped4

v7.2
  NAT 行为探测
  仅对可预测对称 NAT 启用 predicted4
```

升级前状态已保存在分支：

```text
backup/pre-v7-alpha-20260807
```
