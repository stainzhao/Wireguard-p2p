# WireGuard P2P v7.3

该项目在保留 VPS `10.0.0.1` 中转路由的同时，为 Windows 客户端与 GPU `10.0.0.2`、2696 `10.0.0.5` 建立动态 `/32` P2P 路由。

v7.0 完成 Candidate 快速探测和 session/nonce 安全控制面；v7.1 加入 **PCP -> NAT-PMP -> UPnP 自动 IPv4 端口映射**；v7.2 完成 NAT66 `observed6` 被动学习与 confirmation rekey；v7.3 新增 **reflexive6 + 双向 simultaneous IPv6 punch**，用于客户端和服务器两侧都存在 IPv6 stateful firewall/NAT66 的场景。

## 运行结构

- VPS：`peers-api.service`，`10.0.0.1:8899`，负责 session、候选汇聚和协调。
- GPU、2696：`wireguard-p2p-agent.service`，负责候选探测与 `/32` 路由升级。
- GPU、2696 v7.1：`wireguard-p2p-portmap.service`，后台维护 WireGuard UDP 映射。
- Windows：`wireguard-p2p.exe`，负责候选上报与客户端侧路径探测。
- 手机 `10.0.0.8`：固定 VPS 中转。

## Candidate 优先级

```text
lan4        1000   同局域网私有 IPv4
host6        900   原生公网 IPv6
observed6    850   WireGuard 已认证学习到的公网 IPv6 Endpoint
reflexive6   825   NAT66 外部 IPv6 + WG ListenPort（未验证）
mapped4      800   PCP/NAT-PMP/UPnP 显式映射
observed4    600   VPS 观察到的公网 IPv4 NAT Endpoint
predicted4   400   IPv4 端口预测（预留）
```

路径失败时 VPS `/24` 始终继续工作。

## v7.3 simultaneous IPv6 punch

当 Linux server 没有可发布的 native `host6`，但具备 IPv6 出站能力时，Agent 会在启动时发现 NAT66 后的公网 IPv6，并生成未验证的 `reflexive6` Candidate。Windows 对 `reflexive6` 主动探测，同时 Linux 对 Windows `host6` 主动探测，两个方向各保持最多约 8 秒重叠窗口。

`reflexive6` 只是假设“外部 IPv6 + 当前 WireGuard ListenPort”可达；**没有 fresh authenticated WireGuard handshake 就绝不会安装 `/32`**。发现失败、端口被 NAT66 改写或双方防火墙仍无法穿透时，自动继续原有 Candidate 和 VPS relay。完整设计见 `docs/protocol-v7.3.md`。

诊断 NAT66 公网地址：

```bash
curl http://10.0.0.5:8898/health
```

返回中的 `reflexive6` 为 Agent 当前缓存的外部 IPv6。

## v7.1 mapped4

服务器后台服务按以下顺序尝试：

```text
PCP -> NAT-PMP -> UPnP-IGD
```

成功后把路由器建立的：

```text
公网IPv4:外部UDP端口 -> 服务器LAN_IP:WireGuardListenPort
```

写入：

```text
/var/lib/wireguard-p2p/mapped4.json
```

Agent 的 `gather_candidates()` 只读取与当前 LAN IPv4、WireGuard ListenPort 和租期完全匹配的缓存，然后发布：

```json
{
  "type": "mapped4",
  "family": "udp4",
  "endpoint": "PUBLIC_IP:PORT",
  "priority": 800
}
```

如果返回的是 RFC1918、CGNAT `100.64.0.0/10` 或其他非公网 IPv4，则不会发布。

映射失败不会影响 Agent、IPv6、observed4 或 VPS relay。

### 为什么服务器侧映射优先

当前困难 NAT 位于 GPU/2696 所在网络。只要服务器获得稳定 `mapped4`，Windows 客户端主动向该地址发 WireGuard 握手即可；Windows 本身不需要拥有端口映射。因此 v7.1 首先实现服务器侧映射。

## v7.1 部署

在 GPU 和 2696 更新仓库后，进入：

```bash
cd p2p/wireguard-p2p/linux
sudo sh install_portmap.sh
```

脚本会自动识别现有 Agent 的服务用户，安装：

```text
/opt/wireguard-p2p/portmap.py
/opt/wireguard-p2p/portmap_daemon.py
/opt/wireguard-p2p/candidates.py
/etc/systemd/system/wireguard-p2p-portmap.service
```

并启用新服务、重启 Agent。

若自动识别用户失败：

```bash
sudo sh install_portmap.sh <service-user>
```

诊断：

```bash
systemctl status wireguard-p2p-portmap.service
journalctl -u wireguard-p2p-portmap.service -n 50 --no-pager
cat /var/lib/wireguard-p2p/mapped4.json
```

如果路由器支持其中任一协议，应看到类似：

```json
{
  "method": "pcp",
  "internal_ip": "192.168.0.134",
  "internal_port": 35422,
  "candidate": {
    "type": "mapped4",
    "endpoint": "211.71.91.89:35422"
  }
}
```

没有该文件只说明自动端口映射未成功，原有 P2P 和 VPS fallback 不受影响。

## 快速探测状态机

每个候选默认约 2 秒，最多选择 5 个。

探测阶段：

```text
PersistentKeepalive = 1
不安装目标 /32
业务流量继续走 VPS
```

成功必须满足：

```text
latest_handshake > candidate 安装前 baseline_handshake
```

成功后：

```text
读取 WireGuard 实际 Endpoint
添加目标 10.0.0.x/32
PersistentKeepalive = 25
```

全部失败后删除动态 Peer，继续走 VPS。Windows fallback 退避保持 60 秒、120 秒、随后 30 分钟；Linux Agent 为快速 NAT66 恢复使用 3 秒、10 秒、随后 30 分钟。Candidate 变化会解除旧冷却并重新评估。

## v7.0 控制面安全

每个客户端会话包含：

```text
session_id         UUIDv4
session_started_ns 单调比较的新会话创建时间
```

旧 `/offer` 无法覆盖新 session；`/remove` 必须匹配 `peer_key + peer_ip + session_id`。

VPS -> Agent 使用：

```text
HMAC-SHA256(
  METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY
)
```

nonce 为 128 bit 随机值，时间窗口 ±30 秒，已使用 nonce 缓存 60 秒，防止合法请求在窗口内重放。

## 直连健康检查

直连握手超过 180 秒未更新：

1. 删除动态 `/32` Peer；
2. 流量立即回 VPS；
3. 后台重新运行 Candidate Probe。

## 协议文档

```text
docs/protocol-v7.md       v7.0 正式 Candidate/session/security 协议
docs/protocol-v7.1.md     v7.1 mapped4 端口映射
docs/protocol-v7.3.md     v7.3 reflexive6 / simultaneous IPv6 punch
docs/protocol-v7-beta.md  历史快速探测设计
docs/protocol-v7-alpha.md 历史 Candidate 交换设计
```

## 主要文件

```text
wireguard-p2p/
├── docs/
│   ├── protocol-v7.md
│   └── protocol-v7.1.md
├── linux/
│   ├── candidates.py
│   ├── p2p_agent.py
│   ├── portmap.py
│   ├── portmap_daemon.py
│   ├── install_portmap.sh
│   ├── wireguard-p2p-agent.service
│   └── wireguard-p2p-portmap.service
├── tests/
│   ├── test_peer_logic.py
│   ├── test_protocol_v7.py
│   ├── test_security_v7.py
│   └── test_portmap_v7.py
└── vps/
    └── peers_api.py
```

GitHub Actions 在 `main` 每次提交后运行 Python 与 Go 测试。

## 回滚点

```text
backup/pre-v7-alpha-20260807
backup/pre-v7-beta-20260807
backup/pre-v7-stable-20260807
backup/pre-v7.1-20260807
backup/pre-v7.3-simultaneous-ipv6-20260807
```

## 后续路线

```text
v7.3.x
  实网验证不同家庭/校园 IPv6 防火墙下的 simultaneous punch
  根据实测决定是否需要 UDP 端口变化检测

v7.4（按需）
  IPv6 端口改写/endpoint-dependent NAT66 行为探测
  多候选 bounded port prediction

v8（仅当内核 WireGuard 无法覆盖目标网络）
  userspace WireGuard + UDP mux / ICE-like coordination
```
