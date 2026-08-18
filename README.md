# WireGuard P2P

WireGuard P2P 是一个建立在 **现有 WireGuard Overlay 网络**之上的自动直连增强层。

它不会替代 WireGuard，也不会重新设计你的 VPN。项目的目标是：在保留 VPS 中继作为可靠兜底的同时，让节点自动发现彼此可用的网络地址，并优先尝试建立局域网、IPv6 或 IPv4 P2P 直连，从而降低中继带宽占用并改善端到端延迟与吞吐。

## 特性

- **P2P 优先，Relay 兜底**：直连可用时自动切换到 Direct；直连失败或失效时回退到原有 WireGuard VPS Relay。
- **不破坏基础 WireGuard 配置**：保留原有 Peer、密钥和 `/24` Relay 路由，P2P 只作为增强层运行。
- **多种直连候选**：支持局域网 IPv4、原生 IPv6、学习到的 IPv6、IPv4 公网端点与 NAT 打洞候选。
- **自动重试与故障恢复**：节点重启、地址变化、候选变化或协调服务短暂不可用后会自动重新同步和探测。
- **动态节点角色**：节点角色由 Coordinator 配置决定，不依赖固定 IP 尾号。
- **Windows / Linux 客户端**：Windows 提供原生轻量 GUI，Linux 以 systemd 服务方式运行。
- **Linux Server 双能力模式**：Server 既可以接受其他节点建立 Direct，也可以主动与其他 Server 建立直连。
- **低资源常驻**：正常运行时只进行轻量控制同步和必要的探测，不周期性刷新 Windows UI，也不默认将 GUI 日志写入本地磁盘。

## 工作方式

整体结构如下：

```text
                         ┌──────────────────────┐
                         │   VPS / Coordinator  │
                         │ WireGuard + API      │
                         │ Relay / Rendezvous   │
                         └──────────┬───────────┘
                                    │
                    WireGuard Overlay / 控制协调
                                    │
                  ┌─────────────────┴─────────────────┐
                  │                                   │
          ┌───────▼────────┐                  ┌───────▼────────┐
          │ Client / Server│                  │ Client / Server│
          │   Node A       │◄──── P2P ───────►│   Node B       │
          └────────────────┘                  └────────────────┘
```

VPS 负责两件事：

1. 保留基础 WireGuard Relay 数据通路；
2. 作为 Coordinator 交换节点在线状态和网络 Candidate。

节点收到对端 Candidate 后会按优先级尝试直连。只有在 WireGuard 产生新的、有效的握手后，Direct 路径才会被确认并投入使用。

因此，即使 P2P 探测失败，基础 WireGuard Overlay 仍然可以继续工作。

## 节点角色

项目支持三种角色：

| 角色 | 说明 |
| --- | --- |
| `client` | 默认角色。主动发现可连接的 Server，并优先建立 Direct。 |
| `server` | Linux 双能力节点。既可接受 Client/Server 直连，也可主动参与 Server ↔ Server Direct。 |
| `relay_only` | 仅保留基础 WireGuard Relay，不参与 P2P 协调。 |

角色由 Coordinator 管理，不由节点 IP 决定。

常用命令：

```bash
sudo wireguard-p2p role list
sudo wireguard-p2p role get 10.0.0.10
sudo wireguard-p2p role set 10.0.0.10 client
sudo wireguard-p2p role set 10.0.0.10 server
sudo wireguard-p2p role set 10.0.0.10 relay_only
```

## 当前默认网络约定

当前实现默认使用：

```text
Overlay CIDR: 10.0.0.0/24
Coordinator:  10.0.0.1
API:          http://10.0.0.1:8899
WG interface: wg0
```

这些是当前项目的默认实现约定，并不是 WireGuard 本身的限制。

在部署 P2P 之前，应先保证基础 WireGuard 已经正常：

```bash
wg show wg0
ping -c 2 10.0.0.1
```

如果基础 Overlay 本身不可达，应先修复 WireGuard，再部署 P2P。

## 部署概览

### VPS / Coordinator

VPS 需要已有可用的 WireGuard `wg0`，并安装：

- Python 3.6+
- `wireguard-tools`
- `systemd`

项目提供 VPS bootstrap 与 Release 发布物用于安装和更新 Coordinator、管理工具及更新缓存。

安装完成后可使用：

```bash
sudo wireguard-p2p status
sudo wireguard-p2p version
sudo wireguard-p2p role list
curl -fsS http://10.0.0.1:8899/health
```

### Linux Server

先在 VPS 将目标 Overlay IP 设置为 `server`：

```bash
sudo wireguard-p2p role set 10.0.0.10 server
```

随后在目标 Linux 节点运行 Release 中提供的 Server bootstrap。

Server 主要服务：

```text
wireguard-p2p-agent.service
wireguard-p2p-portmap.service
```

验证：

```bash
systemctl is-active wireguard-p2p-agent.service
systemctl is-active wireguard-p2p-portmap.service
wg show wg0
```

### Linux Client

普通节点默认就是 `client`，通常不需要提前注册角色。

Linux Client 以 systemd 服务常驻：

```bash
systemctl status wireguard-p2p-client.service --no-pager
journalctl -u wireguard-p2p-client.service -n 100 --no-pager
wg show wg0
```

### Windows Client

Windows 端需要先安装 WireGuard 并导入基础 Tunnel 配置，然后运行 Release 中的 Windows EXE。

Windows 客户端提供原生 Win32 GUI，可查看：

- 当前 WireGuard interface
- 节点连接状态
- P2P / Relay 状态
- 当前 Direct Candidate 类型
- 内存中的运行日志

客户端需要管理员权限读取和修改 WireGuard interface，因此启动时会请求 UAC 授权。

关闭主窗口后程序可以继续在系统托盘运行，并可通过“安全退出”停止后台进程。

## Direct 与 Relay

P2P 是增强路径，Relay 始终是基础路径。

```text
Relay baseline: AllowedIPs = 10.0.0.0/24
Direct route:   成功握手后安装目标节点 /32
Keepalive:      Direct 使用 PersistentKeepalive
Fallback:       Direct 失效后回退 VPS Relay
```

典型 Candidate 包括：

```text
lan4          局域网 IPv4
host6         主机原生 IPv6
observed6     学习到的 IPv6
reflexive6    IPv6 NAT / 映射地址
mapped4       映射后的公网 IPv4
observed4     观察到的公网 IPv4
predicted4    IPv4 端口预测候选
```

项目会优先尝试更直接、更可靠的路径，并以 fresh WireGuard handshake 作为 Direct 成功的最终依据。

## 更新

推荐顺序：

```text
VPS / Coordinator
        ↓
Linux Servers
        ↓
Clients
```

Linux 节点：

```bash
sudo wireguard-p2p update
```

Windows：

```powershell
.\wireguard-p2p-windows-amd64.exe update
```

正式构建与发布文件请以 GitHub **Releases** 页面为准。

## 常用排查

首先检查基础 WireGuard：

```bash
wg show wg0
ping -c 2 10.0.0.1
```

然后检查 P2P 服务：

```bash
sudo wireguard-p2p status
curl -fsS http://10.0.0.1:8899/health
```

Linux Server：

```bash
journalctl -u wireguard-p2p-agent.service -n 100 --no-pager
wg show wg0 endpoints
wg show wg0 latest-handshakes
```

Linux Client：

```bash
journalctl -u wireguard-p2p-client.service -n 100 --no-pager
wg show wg0
```

常见判断：

- **Overlay IP 可达，但没有 Direct**：P2P 探测未成功，当前正在走 Relay，不代表基础网络故障。
- **Coordinator 不可达**：已有健康 Direct 可以短时间继续工作，失效路径最终会回退 Relay。
- **Windows 报 `Permission denied`**：确认运行的是带管理员权限 manifest 的最新 Windows Release，并接受 UAC 授权。
- **Server bootstrap 返回角色错误**：先在 Coordinator 上确认该节点已设置为 `server`。

## 安全原则

P2P 部署不应破坏已有 WireGuard 基线。除非你明确知道自己在做什么，否则不要因为部署本项目而：

- 重建 WireGuard 私钥或公钥；
- 删除 VPS 基础 Peer；
- 删除 Relay `/24 AllowedIPs`；
- 关闭 VPS Relay；
- 仅根据 Candidate 信息直接安装 `/32`；
- 根据 IP 尾号猜测节点角色。

Direct 应始终以真实 WireGuard 握手作为成功依据。

## 项目目录

```text
.github/                 CI / Release workflow
ci/                      CI 与兼容性辅助内容
p2p/
├── wireguard-p2p/       VPS / Coordinator / Linux Server 相关代码
└── wireguard-p2p-client/ Windows / Linux Client
```

## 适用场景

这个项目适合已经有 WireGuard Overlay、但希望进一步获得以下能力的环境：

- 家庭、实验室、校园网与云服务器之间的直连；
- 多台 Linux Server 之间的低延迟通信；
- Windows 远程桌面、SSH、文件传输等需要尽量绕过低带宽 VPS 的场景；
- IPv6 条件较好，但仍希望保留 IPv4 与 VPS Relay 作为兼容兜底的网络。

## 项目定位

WireGuard P2P 的设计原则可以概括为：

> **WireGuard 负责可靠的 Overlay，Coordinator 负责发现，P2P 负责优化路径，VPS Relay 永远保留兜底。**

项目仍在持续演进。部署和升级时建议使用最新 Release，并在升级前保持基础 WireGuard 配置可独立工作。
