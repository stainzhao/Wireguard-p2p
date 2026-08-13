# WireGuard P2P

当前生产版本：**v7.12.1**，协议版本 7。

**v7.12.1 的恢复变化：每个运行中的 Client/Server 都会向 Coordinator 发布随机 `instance_id`。节点重启或 Agent/Client 进程重启后该 ID 立即变化；对端在下一次控制同步时会废弃旧 `/32` Direct 并马上重新 Probe，不再等待 180 秒 handshake stale。Candidate 集发生变化时，也只有当前 Direct endpoint 仍明确存在于新 Candidate 集中才会继续保留 Direct。**

这是一个建立在现有 WireGuard Overlay 之上的自动 P2P Direct 项目。当前默认拓扑仍是：

```text
Overlay CIDR: 10.0.0.0/24
Coordinator:  10.0.0.1
API:          http://10.0.0.1:8899
WG interface: wg0
```

**v7.12 的 Server 变化：Linux `server` 现在是双能力节点。同一个 Python Agent 既响应 Client/Server 的入站协调，也会主动同步 Coordinator 并建立 Server↔Server Direct。每一对 Server 由 Overlay IP 较小的一端负责主动协调，避免双方同时修改同一个 WireGuard Peer；一旦 Direct 建立，数据面本身是双向的。无需在 Server 上额外安装普通 Linux Client。**

**v7.11 的 IPv6 变化：多 GUA 主机不再把所有 `host6` 当成完全等价。Client/Server 会询问操作系统实际的 IPv6 源地址选择，将该地址以更高优先级发布，并给首选 `host6` 8 秒重叠打洞窗口；deprecated/tentative IPv6 不再发布，IPv6 Probe 会明确写入日志。**

**v7.10 的核心变化：节点编号不再具有任何内置含义。** `.2`、`.5`、`.8`、`.10` 都只是普通 Overlay 地址；除 VPS `10.0.0.1`、网络地址 `.0` 和广播地址 `.255` 外，任意合法 `10.0.0.x` 都可以被配置成 `client`、`server` 或 `relay_only`。

> 这意味着 `10.0.0.8` 不再被写死成 `relay_only`，`.2/.5` 也不再是新安装时的默认 Server。

## 1. 角色模型

角色由 VPS 配置决定，不由 IP 尾号决定：

```text
client       默认角色。没有显式配置的普通 WireGuard Peer 都是 client。
server       Linux 双能力 Agent：可被 Client/Server 连接，也会主动建立 Server↔Server Direct。
relay_only   可选角色。节点保持 WireGuard Relay 基线，但不参与 P2P 协调。
```

VPS 使用两个配置文件：

```text
/etc/wireguard-p2p/servers.conf
/etc/wireguard-p2p/relay-only.conf
```

**不要让 Agent 直接编辑这些文件。** 使用管理命令：

```bash
sudo wireguard-p2p role list
sudo wireguard-p2p role get 10.0.0.8
sudo wireguard-p2p role set 10.0.0.8 client
sudo wireguard-p2p role set 10.0.0.8 server
sudo wireguard-p2p role set 10.0.0.8 relay_only
```

兼容快捷命令仍保留：

```bash
sudo wireguard-p2p server list
sudo wireguard-p2p server add 10.0.0.10
sudo wireguard-p2p server remove 10.0.0.10

sudo wireguard-p2p relay-only list
sudo wireguard-p2p relay-only add 10.0.0.20
sudo wireguard-p2p relay-only remove 10.0.0.20
```

`role set` 会保证角色互斥：一个节点不会同时存在于 `server` 与 `relay_only` 注册表中。`client` 是隐式默认角色，因此设置为 `client` 会从两个显式注册表中移除该 IP。

## 2. 不可破坏的网络不变量

P2P 是增强层，不是基础 WireGuard 的替代品：

```text
Relay baseline: AllowedIPs = 10.0.0.0/24
Direct route:   只有 fresh authenticated WireGuard handshake 成功后才安装目标 /32
Keepalive:      Direct = 25 s
Fallback:       Direct 失败或过期时回退 VPS /24 Relay
```

Agent **禁止**因为部署 P2P 而重建 WireGuard key、删除 VPS Peer、删除 `/24 AllowedIPs`、关闭 Relay，或仅凭 Candidate 信息直接安装 `/32`。

## 3. 给 Agent 的部署决策

先执行：

```bash
wg show wg0
ping -c 2 10.0.0.1
```

基础 WireGuard 不通时，先修 WireGuard，不要继续 P2P 安装。

### 3.1 VPS / Coordinator 首次安装

前提：VPS 已有 `wg0=10.0.0.1`，并安装 **Python 3.6+**、`wireguard-tools`、`systemd`。v7.10.1 起 Manager 避免使用仅 Python 3.7/3.8+ 提供的 API。

私有 GitHub 仓库首次输入只读 Token：

```bash
read -rsp 'GitHub read token: ' T; echo; curl -fsSL -H "Authorization: Bearer $T" -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/stainzhao/p2p/contents/p2p/wireguard-p2p/bootstrap/bootstrap-vps.py?ref=main' | sudo env P2P_GITHUB_TOKEN="$T" python3 -
```

验证：

```bash
curl -fsS http://10.0.0.1:8899/health
sudo wireguard-p2p version
sudo wireguard-p2p role list
```

安装器会在输出成功前轮询 `8899/health` 并确认 `peers-api.service` 仍为 active。

**全新 v7.10 安装不会自动创建 `.2/.5/.8` 等任何角色。** 两个角色注册表初始为空。若从 v7.9 升级，已有 `servers.conf` 会被保留，因此旧 `.2/.5` Server 不会因升级丢失。

### 3.2 部署任意 Linux P2P Server

例如目标 Overlay IP 是 `10.0.0.10`。

在 VPS：

```bash
sudo wireguard-p2p role set 10.0.0.10 server
```

然后在目标 Linux 机器：

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-server.sh | sudo sh
```

Server 安装器会：

```text
检查 wg0
自动读取本机 10.0.0.x
向 VPS 再次验证该 IP 当前确实是 server
领取/刷新 notify.key
安装 Python 双能力 Agent + port mapping
Agent 内置 Server↔Server initiator，不额外安装 Linux Client
若检测到旧的 `wireguard-p2p-client.service`，会停用它以避免两个控制器竞争同一 wg0 Peer
安装 systemd services
启动并重启服务
安装结束前验证 Agent `8898/health`，并确认 Agent 与 portmap 两个 systemd 服务仍为 active；验证失败则安装命令返回失败，不再误报成功。
```

因此 `.2`、`.5`、`.8`、`.10`、`.100` 的部署方式完全相同。IP 尾号不再进入源码逻辑。

验证：

```bash
sudo wireguard-p2p version
systemctl is-active wireguard-p2p-agent.service
systemctl is-active wireguard-p2p-portmap.service
# Server↔Server initiator 已集成在 wireguard-p2p-agent.service 中
wg show wg0
```

### 3.3 普通 Linux Client

没有显式角色时默认就是 `client`，无需先在 VPS 注册。

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-client.sh | sudo sh
```

验证：

```bash
systemctl is-active wireguard-p2p-client.service
journalctl -u wireguard-p2p-client.service -n 50 --no-pager
wg show wg0
```

### 3.4 Windows Client

安装 WireGuard 并导入基础配置，然后运行 Release 中：

```text
wireguard-p2p-windows-amd64.exe
```

Windows/Linux Go Client 都根据 Coordinator 返回的 `role=server` 动态发现 Server，不保存固定 Server IP 或公钥列表。

### 3.5 可选 relay_only 节点

只有明确希望某节点**不参与 P2P，只保留基础 WireGuard Relay 行为**时才配置：

```bash
sudo wireguard-p2p role set 10.0.0.20 relay_only
```

恢复普通 Client：

```bash
sudo wireguard-p2p role set 10.0.0.20 client
```

`relay_only` 是一种可选配置能力，不再绑定任何固定 IP。

## 4. 更新

建议顺序：

```text
VPS -> Servers -> Clients
```

VPS、Linux Server：

```bash
sudo wireguard-p2p update
```

普通 Linux Client 同样：

```bash
sudo wireguard-p2p update
```

Windows：

```powershell
.\wireguard-p2p.exe update
```

VPS 是唯一访问私有 GitHub Release 的节点。发布物经 SHA-256 验证后缓存到：

```text
/var/lib/wireguard-p2p/updates/current
```

其他节点只从 `10.0.0.1:8899/updates/` 获取。

## 5. Candidate 顺序

```text
lan4                  1000
preferred host6          910
backup host6             900
observed6                850
reflexive6   825
mapped4      800
observed4    700
predicted4   500
VPS /24      baseline
```

v7.10 **没有修改** Candidate 优先级、IPv4/IPv6 打洞窗口、fresh-handshake promotion、Direct keepalive 或 Relay fallback。

## 6. 常用运维命令

VPS：

```bash
sudo wireguard-p2p status
sudo wireguard-p2p role list
curl -fsS http://10.0.0.1:8899/health
systemctl status peers-api.service --no-pager
```

Server：

```bash
sudo wireguard-p2p status
systemctl status wireguard-p2p-agent.service --no-pager
systemctl status wireguard-p2p-portmap.service --no-pager
journalctl -u wireguard-p2p-agent.service -n 100 --no-pager
wg show wg0 endpoints
wg show wg0 latest-handshakes
```

Linux Client：

```bash
systemctl status wireguard-p2p-client.service --no-pager
journalctl -u wireguard-p2p-client.service -n 100 --no-pager
wg show wg0
```

## 7. Agent 故障处理规则

- Server bootstrap 返回 `403`：在 VPS 执行 `sudo wireguard-p2p role get <IP>`；若不是 `server`，先 `role set <IP> server`。
- `/updates/...` 返回 `404`：VPS 先执行 `sudo wireguard-p2p update --force`。
- Direct 失败但 Overlay IP 仍通：这是正常 Relay fallback，不要破坏 `/24`。
- `10.0.0.1` 不通：属于基础 WireGuard 问题。
- 改角色不需要重新编译 Client，也不需要改 Server 公钥列表。

## 8. Agent 硬规则

1. 先读本 README，再部署。
2. 先验证 `wg0` 和 `10.0.0.1` 基线。
3. 普通 Linux Client 使用 Go Client，不安装 Python Server Agent。
4. Linux Server 必须先在 VPS 显式设置为 `server`。
5. 不根据 IP 尾号猜角色；`.8` 没有特殊意义。
6. 不直接编辑角色注册表，优先使用 `wireguard-p2p role ...`。
7. 不修改 WireGuard 私钥、公钥、基础 VPS Peer 和 `/24 AllowedIPs`。
8. 更新后验证版本、systemd active 状态以及 VPS/Server `/health`。
9. Direct 失败时保留 Relay。

## 9. 当前“通用”的边界

v7.10 已经实现**节点角色通用化**：项目源码不再依赖 `.2/.5/.8` 等具体设备地址，新节点可直接通过角色配置加入。

当前默认 Overlay 拓扑仍固定为 `10.0.0.0/24 + VPS 10.0.0.1 + wg0`。如果未来需要把这个项目直接复用到 `172.16.x.x`、`10.20.0.0/16` 或不同 Coordinator 地址，可继续把 Overlay CIDR/API 地址参数化；这与本次“去除设备硬编码”是独立的一层。
