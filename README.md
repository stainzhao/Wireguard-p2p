# WireGuard P2P

当前生产版本：**v7.9.0**，协议版本仍为 7。

本项目是在现有 WireGuard `10.0.0.0/24` 网络之上增加自动 P2P Direct。**VPS relay 永远是基线，P2P 失败不能破坏基础连通性。**

## 1. 角色

```text
VPS / Coordinator
  10.0.0.1
  peers_api.py

Linux P2P Server
  任意经 VPS 授权的 10.0.0.x，例如 10.0.0.2 / .5 / .10
  Python p2p_agent.py + port mapping

P2P Client
  Windows amd64
  Linux amd64 / arm64
  共享 Go client core
```

`10.0.0.8` 当前保留为 `relay_only`，不要注册为 Server。`10.0.0.1` 是 VPS。

Server **不再写死 `.2/.5`，也不再把 Server 公钥编译进 Client**。VPS 通过 `/etc/wireguard-p2p/servers.conf` 管理 Server 授权，Client 根据 Coordinator 返回的 `role=server` 动态发现所有 Server。因此以后新增 `.10/.11/...` 不需要修改源码或重新编译 Client。

## 2. 不可破坏的网络约束

部署 Agent 必须遵守：

```text
WireGuard interface: wg0（默认）
VPS overlay:        10.0.0.1
Coordinator API:    http://10.0.0.1:8899
Relay baseline:     AllowedIPs = 10.0.0.0/24
Direct route:       仅 fresh authenticated WG handshake 后添加目标 /32
Keepalive:          Direct 使用 25s
```

除非用户明确要求，否则 **不要修改 WireGuard 私钥、公钥、VPS Endpoint、基础 `/24 AllowedIPs`、Candidate 优先级、打洞窗口或 relay 基线**。

## 3. Agent 最短部署流程

### A. VPS 首次安装

前提：VPS 已有可工作的 `wg0=10.0.0.1`，并安装 `python3`、`wireguard-tools`、`systemd`。

私有 GitHub 仓库首次需要一个只读 Token：

```bash
read -rsp 'GitHub read token: ' T; echo; curl -fsSL -H "Authorization: Bearer $T" -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/stainzhao/p2p/contents/p2p/wireguard-p2p/bootstrap/bootstrap-vps.py?ref=main' | sudo env P2P_GITHUB_TOKEN="$T" python3 -
```

验证：

```bash
curl -fsS http://10.0.0.1:8899/health
sudo wireguard-p2p version
sudo wireguard-p2p server list
```

首次安装会默认保留历史 Server `.2` 和 `.5`。Server 注册表位于：

```text
/etc/wireguard-p2p/servers.conf
```

不要让 Agent 直接编辑该文件，优先使用管理命令。

### B. 新增任意 Linux P2P Server（例如 `.10`）

前提：该机器已经完成基础 WireGuard 配置，`wg0` 上有 `10.0.0.10`，且：

```bash
ping -c 2 10.0.0.1
```

先在 **VPS** 授权：

```bash
sudo wireguard-p2p server add 10.0.0.10
```

再在 **10.0.0.10** 机器执行唯一安装命令：

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-server.sh | sudo sh
```

安装器会自动读取 `wg0` 的 overlay IP，不需要传 `.10`、用户名、CPU 架构或 `notify.key`。只有已经在 VPS 授权的 Server IP 才能取得 Server HMAC key；未授权节点会返回 403，并提示先执行 `server add`。

`.2/.5` 在首次 VPS 安装后默认已授权，因此可以直接运行同一条 Server bootstrap 命令。

验证 Server：

```bash
sudo wireguard-p2p version
systemctl is-active wireguard-p2p-agent.service
systemctl is-active wireguard-p2p-portmap.service
curl -fsS http://$(ip -4 -o addr show dev wg0 | awk '$4 ~ /^10\.0\.0\./ {sub(/\/.*/,"",$4); print $4; exit}'):8898/health
```

删除 Server 授权：

```bash
sudo wireguard-p2p server remove 10.0.0.10
```

此命令在 VPS 执行。若设备不再承担 Server 角色，还应停止该设备上的 Agent service。

### C. 普通 Linux Client 首次安装

前提：`wg0` 已能访问 `10.0.0.1`。

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-client.sh | sudo sh
```

自动识别：

```text
x86_64/amd64 -> linux-amd64
aarch64/arm64 -> linux-arm64
```

验证：

```bash
systemctl is-active wireguard-p2p-client.service
journalctl -u wireguard-p2p-client.service -n 50 --no-pager
wg show wg0
```

### D. Windows Client

安装 WireGuard、导入基础 `wg0` 配置，然后使用 Release 中：

```text
wireguard-p2p-windows-amd64.exe
```

运行后会动态发现 VPS 当前授权的全部 Server，不需要在 EXE 中维护 `.2/.5/.10` 公钥列表。

## 4. 更新

建议顺序：

```text
VPS -> Linux Servers -> Clients
```

所有 Linux VPS/Server/Client：

```bash
sudo wireguard-p2p update
```

Windows：

```powershell
.\wireguard-p2p.exe update
```

VPS 是唯一访问私有 GitHub Release 的节点。VPS 校验 SHA-256 后把 Release 缓存在：

```text
/var/lib/wireguard-p2p/updates/current
```

其他节点只从 WireGuard overlay 的 `10.0.0.1:8899/updates/` 获取包。

## 5. Candidate 优先级

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

只有 fresh authenticated WireGuard handshake 才能提升为 Direct `/32`。

## 6. Agent 部署决策表

| 目标机器 | Agent 应做什么 |
|---|---|
| VPS `10.0.0.1` | 首次跑 VPS bootstrap；以后 `sudo wireguard-p2p update` |
| 新 P2P Server | 先在 VPS `server add <overlay-ip>`，再在目标机跑 server bootstrap |
| 已授权 `.2/.5` | 直接跑 server bootstrap |
| 普通 Linux Client | 直接跑 client bootstrap |
| Windows Client | 使用 Release EXE；以后 EXE `update` |

Agent 在执行前必须先确认：

```bash
wg show wg0
ping -c 2 10.0.0.1
```

若基础 WireGuard 不通，**先排查 WireGuard，不要用 P2P 安装器掩盖问题**。

## 7. 常用诊断

VPS：

```bash
sudo wireguard-p2p status
sudo wireguard-p2p server list
curl -fsS http://10.0.0.1:8899/health
systemctl status peers-api.service --no-pager
```

Server：

```bash
sudo wireguard-p2p status
systemctl status wireguard-p2p-agent.service --no-pager
sudo journalctl -u wireguard-p2p-agent.service -n 100 --no-pager
wg show wg0 endpoints
wg show wg0 latest-handshakes
```

Linux Client：

```bash
systemctl status wireguard-p2p-client.service --no-pager
journalctl -u wireguard-p2p-client.service -n 100 --no-pager
wg show wg0
```

常见错误：

- Server bootstrap `403`：该 overlay IP 尚未在 VPS `server add` 授权。
- `/updates/...` 返回 `404`：VPS 尚未完成当前 Release 缓存，先在 VPS `sudo wireguard-p2p update --force`。
- P2P Direct 失败但 `10.0.0.x` 仍可访问：这是正常 Relay fallback。
- `10.0.0.1` 本身不通：基础 WireGuard 问题，不属于 P2P Agent。

## 8. 发布与源码结构

```text
.github/workflows/ci.yml
p2p/wireguard-p2p-client/        Windows/Linux Go Client
p2p/wireguard-p2p/linux/         Linux Server Agent
p2p/wireguard-p2p/vps/           Coordinator
p2p/wireguard-p2p/manage/        Linux VPS/Server 管理命令
p2p/wireguard-p2p/bootstrap/     一行首次安装入口
p2p/wireguard-p2p/tests/         Python 回归测试
p2p/wireguard-p2p/docs/          当前文档
```

`main` CI 构建并发布 Windows amd64、Linux amd64/arm64、Server、VPS 与 bootstrap 资产。编译产物不提交到 Git。

## 9. 给自动化 Agent 的硬规则

1. 优先读取本 README，再执行部署。
2. 不要把普通 Linux Client 安装成 Python Server Agent。
3. 新 Server IP 必须先通过 VPS `wireguard-p2p server add` 授权。
4. 不要把 `10.0.0.8` 注册为 Server。
5. 不要覆盖 `/etc/wireguard/` 或重新生成 WireGuard key。
6. 不要删除 `AllowedIPs = 10.0.0.0/24` relay baseline。
7. 更新后必须检查版本、systemd active 状态和 `/health`。
8. Direct 失败时保留 Relay，不要为了“强制 P2P”破坏基础连通性。
