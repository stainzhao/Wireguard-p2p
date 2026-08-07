# WireGuard P2P v7.1 mapped4

v7.1 在 v7.0 Candidate/Probe 状态机上启用 `mapped4`，优先解决 Linux 服务器位于对称 NAT 后时，VPS 观察到的 `observed4` 不能代表 server -> client 实际映射的问题。

## 目标

服务器路由器如果支持标准端口映射协议，则为内核 WireGuard 的真实 `ListenPort` 建立显式 UDP 映射：

```text
PublicIPv4:external_port -> LAN_IP:WireGuardListenPort/UDP
```

该公网地址作为：

```json
{
  "type": "mapped4",
  "family": "udp4",
  "endpoint": "PUBLIC_IP:PORT",
  "priority": 800,
  "verified": false
}
```

进入已有 Candidate 列表。

## 映射协议顺序

```text
PCP
 ↓ failure / unsupported
NAT-PMP
 ↓ failure / unsupported
UPnP-IGD
 ↓ failure
不发布 mapped4，继续 host6 / observed4 / VPS relay
```

所有映射均针对 UDP，并使用当前 WireGuard `ListenPort` 作为内部端口。PCP 和 NAT-PMP 允许网关返回不同的外部端口；UPnP 当前请求相同的内外端口。

## 为什么使用独立后台服务

VPS -> Linux Agent `/offer` 的 HTTP 超时很短，PCP/NAT-PMP/SSDP/UPnP 网络发现不能放在请求处理线程中。

因此 v7.1 使用：

```text
wireguard-p2p-portmap.service
    |
    +-- 每 15 秒检查 wg0 ListenPort / LAN IPv4
    +-- PCP -> NAT-PMP -> UPnP
    +-- 建立/续租映射
    +-- 原子写入 /var/lib/wireguard-p2p/mapped4.json

wireguard-p2p-agent.service
    |
    +-- gather_candidates()
    +-- 只读取有效缓存
    +-- 添加 mapped4
```

映射发现失败不会阻塞 Agent，也不会影响 VPS relay。

## 映射租期和续租

默认请求：

```text
lifetime = 3600 s
```

缓存仅在以下条件全部满足时发布：

- `internal_ip` 与当前服务器 LAN IPv4 相同；
- `internal_port` 与当前 WireGuard ListenPort 相同；
- 映射至少还有 15 秒有效期；
- 返回地址为公网 IPv4；
- Candidate 类型为 `mapped4`。

续租在剩余租期进入安全窗口后自动进行。失败后默认 60 秒再尝试。

可通过环境变量调整：

```text
P2P_PORTMAP_LIFETIME
P2P_PORTMAP_RETRY
P2P_PORTMAP_TIMEOUT
P2P_UPNP_TIMEOUT
P2P_PORTMAP_POLL
P2P_PORTMAP_STATE_FILE
```

## CGNAT 处理

如果 PCP/NAT-PMP/UPnP 返回 RFC1918、CGNAT `100.64.0.0/10` 或其他非公网 IPv4，映射不会发布为 `mapped4`。

这避免把“只在上一级 NAT 内有效”的映射误认为互联网可达地址。

## 路径优先级

```text
lan4       1000
host6       900
mapped4     800
observed4   600
predicted4  400
VPS relay   fallback
```

对当前服务器对称 NAT 场景，`mapped4` 的价值在于：客户端只需要主动向服务器的固定映射地址发送 WireGuard 握手，服务器无需依赖 server -> VPS 的 NAT 映射端口来预测 server -> client 的端口。

## 部署

服务器更新仓库文件后，在 Linux 目录执行：

```bash
sudo sh install_portmap.sh
```

脚本会：

1. 从已运行的 `wireguard-p2p-agent.service` 获取服务用户；
2. 安装 `portmap.py`、`portmap_daemon.py`、`candidates.py` 到 `/opt/wireguard-p2p/`；
3. 安装并启用 `wireguard-p2p-portmap.service`；
4. 重启 Agent 使其加载新版 `candidates.py`。

如果无法自动识别服务用户：

```bash
sudo sh install_portmap.sh <service-user>
```

## 诊断

```bash
systemctl status wireguard-p2p-portmap.service
journalctl -u wireguard-p2p-portmap.service -n 50 --no-pager
cat /var/lib/wireguard-p2p/mapped4.json
```

有成功映射时缓存中应包含：

```json
{
  "method": "pcp | natpmp | upnp",
  "internal_ip": "192.168.x.x",
  "internal_port": 35422,
  "candidate": {
    "type": "mapped4",
    "endpoint": "PUBLIC_IP:PORT"
  }
}
```

没有缓存不代表 P2P 失效，只表示路由器未提供可用显式 IPv4 映射；系统继续尝试 IPv6、observed4，并保留 VPS relay。

## 当前范围

v7.1 首先在 Linux 服务器侧启用映射，因为当前困难 NAT 位于 GPU/2696 所在服务器网络。Windows 客户端无需拥有映射即可主动连接服务器 `mapped4`。

Windows 侧主动端口映射属于可选增强，不是当前拓扑直连成立的必要条件。
