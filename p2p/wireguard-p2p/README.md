# WireGuard P2P v6.2

该项目在保留 VPS `10.0.0.1` 中转路由的同时，为客户端与 GPU
`10.0.0.2`、2696 `10.0.0.5` 建立动态 `/32` P2P 路由。

## 运行结构

- VPS：`peers-api.service`，监听 `10.0.0.1:8899`，接收外部设备连接事件。
- GPU、2696：`wireguard-p2p-agent.service`，分别监听 `10.0.0.2:8898`
  和 `10.0.0.5:8898`，不再轮询 VPS。
- Windows：`wireguard-p2p.exe`，窗口打开期间运行。
- 手机 `10.0.0.8`：固定使用 VPS 中转，不参与 P2P。

V6 使用 `POST /connect` 注册外部设备会话。VPS 随后通过带 HMAC、时间戳
和防重放窗口的 `/offer` 通知两台服务器，并从响应中取得服务器 LAN 信息。
VPS 仍保留 `/sync`、`/announce` 和 `GET /`；旧客户端调用这些接口时也会
触发事件通知，便于滚动升级与回退。

## 状态与日志

两台服务器 Agent 默认不记录候选、探测、直连和回退等正常事件，只把监控或
请求处理异常写入 stderr，由 systemd journal 接收。临时诊断时可设置
`P2P_VERBOSE_LOG=1` 恢复详细事件日志。Agent 不创建独立日志文件：

```bash
systemctl status wireguard-p2p-agent.service
journalctl -u wireguard-p2p-agent.service -n 50 --no-pager
```

VPS：

```bash
systemctl status peers-api.service
curl --noproxy '*' http://10.0.0.1:8899/health
```

VPS 保留会话连接、断开、过期以及限频后的推送失败和恢复日志，作为中心诊断点。
健康响应中的 `server_push` 会显示每台服务器最近推送成功时间、连续失败次数
和限长错误信息。

三台设备使用 `journald-wireguard-p2p.conf` 将完整 systemd journal 限制为
100 MB、最多保留 14 天；该限制覆盖系统 journal，不只覆盖 P2P 服务。

Windows 只向控制台输出，不写磁盘日志。协调服务异常时，请求间隔会在
15 至 60 秒之间退避；程序仍会检查本地握手并删除失效 `/32`，确保回退 VPS。
两台服务器空闲时不向 VPS 发出任何 HTTP 请求。

## 故障策略

- 直连握手超过 180 秒未更新：删除 `/32` 并回退 VPS，避免正常的
  WireGuard 约 120 秒换密钥周期被误判。
- 探测 90 秒未成功：前两次按 60、120 秒退避；第 3 次起进入 30 分钟
  冷却，停止持续发送无效 keepalive。冷却期间流量继续走 VPS。
- 端点发生变化：立即解除退避并重新探测。
- 外部设备超过 120 秒未续租：VPS 通知两台服务器清除动态 Peer。
- VPS 通知丢失时：服务器本地租约仍会独立清理 Peer。

## 文件

- `vps/peers_api.py`：VPS 协调 API。
- `vps/peers-api.service`：VPS systemd unit。
- `linux/p2p_agent.py`：Linux 事件 Agent 与本地握手监控器。
- `linux/wireguard-p2p-agent.service`：Linux systemd unit 模板。
- `linux/p2p_sync.py`：仅供源码审计的 V5 历史同步器；两台服务器上已卸载。
- `journald-wireguard-p2p.conf`：三台设备共用的 journal 容量与保留期限制。
- `../wireguard-p2p-exe/`：Windows Go 源码和构建产物。

两台服务器的历史备份已集中迁移到 VPS：
`/var/backups/wireguard-p2p-server-archive-20260806/2696/` 和
`/var/backups/wireguard-p2p-server-archive-20260806/gpu/`。每个目录均附有
`SHA256SUMS` 完整性清单，两台服务器本地不再保留备份；VPS 自身的历史备份
仍位于 `/var/backups/wireguard-p2p-pre-*/`。清理前的旧同步器最终副本位于各主机
目录下的 `retired-runtime-v6.1/`。
