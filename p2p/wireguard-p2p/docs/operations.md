# Operations

本文档只面向当前 v7.4.0 实现。

## 1. 运行组件

```text
VPS:
  peers_api.py
  peers-api.service

Linux server:
  p2p_agent.py
  candidates.py
  portmap.py
  portmap_daemon.py
  wireguard-p2p-agent.service
  wireguard-p2p-portmap.service

Windows:
  GitHub Actions artifact: wireguard-p2p-windows-amd64
```

旧 `p2p_sync.py` 与 `wireguard-p2p-sync.service` 已退出当前架构。

## 2. Linux 低写入运行态

当前临时状态：

```text
/run/wireguard-p2p/state.json
/run/wireguard-p2p/mapped4.json
/run/wireguard-p2p/*.lock
```

`/run` 通常由 tmpfs 提供。文件是覆盖式小快照，不会随 uptime 持续累积，也不要求持久化 `fsync()`。

当前 systemd unit 使用：

```ini
StandardOutput=null
StandardError=journal
LogRateLimitIntervalSec=5min
LogRateLimitBurst=20
```

正常事件不进入 journal；真正 stderr 错误仍可诊断。systemd 自身启停记录仍可能出现在 journal。

## 3. 常用检查

Linux Agent：

```bash
systemctl status wireguard-p2p-agent.service
curl http://10.0.0.5:8898/health
wg show wg0
ls -lh /run/wireguard-p2p
```

VPS：

```bash
systemctl status peers-api.service
curl http://10.0.0.1:8899/health
```

port mapping：

```bash
systemctl status wireguard-p2p-portmap.service
cat /run/wireguard-p2p/mapped4.json
```

## 4. 当前部署更新原则

建议顺序：VPS -> Linux server -> Windows。控制面/Agent 版本先更新后再替换 Windows artifact，可减少滚动升级期间的行为差异。

Windows EXE 不从仓库源码目录获取，只使用 `main` CI 成功后的 Actions artifact。

## 5. 一次性清理旧 Linux 部署

确认当前 `wireguard-p2p-agent.service` 已正常运行后，可清理早期 synchronizer：

```bash
sudo systemctl disable --now wireguard-p2p-sync.service 2>/dev/null || true
sudo rm -f /etc/systemd/system/wireguard-p2p-sync.service
sudo rm -f /opt/wireguard-p2p/p2p_sync.py
sudo rm -f /var/lib/wireguard-p2p/state.json
sudo systemctl daemon-reload
```

这些文件不属于当前架构。

## 6. 调试

生产 unit 默认丢弃 stdout。需要详细诊断时，可临时在 shell 中运行 Agent 并设置：

```bash
P2P_VERBOSE_LOG=1
```

不要长期启用 verbose 输出。


## IPv4 P2P diagnostics

With Windows console output enabled, an IPv4 rendezvous attempt can show `Simultaneous IPv4 punch ... via A.B.C.D:PORT`. If the VPS-observed port does not work, up to four same-IP bounded predictions may be attempted. `P2P OK ... via observed4` confirms a fresh authenticated direct handshake. Failure removes the dynamic `/32` peer and leaves the VPS `/24` relay intact. No additional public STUN/observer port is required by v7.5.
