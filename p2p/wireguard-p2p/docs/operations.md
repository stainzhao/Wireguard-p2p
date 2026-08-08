# Operations

本文档只面向当前 **v7.6.0** 实现。

## 1. 运行角色

```text
VPS:
  peers_api.py
  peers-api.service

Linux P2P server (.2/.5):
  p2p_agent.py
  candidates.py
  portmap.py / portmap_daemon.py
  wireguard-p2p-agent.service
  wireguard-p2p-portmap.service

Windows client:
  artifact wireguard-p2p-windows-amd64

Linux client:
  artifact wireguard-p2p-linux-amd64 或 wireguard-p2p-linux-arm64
  wireguard-p2p-client.service
```

Linux client 和 Linux server 是不同角色：普通客户端运行 Go binary；只有 `.2/.5` 运行 Python Server Agent。

## 2. Linux client 快速部署

前置条件：

```text
systemd
wireguard-tools
已配置并可用的 WireGuard wg0
到 VPS 10.0.0.1 的基线连接
```

下载与 CPU 架构匹配的 artifact，解压其中的 `wireguard-p2p-linux-*.tar.gz`，再解包：

```bash
tar -xzf wireguard-p2p-linux-amd64.tar.gz
sudo ./install.sh --interface wg0
```

ARM64 使用对应 arm64 包。安装后：

```bash
systemctl status wireguard-p2p-client.service
journalctl -u wireguard-p2p-client.service -n 50 --no-pager
wg show wg0
```

卸载：

```bash
sudo ./uninstall.sh
```

安装/卸载均不会修改 `/etc/wireguard/`、WireGuard key、VPS peer 或 `AllowedIPs=10.0.0.0/24`。

## 3. Linux server 低写入运行态

`.2/.5` 临时状态继续位于：

```text
/run/wireguard-p2p/state.json
/run/wireguard-p2p/mapped4.json
/run/wireguard-p2p/*.lock
```

Python Server Agent routine stdout 默认丢弃，stderr 才进入 journal。Linux Go client 的日志主要是连接状态变化与错误，由 systemd journal 接收。

## 4. 常用检查

Linux client：

```bash
systemctl status wireguard-p2p-client.service
wg show wg0
ping 10.0.0.2
ping 10.0.0.5
```

Linux server：

```bash
systemctl status wireguard-p2p-agent.service
curl http://10.0.0.5:8898/health
wg show wg0
```

VPS：

```bash
systemctl status peers-api.service
curl http://10.0.0.1:8899/health
```

## 5. 更新原则

建议顺序仍为：VPS -> `.2/.5` Server Agent -> clients。协议 7 的 `/24` relay 基线始终保留。

Windows 与 Linux clients 使用同一 Go core，因此同一个 release 的 P2P 行为应保持一致。Linux amd64/arm64 只区别 CPU 架构。
