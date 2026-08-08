# Operations

当前版本：**v7.10.0**。

## Roles

VPS `10.0.0.1` 是 Coordinator。其他合法 `10.0.0.x` 没有固定身份：默认是 `client`，可由 VPS 显式设置为 `server` 或 `relay_only`。

```bash
sudo wireguard-p2p role list
sudo wireguard-p2p role get 10.0.0.8
sudo wireguard-p2p role set 10.0.0.8 server
sudo wireguard-p2p role set 10.0.0.8 relay_only
sudo wireguard-p2p role set 10.0.0.8 client
```

新安装的角色注册表为空；升级保留已有文件：

```text
/etc/wireguard-p2p/servers.conf
/etc/wireguard-p2p/relay-only.conf
```

## One-line deployment

Linux Server：先在 VPS 设置 `server`，然后目标机：

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-server.sh | sudo sh
```

普通 Linux Client：

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-client.sh | sudo sh
```

## Update

```bash
sudo wireguard-p2p update
```

Windows 使用：

```powershell
.\wireguard-p2p.exe update
```

建议更新顺序：VPS -> Servers -> Clients。

## Runtime checks

VPS：

```bash
sudo wireguard-p2p status
sudo wireguard-p2p role list
curl -fsS http://10.0.0.1:8899/health
```

Server：

```bash
sudo wireguard-p2p status
systemctl is-active wireguard-p2p-agent.service
systemctl is-active wireguard-p2p-portmap.service
wg show wg0
```

Client：

```bash
systemctl is-active wireguard-p2p-client.service
wg show wg0
```

所有安装和更新都不得修改 WireGuard key、基础 VPS peer 或 `AllowedIPs=10.0.0.0/24` Relay baseline。
