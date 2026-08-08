# WireGuard P2P

当前生产实现：**v7.7.1**。协议仍为 7，VPS `10.0.0.0/24` relay 基线保持不变。

## 角色

```text
VPS coordinator
  └─ p2p/wireguard-p2p/vps/

Linux P2P servers (.2 / .5)
  └─ p2p/wireguard-p2p/linux/          Python server Agent

P2P clients
  └─ p2p/wireguard-p2p-client/         共享 Go client core
       ├─ Windows amd64
       ├─ Linux amd64
       └─ Linux arm64
```

普通 Linux 客户端不运行 `.2/.5` 的 Python Agent；它与 Windows 一样运行 Go client。Go core 共用 Candidate 排序、IPv6/NAT66、IPv4 simultaneous punch、fresh WireGuard handshake 验证以及 Direct/Relay 切换，仅把进程、信号和 `wg` 定位等 OS 细节拆到 platform 文件。

## Candidate 顺序

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

只有 fresh authenticated WireGuard handshake 成功后才安装目标 `/32`。任何 Direct 探测失败都回到 VPS `/24` 基线。

## 客户端发布物

`main` CI 生成三个 artifact：

```text
wireguard-p2p-windows-amd64
wireguard-p2p-linux-amd64
wireguard-p2p-linux-arm64
```

Windows：安装 WireGuard、导入现有配置，然后运行 EXE。

Linux client：先确保 WireGuard 基线已通，例如 `ping 10.0.0.1`，解压对应架构的 tar.gz 后执行：

```bash
sudo ./install.sh --interface wg0
```

安装器只安装 `/usr/local/bin/wireguard-p2p` 和 `wireguard-p2p-client.service`，不会修改 WireGuard 配置、密钥或 `AllowedIPs`。

## 当前结构

```text
.github/workflows/ci.yml              当前唯一 CI
p2p/wireguard-p2p-client/            Windows/Linux 共享 Go 客户端
p2p/wireguard-p2p/linux/             .2/.5 Linux Server Agent + port mapping
p2p/wireguard-p2p/vps/               VPS coordinator
p2p/wireguard-p2p/tests/             Python 回归测试
p2p/wireguard-p2p/docs/              当前架构与运维文档
```

编译后的二进制不提交进 Git，只由成功的 `main` CI 产出。


## 一行更新（v7.7+）

Linux VPS、`.2/.5` Server Agent、Linux Client 安装一次管理入口后，后续统一：

```bash
sudo wireguard-p2p update
```

Windows Client：

```powershell
.\wireguard-p2p.exe update
```

更新分发采用 `GitHub Release -> VPS 私有缓存 -> WireGuard 节点`。私有 GitHub 的只读凭据只保存在 VPS；普通客户端和 `.2/.5` 不保存 GitHub Token。VPS 在切换 coordinator 前会验证所有发布物 SHA-256 并缓存到 `/var/lib/wireguard-p2p/updates/current`，其他节点只通过 `10.0.0.1:8899/updates/` 获取经过清单校验的包。失败时保留或恢复旧版本；WireGuard 配置、密钥和 `/24` relay baseline 不参与更新。
