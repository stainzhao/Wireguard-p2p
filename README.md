# WireGuard P2P

当前生产实现：**v7.5.0**。仓库 `main` 只保留当前实现，不再保存历史版本源码、迁移脚本、旧协议文档或编译后的 Windows EXE。

## 目标

在保留 VPS `10.0.0.1` 的 `10.0.0.0/24` WireGuard relay 基线的同时，为 Windows 客户端与 Linux 服务器建立更具体的动态 `/32` P2P 路由。任何 P2P 探测失败都不会破坏 VPS 基线连通性。

当前 Candidate 顺序：

```text
lan4        1000   同局域网 IPv4
host6        900   原生公网 IPv6
observed6    850   WireGuard 已认证学习到的公网 IPv6 Endpoint
reflexive6   825   NAT66 外部 IPv6 + WG ListenPort（未验证）
mapped4      800   PCP / NAT-PMP / UPnP 显式映射
observed4    600   VPS 观察到的公网 IPv4 Endpoint
predicted4   400   IPv4 端口预测预留
```

`reflexive6` 与 simultaneous IPv6 punch 用于两侧都存在 IPv6 stateful firewall/NAT66 的场景；只有 fresh authenticated WireGuard handshake 成功后才安装目标 `/32`。

## 当前结构

```text
.github/workflows/ci.yml          当前唯一 CI
p2p/wireguard-p2p-exe/           Windows Go 客户端源码
p2p/wireguard-p2p/linux/         Linux P2P Agent + port mapping
p2p/wireguard-p2p/vps/           VPS coordinator
p2p/wireguard-p2p/tests/         当前 Python 回归测试
p2p/wireguard-p2p/docs/          当前架构与运维文档
```

Windows 二进制**不提交到 Git**，每次 `main` CI 通过后从 GitHub Actions artifact `wireguard-p2p-windows-amd64` 获取。

## 当前运行特性

- VPS relay `AllowedIPs = 10.0.0.0/24` 保持不变。
- Windows 建链/恢复阶段 15 秒同步；稳定 direct 且协调器支持 v7.4 时降到 60 秒。
- Linux 探测/恢复阶段 5 秒检查；稳定 direct 30 秒；无 session 60 秒。
- 健康 direct 与 VPS control lease 解耦：VPS 控制面临时故障不会主动拆除仍有新鲜 WireGuard handshake 的 `/32` direct。
- Linux 临时状态全部位于 `/run/wireguard-p2p/`，默认不产生持续 SSD 状态写入。
- systemd 服务丢弃 routine stdout，仅把 stderr 错误送入 journal，并进行限流。
- `PersistentKeepalive=25` 保留，用于维持 NAT/stateful firewall UDP 状态。

## 文档

- `p2p/wireguard-p2p/docs/architecture.md`：当前协议、Candidate、打洞、安全和状态机。
- `p2p/wireguard-p2p/docs/operations.md`：部署、更新、诊断、低写入策略和旧部署清理。

## CI

`main` 每次变更都会执行：

1. 仓库卫生检查，拒绝旧兼容文件、已编译 EXE 和 Python cache；
2. Python 编译检查与全部回归测试；
3. Go `gofmt`、`go vet`、`go test`；
4. Windows amd64 交叉编译；
5. 上传 Windows artifact。

历史实现只存在于 Git 历史/备份分支中，不再出现在当前源码树。


### IPv4 simultaneous direct

v7.5 adds an 8-second simultaneous `observed4` WireGuard punch and bounded same-IP port prediction for sequential symmetric NAT. `mapped4` remains preferred and the VPS `/24` relay remains the connectivity baseline.
