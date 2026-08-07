# WireGuard P2P v7.2 IPv6 NAT traversal

## 目标

v7.2 优先解决校园网环境中“IPv6 免费、IPv4 计费”以及服务器位于 IPv6 地址转换/状态防火墙后的场景。

当前已知拓扑：

```text
Windows client (.3) -- mobile hotspot / native IPv6
                         |
                         | IPv6
                         v
server .2 -------- native campus IPv6 2001:da8:...    (direct host6 works)
server .5 -------- router LAN 2001:3::...              (not a native host6)
                         |
                         v
                    router/NAT66-like translation
                         |
                         v
                    WAN 2001:da8:...
```

现有 VPS 只有 IPv4也可以继续充当控制面；v7.2 第一阶段不要求新增 IPv6 VPS。

## IPv6 Candidate policy

`host6` 只表示可直接作为终端地址使用的 native global IPv6。协议专用/转换/文档前缀不能作为 `host6`。

当前显式排除：

```text
64:ff9b::/96
64:ff9b:1::/48
100::/64
2001::/32
2001:2::/48
2001:3::/32
2001:4:112::/48
2001:10::/28
2001:20::/28
2001:db8::/32
2002::/16
3fff::/20
```

因此路由器分配给 `.5` 的 `2001:3::/32` 不再被发布为 `host6`。

## observed6

新增逻辑类型：

```text
observed6 priority=850
```

它不是节点自行声明的 LAN IPv6，而是 WireGuard 在收到认证握手后实际学习到的公网 IPv6 Endpoint，例如：

```text
[2001:da8:216:191a:5ad9:d5ff:fe0d:dcf1]:48132
```

`observed6` 的可信依据是 WireGuard cryptokey routing / endpoint roaming：只有能够通过对应 peer 公钥认证的握手才能更新 Endpoint。

## 无 IPv6 Reflector 的第一阶段

当 Windows 本机拥有 native `host6`，但远端 `.5` 没有可发布的 `host6` 时：

1. `.5` 从 VPS 的 `/offer` 获得 Windows 的 native IPv6 Candidate；
2. `.5` 使用真实 kernel WireGuard socket 主动向 Windows `host6` 发起握手；
3. Windows 的普通 active candidates 如果失败，会保留一个无 `/32` 路由的被动 WireGuard peer；
4. `.5` 后续重试到达 Windows 后，Windows 从 `wg show` 学到 `.5` 的 NAT66 后公网 IPv6 Endpoint；
5. Windows 将该 Endpoint 分类为 `observed6`；
6. 只有认证握手新鲜时才安装 `.5/32`；
7. 后续业务流量直接使用 IPv6 P2P。

被动 peer 不包含目标 `/32` AllowedIPs，因此等待阶段的正常业务流量仍然通过 VPS relay，不会被黑洞。

## 预期 Windows 日志

`.2` 原生 IPv6：

```text
P2P OK 10.0.0.2 via host6 [2001:da8:...]:35422
```

`.5` 首轮无法直接建立路径时：

```text
Candidate probe failed 10.0.0.5; passive IPv6 listener armed; active retry in 1m0s.
```

如果 `.5` 的主动 IPv6 握手随后穿过路由器：

```text
P2P OK 10.0.0.5 via observed6 [2001:da8:...]:PORT
```

这条日志意味着 `.5` 的 `/32` 已经安装到真实 IPv6 Endpoint，大流量不再经过 IPv4 VPS。

## 为什么不直接使用 2001:3:: 地址

`2001:3::/32` 是 IANA 特殊用途 AMT 前缀，不应被本项目当作普通 native host candidate。更重要的是实网已经证明 `.5` 的 LAN IPv6 与外部看到的 IPv6 不一致，因此直接把 LAN 地址交给远端没有意义。

## 失败后的下一步

如果 Windows 长期保持 `passive IPv6 listener armed`，但始终没有出现 `observed6`，说明手机热点/运营商或路由器的 IPv6 filtering 需要双方同时向对方的外部 Endpoint 发包。

此时进入 v7.2 第二阶段：

```text
multi-observer / reflector
+ IPv6 mapping behavior detection
+ simultaneous IPv6 punch
```

Reflector 是可选基础设施，不再依赖 `.2` 长期开机。可以使用任何未来增加的长期在线 native IPv6 节点；控制面仍可继续使用当前 IPv4 VPS。

## 数据流策略

目标顺序：

```text
lan4
 -> host6
 -> observed6
 -> mapped4
 -> observed4
 -> predicted4
 -> IPv4 relay
```

校园网环境中，IPv4 relay 只作为最后兜底。控制面的少量 IPv4 API 流量与远程桌面/文件传输等数据面流量分离。
