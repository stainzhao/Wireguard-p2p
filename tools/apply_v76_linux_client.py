#!/usr/bin/env python3
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / "p2p/wireguard-p2p-exe"
CLIENT = ROOT / "p2p/wireguard-p2p-client"

if CLIENT.exists():
    raise SystemExit("target client directory already exists")
OLD.rename(CLIENT)


def replace(path, old, new, count=-1):
    p = ROOT / path
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing pattern in {path}: {old[:100]!r}")
    p.write_text(text.replace(old, new, count), encoding="utf-8")


# Release number: keep all current components aligned while protocol remains 7.
for p in list(ROOT.rglob("*.py")) + list(ROOT.rglob("*.go")) + list(ROOT.rglob("*.md")):
    if ".git" in p.parts or p == Path(__file__):
        continue
    text = p.read_text(encoding="utf-8")
    if "7.5.0" in text:
        p.write_text(text.replace("7.5.0", "7.6.0"), encoding="utf-8")

main_path = CLIENT / "main.go"
main = main_path.read_text(encoding="utf-8")
main = main.replace('\t"os"\n', '')
main = main.replace('\t"path/filepath"\n', '')
old_start = '''\tif !acquireSingleInstance() {\n\t\tfmt.Println("WireGuard P2P is already running.")\n\t\twaitForEnter()\n\t\treturn\n\t}\n\n\tif oldTaskExists() {\n\t\tfmt.Println("Old scheduled task \'WireGuard P2P Sync\' still exists.")\n\t\tfmt.Println("Run remove_old_powershell_task.ps1 as Administrator, then start this EXE again.")\n\t\twaitForEnter()\n\t\treturn\n\t}\n\n\twgPath := filepath.Join(os.Getenv("ProgramFiles"), "WireGuard", "wg.exe")\n\tif _, err := os.Stat(wgPath); err != nil {\n\t\tfmt.Printf("WireGuard wg.exe was not found: %s\\n", wgPath)\n\t\twaitForEnter()\n\t\treturn\n\t}\n'''
new_start = '''\tif !acquireSingleInstance() {\n\t\tfmt.Println("WireGuard P2P client is already running or the runtime lock is unavailable.")\n\t\tplatformPauseOnFatal()\n\t\treturn\n\t}\n\n\tif err := legacyClientConflict(); err != nil {\n\t\tfmt.Println(err)\n\t\tplatformPauseOnFatal()\n\t\treturn\n\t}\n\n\twgPath, err := resolveWGExecutable()\n\tif err != nil {\n\t\tfmt.Println(err)\n\t\tplatformPauseOnFatal()\n\t\treturn\n\t}\n'''
if old_start not in main:
    raise SystemExit("main startup block not found")
main = main.replace(old_start, new_start, 1)
old_legacy = '''func oldTaskExists() bool {\n\tcmd := exec.Command("schtasks.exe", "/Query", "/TN", "WireGuard P2P Sync")\n\tcmd.Stdout = io.Discard\n\tcmd.Stderr = io.Discard\n\treturn cmd.Run() == nil\n}\n\nfunc waitForEnter() {\n\tfmt.Println("Press Enter to close.")\n\t_, _ = fmt.Scanln()\n}\n\n'''
if old_legacy not in main:
    raise SystemExit("legacy Windows-only block not found")
main = main.replace(old_legacy, '', 1)
main = main.replace(
    'fmt.Printf("WireGuard P2P %s is running. Close this window or press Ctrl+C to stop.\\n", version)',
    'fmt.Printf("WireGuard P2P %s client is running on %s. Press Ctrl+C to stop.\\n", version, platformLabel())',
)
main = main.replace('a.log("Stopping: removing dynamic GPU/2696 peers...")', 'a.log("Stopping: removing dynamic direct server peers...")')
main_path.write_text(main, encoding="utf-8")

# OS-specific process/bootstrap handling.
(CLIENT / "platform_windows.go").write_text(r'''//go:build windows

package main

import (
    "errors"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
)

func resolveWGExecutable() (string, error) {
    if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
        candidate := filepath.Join(programFiles, "WireGuard", "wg.exe")
        if _, err := os.Stat(candidate); err == nil {
            return candidate, nil
        }
    }
    if candidate, err := exec.LookPath("wg.exe"); err == nil {
        return candidate, nil
    }
    return "", errors.New("WireGuard wg.exe was not found; install WireGuard for Windows first")
}

func legacyClientConflict() error {
    cmd := exec.Command("schtasks.exe", "/Query", "/TN", "WireGuard P2P Sync")
    cmd.Stdout = io.Discard
    cmd.Stderr = io.Discard
    if cmd.Run() == nil {
        return errors.New("old scheduled task 'WireGuard P2P Sync' still exists; remove it before starting the current client")
    }
    return nil
}

func platformPauseOnFatal() {
    fmt.Println("Press Enter to close.")
    _, _ = fmt.Scanln()
}

func platformLabel() string { return "Windows" }
''', encoding="utf-8")

(CLIENT / "platform_linux.go").write_text(r'''//go:build linux

package main

import (
    "errors"
    "os/exec"
)

func resolveWGExecutable() (string, error) {
    candidate, err := exec.LookPath("wg")
    if err != nil {
        return "", errors.New("wg was not found in PATH; install wireguard-tools first")
    }
    return candidate, nil
}

func legacyClientConflict() error { return nil }
func platformPauseOnFatal()       {}
func platformLabel() string       { return "Linux" }
''', encoding="utf-8")

(CLIENT / "platform_other.go").write_text(r'''//go:build !windows && !linux

package main

import (
    "errors"
    "os/exec"
    "runtime"
)

func resolveWGExecutable() (string, error) {
    candidate, err := exec.LookPath("wg")
    if err != nil {
        return "", errors.New("wg was not found in PATH")
    }
    return candidate, nil
}

func legacyClientConflict() error { return nil }
func platformPauseOnFatal()       {}
func platformLabel() string       { return runtime.GOOS }
''', encoding="utf-8")

# Linux gets a real signal handler and a non-blocking runtime singleton lock.
old_console = CLIENT / "console_nonwindows.go"
if old_console.exists():
    old_console.unlink()
(CLIENT / "console_linux.go").write_text(r'''//go:build linux

package main

import (
    "os"
    "os/signal"
    "sync"
    "syscall"
)

var instanceLockFile *os.File

func acquireSingleInstance() bool {
    const runtimeDir = "/run/wireguard-p2p-client"
    if err := os.MkdirAll(runtimeDir, 0755); err != nil {
        return false
    }
    file, err := os.OpenFile(runtimeDir+"/client.lock", os.O_CREATE|os.O_RDWR, 0600)
    if err != nil {
        return false
    }
    if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
        _ = file.Close()
        return false
    }
    instanceLockFile = file
    return true
}

func installConsoleCloseHandler() (<-chan struct{}, chan struct{}) {
    shutdown := make(chan struct{})
    cleanupDone := make(chan struct{})
    signals := make(chan os.Signal, 1)
    signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
    var once sync.Once
    go func() {
        select {
        case <-signals:
            once.Do(func() { close(shutdown) })
        case <-cleanupDone:
            signal.Stop(signals)
        }
    }()
    return shutdown, cleanupDone
}
''', encoding="utf-8")

(CLIENT / "console_other.go").write_text(r'''//go:build !windows && !linux

package main

import (
    "os"
    "os/signal"
    "sync"
)

func acquireSingleInstance() bool { return true }

func installConsoleCloseHandler() (<-chan struct{}, chan struct{}) {
    shutdown := make(chan struct{})
    cleanupDone := make(chan struct{})
    signals := make(chan os.Signal, 1)
    signal.Notify(signals, os.Interrupt)
    var once sync.Once
    go func() {
        select {
        case <-signals:
            once.Do(func() { close(shutdown) })
        case <-cleanupDone:
            signal.Stop(signals)
        }
    }()
    return shutdown, cleanupDone
}
''', encoding="utf-8")

# Linux client deployment payload.
deploy = CLIENT / "deploy/linux"
deploy.mkdir(parents=True, exist_ok=True)
(deploy / "wireguard-p2p-client.service").write_text(r'''[Unit]
Description=WireGuard P2P cross-platform client
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
Environment=P2P_INTERFACE=wg0
EnvironmentFile=-/etc/default/wireguard-p2p-client
ExecStart=/usr/local/bin/wireguard-p2p --interface=${P2P_INTERFACE}
Restart=always
RestartSec=5
TimeoutStopSec=10
RuntimeDirectory=wireguard-p2p-client
RuntimeDirectoryMode=0755
UMask=0077
StandardOutput=journal
StandardError=journal

CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
''', encoding="utf-8")

(deploy / "install.sh").write_text(r'''#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root." >&2
    exit 1
fi

INTERFACE=wg0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --interface)
            [ "$#" -ge 2 ] || { echo "--interface requires a value" >&2; exit 2; }
            INTERFACE=$2
            shift 2
            ;;
        -h|--help)
            echo "Usage: sudo ./install.sh [--interface wg0]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

command -v systemctl >/dev/null 2>&1 || { echo "systemd is required." >&2; exit 1; }
command -v wg >/dev/null 2>&1 || { echo "wireguard-tools is required (wg not found)." >&2; exit 1; }

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BINARY="$SCRIPT_DIR/wireguard-p2p"
UNIT_SOURCE="$SCRIPT_DIR/wireguard-p2p-client.service"

[ -x "$BINARY" ] || { echo "Missing executable: $BINARY" >&2; exit 1; }
[ -f "$UNIT_SOURCE" ] || { echo "Missing systemd unit: $UNIT_SOURCE" >&2; exit 1; }

install -m 0755 "$BINARY" /usr/local/bin/wireguard-p2p
install -m 0644 "$UNIT_SOURCE" /etc/systemd/system/wireguard-p2p-client.service
install -d -m 0755 /etc/default
printf 'P2P_INTERFACE=%s\n' "$INTERFACE" > /etc/default/wireguard-p2p-client
chmod 0644 /etc/default/wireguard-p2p-client

if ! wg show "$INTERFACE" >/dev/null 2>&1; then
    echo "Warning: WireGuard interface '$INTERFACE' is not active yet."
    echo "The client will keep restarting until the interface becomes available."
fi

systemctl daemon-reload
systemctl enable --now wireguard-p2p-client.service
sleep 1
systemctl --no-pager --full status wireguard-p2p-client.service || true

echo
echo "Installed WireGuard P2P client for interface: $INTERFACE"
echo "The existing WireGuard configuration and AllowedIPs were not modified."
''', encoding="utf-8")

(deploy / "uninstall.sh").write_text(r'''#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this uninstaller as root." >&2
    exit 1
fi

systemctl disable --now wireguard-p2p-client.service 2>/dev/null || true
rm -f /etc/systemd/system/wireguard-p2p-client.service
rm -f /etc/default/wireguard-p2p-client
rm -f /usr/local/bin/wireguard-p2p
rm -rf /run/wireguard-p2p-client
systemctl daemon-reload

echo "WireGuard P2P client removed. WireGuard itself was not modified."
''', encoding="utf-8")

# Current CI: test shared core once natively, then build all supported client binaries.
(ROOT / ".github/workflows/ci.yml").write_text(r'''name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Repository hygiene
        run: |
          test ! -e p2p/wireguard-p2p/linux/p2p_sync.py
          test ! -e p2p/wireguard-p2p/linux/wireguard-p2p-sync.service
          test ! -e p2p/wireguard-p2p-exe
          test ! -e p2p/wireguard-p2p/journald-wireguard-p2p.conf
          if find p2p -type f -name '*.exe' -print -quit | grep -q .; then
            echo 'compiled Windows EXE must not be tracked'
            exit 1
          fi
          if find . -type d -name __pycache__ -print -quit | grep -q .; then
            echo 'tracked/generated __pycache__ is not allowed'
            exit 1
          fi
      - name: Compile Python sources
        run: python -m compileall -q p2p/wireguard-p2p/linux p2p/wireguard-p2p/vps
      - name: Run Python tests
        run: python -m unittest discover -s p2p/wireguard-p2p/tests -v

  client:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: p2p/wireguard-p2p-client/go.mod
          cache-dependency-path: p2p/wireguard-p2p-client/go.mod
      - name: Check gofmt
        working-directory: p2p/wireguard-p2p-client
        run: test -z "$(gofmt -l .)"
      - name: Vet shared client
        working-directory: p2p/wireguard-p2p-client
        run: go vet ./...
      - name: Test shared client on Linux
        working-directory: p2p/wireguard-p2p-client
        run: go test ./...
      - name: Build Windows amd64
        working-directory: p2p/wireguard-p2p-client
        run: |
          mkdir -p dist/windows-amd64
          GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o dist/windows-amd64/wireguard-p2p.exe .
      - name: Build Linux amd64 package
        working-directory: p2p/wireguard-p2p-client
        run: |
          mkdir -p dist/linux-amd64/package
          GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o dist/linux-amd64/package/wireguard-p2p .
          cp deploy/linux/install.sh deploy/linux/uninstall.sh deploy/linux/wireguard-p2p-client.service dist/linux-amd64/package/
          chmod 0755 dist/linux-amd64/package/wireguard-p2p dist/linux-amd64/package/install.sh dist/linux-amd64/package/uninstall.sh
          tar -C dist/linux-amd64/package -czf dist/wireguard-p2p-linux-amd64.tar.gz .
      - name: Build Linux arm64 package
        working-directory: p2p/wireguard-p2p-client
        run: |
          mkdir -p dist/linux-arm64/package
          GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o dist/linux-arm64/package/wireguard-p2p .
          cp deploy/linux/install.sh deploy/linux/uninstall.sh deploy/linux/wireguard-p2p-client.service dist/linux-arm64/package/
          chmod 0755 dist/linux-arm64/package/wireguard-p2p dist/linux-arm64/package/install.sh dist/linux-arm64/package/uninstall.sh
          tar -C dist/linux-arm64/package -czf dist/wireguard-p2p-linux-arm64.tar.gz .
      - name: Upload Windows client
        uses: actions/upload-artifact@v4
        with:
          name: wireguard-p2p-windows-amd64
          path: p2p/wireguard-p2p-client/dist/windows-amd64/wireguard-p2p.exe
          if-no-files-found: error
          retention-days: 14
      - name: Upload Linux amd64 client
        uses: actions/upload-artifact@v4
        with:
          name: wireguard-p2p-linux-amd64
          path: p2p/wireguard-p2p-client/dist/wireguard-p2p-linux-amd64.tar.gz
          if-no-files-found: error
          retention-days: 14
      - name: Upload Linux arm64 client
        uses: actions/upload-artifact@v4
        with:
          name: wireguard-p2p-linux-arm64
          path: p2p/wireguard-p2p-client/dist/wireguard-p2p-linux-arm64.tar.gz
          if-no-files-found: error
          retention-days: 14
''', encoding="utf-8")

# Go regression test: shared source must remain OS-neutral and Linux deployment files present.
(CLIENT / "cross_platform_test.go").write_text(r'''package main

import (
    "os"
    "strings"
    "testing"
)

func TestCrossPlatformClientRelease(t *testing.T) {
    if version != "7.6.0" {
        t.Fatalf("version = %q, want 7.6.0", version)
    }
}

func TestSharedMainHasNoWindowsBootstrap(t *testing.T) {
    body, err := os.ReadFile("main.go")
    if err != nil {
        t.Fatal(err)
    }
    text := string(body)
    for _, forbidden := range []string{"schtasks.exe", "ProgramFiles", "wg.exe", "filepath.Join"} {
        if strings.Contains(text, forbidden) {
            t.Fatalf("shared main.go still contains Windows-only bootstrap %q", forbidden)
        }
    }
}

func TestLinuxDeploymentPayloadExists(t *testing.T) {
    for _, path := range []string{
        "deploy/linux/install.sh",
        "deploy/linux/uninstall.sh",
        "deploy/linux/wireguard-p2p-client.service",
        "platform_linux.go",
        "console_linux.go",
    } {
        if _, err := os.Stat(path); err != nil {
            t.Fatalf("missing Linux client payload %s: %v", path, err)
        }
    }
}
''', encoding="utf-8")

# README rewritten around role-based deployment, not OS-specific client implementation.
(ROOT / "README.md").write_text(r'''# WireGuard P2P

当前生产实现：**v7.6.0**。协议仍为 7，VPS `10.0.0.0/24` relay 基线保持不变。

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
''', encoding="utf-8")

ops = ROOT / "p2p/wireguard-p2p/docs/operations.md"
ops.write_text(r'''# Operations

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
''', encoding="utf-8")

arch = ROOT / "p2p/wireguard-p2p/docs/architecture.md"
text = arch.read_text(encoding="utf-8")
text = text.replace("v7.5", "v7.6")
text += r'''

## Cross-platform clients

v7.6 将原 Windows-only Go 程序收敛为共享 client core。Windows 和 Linux 复用相同的 `/connect`、Candidate 排序、probe、fresh-handshake promotion、Direct health 和 Relay fallback；系统差异只存在于 platform/console 文件。Linux amd64 与 arm64 由同一源码交叉编译。

普通 Linux client 的角色与 Windows client 相同，不运行 `.2/.5` 的 Python Server Agent。Linux Server Agent 仍只负责被连接的 server 节点和 VPS `/offer` 接收。
'''
arch.write_text(text, encoding="utf-8")

# Current Python tests pin aligned release versions.
for p in (ROOT / "p2p/wireguard-p2p/tests").glob("test_*.py"):
    text = p.read_text(encoding="utf-8")
    text = text.replace("7.5.0", "7.6.0")
    p.write_text(text, encoding="utf-8")

print("v7.6 cross-platform client patch applied")
