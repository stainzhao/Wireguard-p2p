//go:build windows

package main

import (
	"fmt"
	"sort"
	"strings"
	"unsafe"
)

const (
	emGetLineCount = 0x00BA
	emLineIndex    = 0x00BB
	emReplaceSel   = 0x00C2
	wmGetTextLength = 0x000E
	maxGUILogLines = 300
)

type guiPeer struct {
	IP     string
	Mode   string
	Detail string
	Direct bool
	Busy   bool
}

type guiView struct {
	Status      string
	Summary     string
	Interface   string
	StatusColor uint32
	Peers       []guiPeer
	Fatal       bool
	Stopping    bool
}

func (g *guiState) consume(line string) {
	g.mu.Lock()
	wasStopping := g.stopping
	g.logs = append(g.logs, line)
	if len(g.logs) > maxGUILogLines {
		g.logs = append([]string(nil), g.logs[len(g.logs)-maxGUILogLines:]...)
	}

	switch {
	case strings.Contains(line, "Using WireGuard interface:"):
		g.health = "running"
		parts := strings.SplitN(line, "Using WireGuard interface:", 2)
		if len(parts) == 2 {
			g.iface = strings.TrimSpace(parts[1])
		}
	case strings.Contains(line, "WireGuard tunnel is inactive"):
		g.health = "wireguard-down"
		g.iface = "未检测到活动隧道"
	case strings.Contains(line, "Sync failed:"):
		g.health = "sync-error"
	case strings.Contains(line, "Sync recovered"):
		g.health = "running"
	case strings.Contains(line, "Stopping:"):
		g.health = "stopping"
		g.stopping = true
	case strings.Contains(line, "Stopped."):
		g.health = "stopped"
	}
	logEdit := g.logEdit
	a := g.app
	stoppingChanged := wasStopping != g.stopping
	g.mu.Unlock()

	// Logs are independent from the dashboard paint path. Append only the new
	// line instead of replacing the entire EDIT control on every message.
	if logEdit != 0 {
		appendGUILogLine(logEdit, line)
	}

	// The log may correspond to a real backend state transition (for example a
	// successful Direct promotion). The platform hook fingerprints the visible
	// state and repaints only if that state actually changed.
	platformClientStateChanged(a)

	// Only the explicit shutdown transition needs the owner-drawn controls to
	// change label/enabled state. This is rare and intentionally uses the full
	// control refresh path once.
	if stoppingChanged {
		g.post(wmGUIRefresh)
	}
}

func appendGUILogLine(hwnd uintptr, line string) {
	length, _, _ := procSendMessageW.Call(hwnd, wmGetTextLength, 0, 0)
	text := line
	if length > 0 {
		text = "\r\n" + line
	}
	procSendMessageW.Call(hwnd, emSetSel, ^uintptr(0), ^uintptr(0))
	ptr := utf16Ptr(text)
	procSendMessageW.Call(hwnd, emReplaceSel, 0, uintptr(unsafe.Pointer(ptr)))

	// Keep the visible control bounded without rebuilding all log text. Delete
	// only the oldest line once the rolling window exceeds maxGUILogLines.
	lineCount, _, _ := procSendMessageW.Call(hwnd, emGetLineCount, 0, 0)
	if lineCount > maxGUILogLines {
		secondLine, _, _ := procSendMessageW.Call(hwnd, emLineIndex, 1, 0)
		if secondLine > 0 && secondLine != ^uintptr(0) {
			procSendMessageW.Call(hwnd, emSetSel, 0, secondLine)
			empty := utf16Ptr("")
			procSendMessageW.Call(hwnd, emReplaceSel, 0, uintptr(unsafe.Pointer(empty)))
		}
	}
	procSendMessageW.Call(hwnd, emSetSel, ^uintptr(0), ^uintptr(0))
	procSendMessageW.Call(hwnd, emScrollCaret, 0, 0)
}

func (g *guiState) buildView() guiView {
	g.mu.Lock()
	health := g.health
	iface := g.iface
	fatal := g.fatal
	fatalMessage := g.fatalMessage
	stopping := g.stopping
	a := g.app
	g.mu.Unlock()

	view := guiView{
		Interface:   iface,
		Fatal:       fatal,
		Stopping:    stopping,
		StatusColor: rgb(37, 99, 235),
	}
	if fatal {
		view.Status = "启动失败"
		view.Summary = fatalMessage
		view.StatusColor = rgb(220, 38, 38)
		return view
	}
	if stopping || health == "stopping" || health == "stopped" {
		view.Status = "正在安全退出"
		view.Summary = "正在清理临时直连 Peer，并通知协调服务断开"
		view.StatusColor = rgb(100, 116, 139)
		return view
	}
	if health == "wireguard-down" {
		view.Status = "等待 WireGuard"
		view.Summary = "请先启用 WireGuard 隧道，程序会自动继续连接"
		view.StatusColor = rgb(217, 119, 6)
		return view
	}

	view.Peers = snapshotGUIPeers(a)
	direct, busy, relay := 0, 0, 0
	for _, peer := range view.Peers {
		switch {
		case peer.Direct:
			direct++
		case peer.Busy:
			busy++
		default:
			relay++
		}
	}
	if health == "sync-error" {
		view.Status = "协调服务暂不可用"
		view.Summary = "现有连接保持工作，程序会自动重试协调服务"
		view.StatusColor = rgb(217, 119, 6)
		return view
	}
	if len(view.Peers) == 0 {
		view.Status = "正在运行"
		view.Summary = "VPS 中继可用，等待可连接的远端设备"
		view.StatusColor = rgb(37, 99, 235)
		return view
	}
	if busy > 0 {
		view.Status = "正在优化连接"
		view.Summary = fmt.Sprintf("%d 个设备：%d 个 P2P 直连 · %d 个正在尝试 · %d 个 VPS 中继", len(view.Peers), direct, busy, relay)
		view.StatusColor = rgb(37, 99, 235)
		return view
	}
	view.Status = "已连接"
	if relay == 0 {
		view.Summary = fmt.Sprintf("%d 个设备 · 全部 P2P 直连", len(view.Peers))
	} else {
		view.Summary = fmt.Sprintf("%d 个设备：%d 个 P2P 直连 · %d 个 VPS 中继", len(view.Peers), direct, relay)
	}
	view.StatusColor = rgb(22, 163, 74)
	return view
}

func snapshotGUIPeers(a *app) []guiPeer {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	peers := make([]guiPeer, 0, len(a.serverKeys))
	for key, ip := range a.serverKeys {
		peer := guiPeer{IP: ip, Mode: "VPS 中继", Detail: "保持可用"}
		state := a.states[key]
		if state != nil {
			switch state.Mode {
			case "direct":
				peer.Mode = "P2P 直连"
				peer.Detail = friendlyCandidateType(state.SelectedType)
				peer.Direct = true
			case "probe":
				peer.Mode = "正在尝试直连"
				peer.Detail = friendlyCandidateType(state.SelectedType)
				peer.Busy = true
			case "passive6":
				peer.Mode = "等待 IPv6 直连"
				peer.Detail = "监听入站握手"
				peer.Busy = true
			case "idle":
				if state.RetryAfter > 0 {
					peer.Detail = "等待下一次直连尝试"
				}
			}
		}
		peers = append(peers, peer)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].IP < peers[j].IP })
	return peers
}

func friendlyCandidateType(value string) string {
	switch value {
	case "host6":
		return "IPv6 直连"
	case "reflexive6":
		return "IPv6 NAT 直连"
	case "observed6":
		return "IPv6 学习直连"
	case "observed4":
		return "IPv4 打洞"
	case "predicted4":
		return "IPv4 端口预测"
	case "lan":
		return "局域网直连"
	case "endpoint":
		return "公网端点直连"
	case "":
		return "正在检测最佳路径"
	default:
		return value
	}
}
