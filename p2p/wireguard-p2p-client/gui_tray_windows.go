//go:build windows

package main

import (
	"strings"
	"unsafe"
)

func (g *guiState) requestStop() {
	g.mu.Lock()
	fatal := g.fatal
	if !fatal {
		if g.stopping {
			g.mu.Unlock()
			return
		}
		g.stopping = true
		g.health = "stopping"
	}
	hwnd := g.window
	g.mu.Unlock()

	if fatal {
		if hwnd != 0 {
			procDestroyWindow.Call(hwnd)
		}
		return
	}
	g.refreshUI()
	_ = requestRunningInstanceStop()
}

func (g *guiState) hideToTray(notify bool) {
	g.mu.Lock()
	if g.fatal || g.stopping {
		g.mu.Unlock()
		return
	}
	hwnd := g.window
	showNotice := notify && !g.trayNoticeShown
	if showNotice {
		g.trayNoticeShown = true
	}
	g.mu.Unlock()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, swHide)
	}
	if showNotice {
		g.showTrayNotice()
	}
}

func (g *guiState) showWindow() {
	g.mu.Lock()
	hwnd := g.window
	g.mu.Unlock()
	if hwnd == 0 {
		return
	}
	procShowWindow.Call(hwnd, swRestore)
	procShowWindow.Call(hwnd, swShow)
	procSetForegroundWindow.Call(hwnd)
	procUpdateWindow.Call(hwnd)
}

func (g *guiState) isFatal() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fatal
}

func showExistingWindowsGUI() {
	className := utf16Ptr("WireGuardP2PGUI")
	hwnd, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(className)), 0)
	if hwnd != 0 {
		procShowWindow.Call(hwnd, swRestore)
		procShowWindow.Call(hwnd, swShow)
		procSetForegroundWindow.Call(hwnd)
		return
	}
	procMessageBoxW.Call(0,
		uintptr(unsafe.Pointer(utf16Ptr("WireGuard P2P 已在后台运行。请从系统托盘打开现有窗口。"))),
		uintptr(unsafe.Pointer(utf16Ptr("WireGuard P2P"))),
		0x40)
}

func (g *guiState) handleTray(mouseMessage uint32) {
	switch mouseMessage {
	case wmLButtonUp, wmLButtonDblClk:
		g.showWindow()
	case wmRButtonUp:
		menu, _, _ := procCreatePopupMenu.Call()
		if menu == 0 {
			return
		}
		defer procDestroyMenu.Call(menu)
		procAppendMenuW.Call(menu, mfString, trayShow, uintptr(unsafe.Pointer(utf16Ptr("显示窗口"))))
		procAppendMenuW.Call(menu, mfSeparator, 0, 0)
		procAppendMenuW.Call(menu, mfString, trayExit, uintptr(unsafe.Pointer(utf16Ptr("安全退出"))))
		var pt point
		procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
		g.mu.Lock()
		hwnd := g.window
		g.mu.Unlock()
		procSetForegroundWindow.Call(hwnd)
		command, _, _ := procTrackPopupMenu.Call(menu, tpmRightButton|tpmReturnCmd, uintptr(pt.x), uintptr(pt.y), 0, hwnd, 0)
		switch command {
		case trayShow:
			g.showWindow()
		case trayExit:
			g.requestStop()
		}
	}
}

func (g *guiState) addTrayIcon() {
	g.mu.Lock()
	if g.trayAdded || g.window == 0 {
		g.mu.Unlock()
		return
	}
	nid := notifyIconData{cbSize: uint32(unsafe.Sizeof(notifyIconData{})), hwnd: g.window, uID: 1, uFlags: nifMessage | nifIcon | nifTip, uCallbackMessage: wmTray, hIcon: g.icon}
	copyUTF16(nid.szTip[:], "WireGuard P2P")
	g.mu.Unlock()
	result, _, _ := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
	if result != 0 {
		g.mu.Lock()
		g.trayAdded = true
		g.mu.Unlock()
	}
}

func (g *guiState) removeTrayIcon() {
	g.mu.Lock()
	if !g.trayAdded || g.window == 0 {
		g.mu.Unlock()
		return
	}
	nid := notifyIconData{cbSize: uint32(unsafe.Sizeof(notifyIconData{})), hwnd: g.window, uID: 1}
	g.trayAdded = false
	g.mu.Unlock()
	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
}

func (g *guiState) updateTrayTip(status string) {
	g.mu.Lock()
	if !g.trayAdded || g.window == 0 || status == g.lastTrayTip {
		g.mu.Unlock()
		return
	}
	g.lastTrayTip = status
	nid := notifyIconData{cbSize: uint32(unsafe.Sizeof(notifyIconData{})), hwnd: g.window, uID: 1, uFlags: nifTip}
	copyUTF16(nid.szTip[:], "WireGuard P2P · "+status)
	g.mu.Unlock()
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

func (g *guiState) showTrayNotice() {
	g.mu.Lock()
	if !g.trayAdded || g.window == 0 {
		g.mu.Unlock()
		return
	}
	nid := notifyIconData{cbSize: uint32(unsafe.Sizeof(notifyIconData{})), hwnd: g.window, uID: 1, uFlags: nifInfo, dwInfoFlags: niifInfo}
	copyUTF16(nid.szInfoTitle[:], "WireGuard P2P 仍在运行")
	copyUTF16(nid.szInfo[:], "窗口已隐藏到系统托盘，P2P 连接不会中断。点击托盘图标可恢复窗口。")
	g.mu.Unlock()
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

func waitWindowsGUIOnFatal() {
	if !windowsGUIRequested() || singleInstanceConflict {
		return
	}
	windowsGUI.mu.Lock()
	windowsGUI.fatal = true
	windowsGUI.health = "fatal"
	windowsGUI.fatalMessage = lastNonEmptyLog(windowsGUI.logs)
	if windowsGUI.fatalMessage == "" {
		windowsGUI.fatalMessage = "程序无法完成启动，请查看运行日志。"
	}
	windowsGUI.mu.Unlock()
	ensureWindowsGUIStarted()
	windowsGUI.post(wmGUIShow)
	windowsGUI.post(wmGUIRefresh)
	<-windowsGUI.exit
}

func lastNonEmptyLog(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return trimLogPrefix(line)
		}
	}
	return ""
}

func trimLogPrefix(line string) string {
	if idx := strings.Index(line, "] "); idx >= 0 {
		return line[idx+2:]
	}
	return line
}
