//go:build windows

package main

import (
	"bufio"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	wmDestroy     = 0x0002
	wmClose       = 0x0010
	wmCommand     = 0x0111
	wsOverlapped  = 0x00000000
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsMinimizeBox = 0x00020000
	wsVisible     = 0x10000000
	wsChild       = 0x40000000
	wsVScroll     = 0x00200000
	wsBorder      = 0x00800000
	esMultiline   = 0x0004
	esAutoVScroll = 0x0040
	esReadOnly    = 0x0800
	bsPushButton  = 0x00000000
	swShow        = 5
	emSetSel      = 0x00B1
	emReplaceSel  = 0x00C2
	idStop        = 1001
	colorWindow   = 5
	cwUseDefault  = ^uintptr(0x7fffffff)
)

type guiState struct {
	mu          sync.Mutex
	window      uintptr
	statusLabel uintptr
	ifaceLabel  uintptr
	modeLabel   uintptr
	logEdit     uintptr
	status      string
	iface       string
	mode        string
	logs        []string
	exit        chan struct{}
	exitOnce    sync.Once
}

var windowsGUI = &guiState{
	status: "正在启动",
	iface:  "接口：等待检测",
	mode:   "连接：VPS 中继可用，正在检测直连",
	exit:   make(chan struct{}),
}

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	kernel32GUI          = syscall.NewLazyDLL("kernel32.dll")
	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procUpdateWindow     = user32.NewProc("UpdateWindow")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procSetWindowTextW   = user32.NewProc("SetWindowTextW")
	procSendMessageW     = user32.NewProc("SendMessageW")
	procLoadCursorW      = user32.NewProc("LoadCursorW")
	procGetModuleHandleW = kernel32GUI.NewProc("GetModuleHandleW")
	procFreeConsole      = kernel32GUI.NewProc("FreeConsole")
)

type point struct {
	x int32
	y int32
}

type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

type wndClassEx struct {
	cbSize     uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   uintptr
	icon       uintptr
	cursor     uintptr
	background uintptr
	menuName   *uint16
	className  *uint16
	iconSmall  uintptr
}

func init() {
	if !windowsGUIRequested() {
		return
	}

	r, w, err := os.Pipe()
	if err == nil {
		os.Stdout = w
		os.Stderr = w
		go consumeWindowsGUILogs(r)
	}

	// Detach from a parent console instead of hiding it. This keeps terminal
	// windows intact when the EXE is launched from PowerShell or cmd.exe.
	procFreeConsole.Call()
	go runWindowsGUI()
}

func windowsGUIRequested() bool {
	if len(os.Args) <= 1 {
		return true
	}
	switch os.Args[1] {
	case "version", "--version", "-version", "update":
		return false
	default:
		return true
	}
}

func consumeWindowsGUILogs(r *os.File) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		windowsGUI.consume(line)
	}
}

func (g *guiState) consume(line string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.logs = append(g.logs, line)
	if len(g.logs) > 300 {
		g.logs = append([]string(nil), g.logs[len(g.logs)-300:]...)
	}

	switch {
	case strings.Contains(line, "Using WireGuard interface:"):
		g.status = "运行中"
		parts := strings.SplitN(line, "Using WireGuard interface:", 2)
		if len(parts) == 2 {
			g.iface = "接口：" + strings.TrimSpace(parts[1])
		}
	case strings.Contains(line, "P2P OK"):
		g.status = "P2P 直连"
		g.mode = "连接：" + trimLogPrefix(line)
	case strings.Contains(line, "Fallback "):
		g.status = "VPS 中继"
		g.mode = "连接：" + trimLogPrefix(line)
	case strings.Contains(line, "WireGuard tunnel is inactive"):
		g.status = "WireGuard 未连接"
		g.iface = "接口：未检测到活动隧道"
		g.mode = "连接：等待 WireGuard"
	case strings.Contains(line, "Sync failed:"):
		g.status = "同步异常"
		g.mode = "连接：VPS fallback 保持可用"
	case strings.Contains(line, "Sync recovered"):
		g.status = "运行中"
	case strings.Contains(line, "Stopping:"):
		g.status = "正在停止"
	case strings.Contains(line, "Stopped."):
		g.status = "已停止"
	}

	g.refreshLocked()
}

func trimLogPrefix(line string) string {
	if idx := strings.Index(line, "] "); idx >= 0 {
		return line[idx+2:]
	}
	return line
}

func (g *guiState) refreshLocked() {
	if g.statusLabel != 0 {
		setWindowText(g.statusLabel, "状态："+g.status)
	}
	if g.ifaceLabel != 0 {
		setWindowText(g.ifaceLabel, g.iface)
	}
	if g.modeLabel != 0 {
		setWindowText(g.modeLabel, g.mode)
	}
	if g.logEdit != 0 {
		text := strings.Join(g.logs, "\r\n")
		setWindowText(g.logEdit, text)
		procSendMessageW.Call(g.logEdit, emSetSel, ^uintptr(0), ^uintptr(0))
	}
}

func runWindowsGUI() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	instance, _, _ := procGetModuleHandleW.Call(0)
	className := utf16Ptr("WireGuardP2PGUI")
	cursor, _, _ := procLoadCursorW.Call(0, 32512) // IDC_ARROW
	wc := wndClassEx{
		cbSize:     uint32(unsafe.Sizeof(wndClassEx{})),
		wndProc:    syscall.NewCallback(windowsGUIWndProc),
		instance:   instance,
		cursor:     cursor,
		background: colorWindow + 1,
		className:  className,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	style := uintptr(wsOverlapped | wsCaption | wsSysMenu | wsMinimizeBox | wsVisible)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(utf16Ptr("WireGuard P2P"))),
		style,
		cwUseDefault, cwUseDefault, 660, 500,
		0, 0, instance, 0,
	)
	if hwnd == 0 {
		return
	}

	windowsGUI.mu.Lock()
	windowsGUI.window = hwnd
	windowsGUI.statusLabel = createControl(hwnd, "STATIC", "状态：正在启动", 18, 18, 250, 24, 0, 0)
	createControl(hwnd, "STATIC", "WireGuard P2P v"+version, 430, 18, 190, 24, 0, 0)
	windowsGUI.ifaceLabel = createControl(hwnd, "STATIC", windowsGUI.iface, 18, 50, 590, 22, 0, 0)
	windowsGUI.modeLabel = createControl(hwnd, "STATIC", windowsGUI.mode, 18, 78, 590, 42, 0, 0)
	createControl(hwnd, "STATIC", "运行日志", 18, 126, 120, 22, 0, 0)
	windowsGUI.logEdit = createControl(hwnd, "EDIT", "", 18, 150, 604, 244,
		wsBorder|wsVScroll|esMultiline|esAutoVScroll|esReadOnly, 0)
	createControl(hwnd, "BUTTON", "安全停止并退出", 470, 410, 152, 32, bsPushButton, idStop)
	windowsGUI.refreshLocked()
	windowsGUI.mu.Unlock()

	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)

	var m msg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func windowsGUIWndProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	switch message {
	case wmCommand:
		if wParam&0xffff == idStop {
			windowsGUI.requestStop()
			return 0
		}
	case wmClose:
		windowsGUI.requestStop()
		return 0
	case wmDestroy:
		windowsGUI.exitOnce.Do(func() { close(windowsGUI.exit) })
		procPostQuitMessage.Call(0)
		return 0
	}
	result, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
	return result
}

func (g *guiState) requestStop() {
	g.mu.Lock()
	if g.statusLabel != 0 {
		setWindowText(g.statusLabel, "状态：正在安全停止")
	}
	hwnd := g.window
	g.mu.Unlock()

	_ = requestRunningInstanceStop()
	if hwnd != 0 {
		procDestroyWindow.Call(hwnd)
	}
}

func createControl(parent uintptr, class, text string, x, y, width, height int, extraStyle uintptr, id uintptr) uintptr {
	style := uintptr(wsChild|wsVisible) | extraStyle
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(utf16Ptr(class))),
		uintptr(unsafe.Pointer(utf16Ptr(text))),
		style,
		uintptr(x), uintptr(y), uintptr(width), uintptr(height),
		parent, id, 0, 0,
	)
	return hwnd
}

func setWindowText(hwnd uintptr, text string) {
	ptr := utf16Ptr(text)
	procSetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(ptr)))
}

func utf16Ptr(value string) *uint16 {
	ptr, _ := syscall.UTF16PtrFromString(value)
	return ptr
}

func waitWindowsGUIOnFatal() {
	if !windowsGUIRequested() {
		return
	}
	windowsGUI.mu.Lock()
	windowsGUI.status = "启动失败"
	windowsGUI.mode = "请查看下方日志后关闭窗口"
	windowsGUI.refreshLocked()
	windowsGUI.mu.Unlock()
	<-windowsGUI.exit
}
