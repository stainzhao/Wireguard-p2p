//go:build windows

package main

import (
	"bufio"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

const (
	wmDestroy        = 0x0002
	wmSize           = 0x0005
	wmPaint          = 0x000F
	wmClose          = 0x0010
	wmCommand        = 0x0111
	wmTimer          = 0x0113
	wmCtlColorEdit   = 0x0133
	wmCtlColorStatic = 0x0138
	wmEraseBkgnd     = 0x0014
	wmDrawItem       = 0x002B
	wmLButtonUp      = 0x0202
	wmLButtonDblClk  = 0x0203
	wmRButtonUp      = 0x0205
	wmApp            = 0x8000
	wmGUIRefresh     = wmApp + 1
	wmGUIShow        = wmApp + 2
	wmGUIExit        = wmApp + 3
	wmTray           = wmApp + 4

	wsOverlapped  = 0x00000000
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsMinimizeBox = 0x00020000
	wsVisible     = 0x10000000
	wsChild       = 0x40000000
	wsVScroll     = 0x00200000

	esMultiline   = 0x0004
	esAutoVScroll = 0x0040
	esReadOnly    = 0x0800
	bsOwnerDraw   = 0x0000000B

	swHide    = 0
	swShow    = 5
	swRestore = 9

	emSetSel      = 0x00B1
	emScrollCaret = 0x00B7
	wmSetFont     = 0x0030

	idHide = 1001
	idStop = 1002

	colorWindow  = 5
	cwUseDefault = ^uintptr(0x7fffffff)

	odSelected = 0x0001
	odDisabled = 0x0004

	nimAdd     = 0x00000000
	nimModify  = 0x00000001
	nimDelete  = 0x00000002
	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004
	nifInfo    = 0x00000010
	niifInfo   = 0x00000001

	mfString       = 0x00000000
	mfSeparator    = 0x00000800
	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100

	trayShow = 2001
	trayExit = 2002

	transparent = 1
	psSolid     = 0
)

type guiState struct {
	mu              sync.Mutex
	window          uintptr
	logEdit         uintptr
	hideButton      uintptr
	stopButton      uintptr
	app             *app
	health          string
	iface           string
	fatalMessage    string
	logs            []string
	fatal           bool
	stopping        bool
	startOnce       sync.Once
	ready           chan struct{}
	readyOnce       sync.Once
	exit            chan struct{}
	exitOnce        sync.Once
	trayAdded       bool
	trayNoticeShown bool
	lastTrayTip     string
	dpi             int
	fontTitle       uintptr
	fontStatus      uintptr
	fontBody        uintptr
	fontSmall       uintptr
	fontButton      uintptr
	icon            uintptr
	whiteBrush      uintptr
}

var windowsGUI = &guiState{
	health: "starting",
	iface:  "等待检测",
	ready:  make(chan struct{}),
	exit:   make(chan struct{}),
	dpi:    96,
}

var (
	user32                  = syscall.NewLazyDLL("user32.dll")
	gdi32                   = syscall.NewLazyDLL("gdi32.dll")
	kernel32GUI             = syscall.NewLazyDLL("kernel32.dll")
	shell32                 = syscall.NewLazyDLL("shell32.dll")
	procRegisterClassExW    = user32.NewProc("RegisterClassExW")
	procCreateWindowExW     = user32.NewProc("CreateWindowExW")
	procDefWindowProcW      = user32.NewProc("DefWindowProcW")
	procShowWindow          = user32.NewProc("ShowWindow")
	procUpdateWindow        = user32.NewProc("UpdateWindow")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessageW    = user32.NewProc("DispatchMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procSetWindowTextW      = user32.NewProc("SetWindowTextW")
	procSendMessageW        = user32.NewProc("SendMessageW")
	procPostMessageW        = user32.NewProc("PostMessageW")
	procLoadCursorW         = user32.NewProc("LoadCursorW")
	procLoadIconW           = user32.NewProc("LoadIconW")
	procFindWindowW         = user32.NewProc("FindWindowW")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procMessageBoxW         = user32.NewProc("MessageBoxW")
	procEnableWindow        = user32.NewProc("EnableWindow")
	procSetTimer            = user32.NewProc("SetTimer")
	procKillTimer           = user32.NewProc("KillTimer")
	procInvalidateRect      = user32.NewProc("InvalidateRect")
	procBeginPaint          = user32.NewProc("BeginPaint")
	procEndPaint            = user32.NewProc("EndPaint")
	procFillRect            = user32.NewProc("FillRect")
	procDrawTextW           = user32.NewProc("DrawTextW")
	procGetClientRect       = user32.NewProc("GetClientRect")
	procCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	procAppendMenuW         = user32.NewProc("AppendMenuW")
	procTrackPopupMenu      = user32.NewProc("TrackPopupMenu")
	procDestroyMenu         = user32.NewProc("DestroyMenu")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procGetModuleHandleW    = kernel32GUI.NewProc("GetModuleHandleW")
	procGetDpiForSystem     = user32.NewProc("GetDpiForSystem")
	procAttachConsole       = kernel32GUI.NewProc("AttachConsole")
	procShellNotifyIconW    = shell32.NewProc("Shell_NotifyIconW")
	procCreateFontW         = gdi32.NewProc("CreateFontW")
	procCreateSolidBrush    = gdi32.NewProc("CreateSolidBrush")
	procCreatePen           = gdi32.NewProc("CreatePen")
	procSelectObject        = gdi32.NewProc("SelectObject")
	procDeleteObject        = gdi32.NewProc("DeleteObject")
	procSetTextColor        = gdi32.NewProc("SetTextColor")
	procSetBkMode           = gdi32.NewProc("SetBkMode")
	procRoundRect           = gdi32.NewProc("RoundRect")
	procEllipse             = gdi32.NewProc("Ellipse")
)

type point struct {
	x int32
	y int32
}

type rect struct {
	left   int32
	top    int32
	right  int32
	bottom int32
}

type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

type paintStruct struct {
	hdc         uintptr
	erase       int32
	rcPaint     rect
	restore     int32
	incUpdate   int32
	rgbReserved [32]byte
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

type drawItemStruct struct {
	ctlType    uint32
	ctlID      uint32
	itemID     uint32
	itemAction uint32
	itemState  uint32
	hwndItem   uintptr
	hdc        uintptr
	rcItem     rect
	itemData   uintptr
}

type notifyIconData struct {
	cbSize           uint32
	hwnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     uintptr
}

func init() {
	if !windowsGUIRequested() {
		attachParentConsoleForCLI()
		return
	}

	r, w, err := os.Pipe()
	if err == nil {
		os.Stdout = w
		os.Stderr = w
		go consumeWindowsGUILogs(r)
	}
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

func attachParentConsoleForCLI() {
	const attachParentProcess = 0xFFFFFFFF
	procAttachConsole.Call(uintptr(uint32(attachParentProcess)))
	if out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = out
		os.Stderr = out
	}
	if in, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = in
	}
}

func consumeWindowsGUILogs(r *os.File) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		windowsGUI.consume(scanner.Text())
	}
}

func ensureWindowsGUIStarted() {
	windowsGUI.startOnce.Do(func() { go runWindowsGUI() })
	<-windowsGUI.ready
}

func platformClientStarted(a *app) {
	if !windowsGUIRequested() {
		return
	}
	windowsGUI.mu.Lock()
	windowsGUI.app = a
	windowsGUI.health = "running"
	windowsGUI.mu.Unlock()
	ensureWindowsGUIStarted()
	windowsGUI.post(wmGUIShow)
}

func platformClientStopped() {
	if !windowsGUIRequested() {
		return
	}
	windowsGUI.post(wmGUIExit)
}

func (g *guiState) post(message uint32) {
	g.mu.Lock()
	hwnd := g.window
	g.mu.Unlock()
	if hwnd != 0 {
		procPostMessageW.Call(hwnd, uintptr(message), 0, 0)
	}
}

func runWindowsGUI() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if dpi, _, _ := procGetDpiForSystem.Call(); dpi >= 96 && dpi <= 384 {
		windowsGUI.dpi = int(dpi)
	}
	instance, _, _ := procGetModuleHandleW.Call(0)
	className := utf16Ptr("WireGuardP2PGUI")
	cursor, _, _ := procLoadCursorW.Call(0, 32512)
	icon, _, _ := procLoadIconW.Call(instance, 1)
	if icon == 0 {
		icon, _, _ = procLoadIconW.Call(0, 32512)
	}
	windowsGUI.icon = icon
	wc := wndClassEx{
		cbSize:     uint32(unsafe.Sizeof(wndClassEx{})),
		wndProc:    syscall.NewCallback(windowsGUIWndProc),
		instance:   instance,
		icon:       icon,
		cursor:     cursor,
		background: colorWindow + 1,
		className:  className,
		iconSmall:  icon,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	style := uintptr(wsOverlapped | wsCaption | wsSysMenu | wsMinimizeBox)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(utf16Ptr("WireGuard P2P"))),
		style,
		cwUseDefault, cwUseDefault,
		uintptr(windowsGUI.px(820)), uintptr(windowsGUI.px(740)),
		0, 0, instance, 0,
	)
	if hwnd == 0 {
		windowsGUI.readyOnce.Do(func() { close(windowsGUI.ready) })
		return
	}

	windowsGUI.initFonts()
	windowsGUI.mu.Lock()
	windowsGUI.window = hwnd
	windowsGUI.logEdit = createControl(hwnd, "EDIT", "", windowsGUI.px(36), windowsGUI.px(474), windowsGUI.px(748), windowsGUI.px(132),
		wsVScroll|esMultiline|esAutoVScroll|esReadOnly, 0, 0)
	windowsGUI.hideButton = createControl(hwnd, "BUTTON", "隐藏到后台", windowsGUI.px(558), windowsGUI.px(626), windowsGUI.px(108), windowsGUI.px(38), bsOwnerDraw, idHide, 0)
	windowsGUI.stopButton = createControl(hwnd, "BUTTON", "安全退出", windowsGUI.px(676), windowsGUI.px(626), windowsGUI.px(108), windowsGUI.px(38), bsOwnerDraw, idStop, 0)
	windowsGUI.mu.Unlock()

	applyFont(windowsGUI.logEdit, windowsGUI.fontSmall)
	applyFont(windowsGUI.hideButton, windowsGUI.fontButton)
	applyFont(windowsGUI.stopButton, windowsGUI.fontButton)
	windowsGUI.addTrayIcon()
	procSetTimer.Call(hwnd, 1, 1000, 0)
	windowsGUI.readyOnce.Do(func() { close(windowsGUI.ready) })
	windowsGUI.refreshUI()

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
		switch wParam & 0xffff {
		case idHide:
			windowsGUI.hideToTray(true)
			return 0
		case idStop:
			windowsGUI.requestStop()
			return 0
		}
	case wmClose:
		if windowsGUI.isFatal() {
			procDestroyWindow.Call(hwnd)
		} else {
			windowsGUI.hideToTray(true)
		}
		return 0
	case wmGUIRefresh, wmTimer:
		windowsGUI.refreshUI()
		return 0
	case wmGUIShow:
		windowsGUI.showWindow()
		return 0
	case wmGUIExit:
		procDestroyWindow.Call(hwnd)
		return 0
	case wmTray:
		windowsGUI.handleTray(uint32(lParam))
		return 0
	case wmPaint:
		windowsGUI.paint(hwnd)
		return 0
	case wmEraseBkgnd:
		return 1
	case wmDrawItem:
		if windowsGUI.drawButton((*drawItemStruct)(unsafe.Pointer(lParam))) {
			return 1
		}
	case wmCtlColorEdit:
		hdc := wParam
		procSetTextColor.Call(hdc, uintptr(rgb(51, 65, 85)))
		procSetBkMode.Call(hdc, transparent)
		return windowsGUI.whiteBrush
	case wmCtlColorStatic:
		if lParam == windowsGUI.logEdit {
			procSetTextColor.Call(wParam, uintptr(rgb(51, 65, 85)))
			procSetBkMode.Call(wParam, transparent)
			return windowsGUI.whiteBrush
		}
		procSetBkMode.Call(wParam, transparent)
		return 0
	case wmDestroy:
		procKillTimer.Call(hwnd, 1)
		windowsGUI.removeTrayIcon()
		windowsGUI.deleteFonts()
		windowsGUI.exitOnce.Do(func() { close(windowsGUI.exit) })
		procPostQuitMessage.Call(0)
		return 0
	case wmSize:
		return 0
	}
	result, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
	return result
}

func (g *guiState) refreshUI() {
	view := g.buildView()
	g.mu.Lock()
	logs := stringsJoinCRLF(g.logs)
	logEdit := g.logEdit
	hideButton := g.hideButton
	stopButton := g.stopButton
	hwnd := g.window
	g.mu.Unlock()

	if logEdit != 0 {
		setWindowText(logEdit, logs)
		procSendMessageW.Call(logEdit, emSetSel, ^uintptr(0), ^uintptr(0))
		procSendMessageW.Call(logEdit, emScrollCaret, 0, 0)
	}
	if stopButton != 0 {
		label := "安全退出"
		enabled := uintptr(1)
		if view.Fatal {
			label = "关闭"
		} else if view.Stopping {
			label = "正在退出…"
			enabled = 0
		}
		setWindowText(stopButton, label)
		procEnableWindow.Call(stopButton, enabled)
	}
	if hideButton != 0 {
		enabled := uintptr(1)
		if view.Fatal || view.Stopping {
			enabled = 0
		}
		procEnableWindow.Call(hideButton, enabled)
	}
	if hwnd != 0 {
		procInvalidateRect.Call(hwnd, 0, 0)
	}
	g.updateTrayTip(view.Status)
}

func stringsJoinCRLF(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	result := lines[0]
	for _, line := range lines[1:] {
		result += "\r\n" + line
	}
	return result
}

func (g *guiState) initFonts() {
	g.whiteBrush = newBrush(rgb(255, 255, 255))
	g.fontTitle = createFont(g.px(27), 600)
	g.fontStatus = createFont(g.px(19), 600)
	g.fontBody = createFont(g.px(14), 400)
	g.fontSmall = createFont(g.px(12), 400)
	g.fontButton = createFont(g.px(13), 500)
}

func (g *guiState) deleteFonts() {
	if g.whiteBrush != 0 {
		procDeleteObject.Call(g.whiteBrush)
		g.whiteBrush = 0
	}
	for _, font := range []uintptr{g.fontTitle, g.fontStatus, g.fontBody, g.fontSmall, g.fontButton} {
		if font != 0 {
			procDeleteObject.Call(font)
		}
	}
}

func createFont(height, weight int) uintptr {
	face := utf16Ptr("Segoe UI")
	font, _, _ := procCreateFontW.Call(
		uintptr(^uint32(height-1)), 0, 0, 0, uintptr(weight), 0, 0, 0,
		1, 0, 0, 5, 0, uintptr(unsafe.Pointer(face)),
	)
	return font
}

func applyFont(hwnd, font uintptr) {
	if hwnd != 0 && font != 0 {
		procSendMessageW.Call(hwnd, wmSetFont, font, 1)
	}
}

func createControl(parent uintptr, class, text string, x, y, width, height int, styleExtra uintptr, id uintptr, exStyle uintptr) uintptr {
	style := uintptr(wsChild|wsVisible) | styleExtra
	hwnd, _, _ := procCreateWindowExW.Call(
		exStyle,
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

func copyUTF16(dst []uint16, value string) {
	encoded, _ := syscall.UTF16FromString(value)
	if len(encoded) > len(dst) {
		encoded = encoded[:len(dst)]
		encoded[len(encoded)-1] = 0
	}
	copy(dst, encoded)
}

func newBrush(color uint32) uintptr {
	brush, _, _ := procCreateSolidBrush.Call(uintptr(color))
	return brush
}

func rgb(r, g, b uint32) uint32 {
	return r | g<<8 | b<<16
}

func (g *guiState) px(value int) int {
	if g.dpi <= 0 {
		return value
	}
	return value * g.dpi / 96
}
