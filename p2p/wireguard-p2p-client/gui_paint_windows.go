//go:build windows

package main

import (
	"fmt"
	"unsafe"
)

const srcCopy = 0x00CC0020

var (
	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procBitBlt                 = gdi32.NewProc("BitBlt")
)

func (g *guiState) paint(hwnd uintptr) {
	var ps paintStruct
	hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	if hdc == 0 {
		return
	}
	defer procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))

	view := g.buildView()
	var client rect
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&client)))
	width := int(client.right - client.left)
	height := int(client.bottom - client.top)
	if width <= 0 || height <= 0 {
		return
	}

	// Draw the complete frame off-screen, then copy it to the window in one
	// operation. Direct GDI painting exposes intermediate frames (background,
	// cards, then text) and was the second source of visible flashing in v7.15.0.
	memDC, _, _ := procCreateCompatibleDC.Call(hdc)
	if memDC == 0 {
		g.paintScene(hdc, view, client)
		return
	}
	defer procDeleteDC.Call(memDC)

	bitmap, _, _ := procCreateCompatibleBitmap.Call(hdc, uintptr(width), uintptr(height))
	if bitmap == 0 {
		g.paintScene(hdc, view, client)
		return
	}
	oldBitmap, _, _ := procSelectObject.Call(memDC, bitmap)
	g.paintScene(memDC, view, client)
	procBitBlt.Call(hdc, 0, 0, uintptr(width), uintptr(height), memDC, 0, 0, srcCopy)
	procSelectObject.Call(memDC, oldBitmap)
	procDeleteObject.Call(bitmap)
}

func (g *guiState) paintScene(hdc uintptr, view guiView, client rect) {
	bg := newBrush(rgb(248, 250, 252))
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&client)), bg)
	procDeleteObject.Call(bg)

	g.drawText(hdc, "WireGuard P2P", g.fontTitle, rgb(15, 23, 42), 28, 20, 430, 36, 0)
	g.drawText(hdc, "v"+version, g.fontSmall, rgb(100, 116, 139), 650, 25, 130, 26, 2)

	g.drawCard(hdc, 24, 70, 772, 92)
	g.drawStatusDot(hdc, 44, 98, view.StatusColor)
	g.drawText(hdc, view.Status, g.fontStatus, rgb(15, 23, 42), 68, 84, 430, 34, 0)
	g.drawText(hdc, view.Summary, g.fontBody, rgb(71, 85, 105), 68, 118, 650, 26, 0)
	iface := view.Interface
	if iface == "" {
		iface = "等待检测"
	}
	g.drawText(hdc, "WireGuard · "+iface, g.fontSmall, rgb(100, 116, 139), 590, 86, 170, 24, 2)

	g.drawText(hdc, "设备连接", g.fontBody, rgb(15, 23, 42), 28, 180, 200, 28, 0)
	g.drawCard(hdc, 24, 212, 772, 230)
	g.drawText(hdc, "设备", g.fontSmall, rgb(100, 116, 139), 44, 224, 180, 24, 0)
	g.drawText(hdc, "连接方式", g.fontSmall, rgb(100, 116, 139), 250, 224, 180, 24, 0)
	g.drawText(hdc, "路径 / 状态", g.fontSmall, rgb(100, 116, 139), 465, 224, 280, 24, 0)

	if len(view.Peers) == 0 {
		g.drawText(hdc, "暂无远端设备，程序会在后台自动发现并建立连接。", g.fontBody, rgb(100, 116, 139), 44, 275, 690, 32, 0)
	} else {
		limit := len(view.Peers)
		if limit > 7 {
			limit = 7
		}
		for i := 0; i < limit; i++ {
			peer := view.Peers[i]
			y := 254 + i*27
			if i > 0 {
				g.drawSeparator(hdc, 44, y-3, 728)
			}
			g.drawText(hdc, peer.IP, g.fontBody, rgb(30, 41, 59), 44, y, 180, 24, 0)
			modeColor := rgb(71, 85, 105)
			if peer.Direct {
				modeColor = rgb(22, 163, 74)
			} else if peer.Busy {
				modeColor = rgb(37, 99, 235)
			}
			g.drawText(hdc, peer.Mode, g.fontBody, modeColor, 250, y, 190, 24, 0)
			g.drawText(hdc, peer.Detail, g.fontBody, rgb(71, 85, 105), 465, y, 280, 24, 0)
		}
		if len(view.Peers) > limit {
			g.drawText(hdc, fmt.Sprintf("另有 %d 个设备", len(view.Peers)-limit), g.fontSmall, rgb(100, 116, 139), 44, 254+limit*27, 300, 22, 0)
		}
	}

	g.drawText(hdc, "运行日志", g.fontBody, rgb(15, 23, 42), 28, 452, 200, 28, 0)
	g.drawCard(hdc, 24, 468, 772, 146)
	g.drawText(hdc, "关闭窗口后程序会继续在系统托盘运行", g.fontSmall, rgb(100, 116, 139), 28, 634, 420, 28, 0)
}

func (g *guiState) drawCard(hdc uintptr, x, y, width, height int) {
	brush := newBrush(rgb(255, 255, 255))
	pen, _, _ := procCreatePen.Call(psSolid, uintptr(g.px(1)), uintptr(rgb(226, 232, 240)))
	oldBrush, _, _ := procSelectObject.Call(hdc, brush)
	oldPen, _, _ := procSelectObject.Call(hdc, pen)
	procRoundRect.Call(hdc, uintptr(g.px(x)), uintptr(g.px(y)), uintptr(g.px(x+width)), uintptr(g.px(y+height)), uintptr(g.px(14)), uintptr(g.px(14)))
	procSelectObject.Call(hdc, oldBrush)
	procSelectObject.Call(hdc, oldPen)
	procDeleteObject.Call(brush)
	procDeleteObject.Call(pen)
}

func (g *guiState) drawSeparator(hdc uintptr, x, y, width int) {
	brush := newBrush(rgb(241, 245, 249))
	pen, _, _ := procCreatePen.Call(psSolid, uintptr(g.px(1)), uintptr(rgb(241, 245, 249)))
	oldBrush, _, _ := procSelectObject.Call(hdc, brush)
	oldPen, _, _ := procSelectObject.Call(hdc, pen)
	procRoundRect.Call(hdc, uintptr(g.px(x)), uintptr(g.px(y)), uintptr(g.px(x+width)), uintptr(g.px(y+1)), 0, 0)
	procSelectObject.Call(hdc, oldBrush)
	procSelectObject.Call(hdc, oldPen)
	procDeleteObject.Call(brush)
	procDeleteObject.Call(pen)
}

func (g *guiState) drawStatusDot(hdc uintptr, x, y int, color uint32) {
	brush := newBrush(color)
	pen, _, _ := procCreatePen.Call(psSolid, 0, uintptr(color))
	oldBrush, _, _ := procSelectObject.Call(hdc, brush)
	oldPen, _, _ := procSelectObject.Call(hdc, pen)
	procEllipse.Call(hdc, uintptr(g.px(x)), uintptr(g.px(y)), uintptr(g.px(x+12)), uintptr(g.px(y+12)))
	procSelectObject.Call(hdc, oldBrush)
	procSelectObject.Call(hdc, oldPen)
	procDeleteObject.Call(brush)
	procDeleteObject.Call(pen)
}

func (g *guiState) drawText(hdc uintptr, text string, font uintptr, color uint32, x, y, width, height int, align uint32) {
	oldFont, _, _ := procSelectObject.Call(hdc, font)
	procSetTextColor.Call(hdc, uintptr(color))
	procSetBkMode.Call(hdc, transparent)
	r := rect{int32(g.px(x)), int32(g.px(y)), int32(g.px(x + width)), int32(g.px(y + height))}
	flags := uintptr(0x20 | 0x4 | 0x8000 | align)
	ptr := utf16Ptr(text)
	procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(ptr)), ^uintptr(0), uintptr(unsafe.Pointer(&r)), flags)
	procSelectObject.Call(hdc, oldFont)
}

func (g *guiState) drawButton(dis *drawItemStruct) bool {
	if dis == nil || (dis.ctlID != idHide && dis.ctlID != idStop) {
		return false
	}
	isStop := dis.ctlID == idStop
	disabled := dis.itemState&odDisabled != 0
	selected := dis.itemState&odSelected != 0
	fill := rgb(255, 255, 255)
	border := rgb(203, 213, 225)
	text := rgb(51, 65, 85)
	if isStop {
		fill = rgb(239, 68, 68)
		border = rgb(239, 68, 68)
		text = rgb(255, 255, 255)
	}
	if selected {
		if isStop {
			fill = rgb(220, 38, 38)
			border = fill
		} else {
			fill = rgb(241, 245, 249)
		}
	}
	if disabled {
		fill = rgb(241, 245, 249)
		border = rgb(226, 232, 240)
		text = rgb(148, 163, 184)
	}
	brush := newBrush(fill)
	pen, _, _ := procCreatePen.Call(psSolid, uintptr(g.px(1)), uintptr(border))
	oldBrush, _, _ := procSelectObject.Call(dis.hdc, brush)
	oldPen, _, _ := procSelectObject.Call(dis.hdc, pen)
	procRoundRect.Call(dis.hdc, uintptr(dis.rcItem.left), uintptr(dis.rcItem.top), uintptr(dis.rcItem.right), uintptr(dis.rcItem.bottom), uintptr(g.px(10)), uintptr(g.px(10)))
	procSelectObject.Call(dis.hdc, oldBrush)
	procSelectObject.Call(dis.hdc, oldPen)
	procDeleteObject.Call(brush)
	procDeleteObject.Call(pen)

	label := "隐藏到后台"
	if isStop {
		label = g.stopButtonLabel()
	}
	oldFont, _, _ := procSelectObject.Call(dis.hdc, g.fontButton)
	procSetTextColor.Call(dis.hdc, uintptr(text))
	procSetBkMode.Call(dis.hdc, transparent)
	ptr := utf16Ptr(label)
	procDrawTextW.Call(dis.hdc, uintptr(unsafe.Pointer(ptr)), ^uintptr(0), uintptr(unsafe.Pointer(&dis.rcItem)), uintptr(0x1|0x4|0x20))
	procSelectObject.Call(dis.hdc, oldFont)
	return true
}

func (g *guiState) stopButtonLabel() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fatal {
		return "关闭"
	}
	if g.stopping {
		return "正在退出…"
	}
	return "安全退出"
}
