//go:build windows

package main

import (
	"fmt"
	"sync"
)

var guiVisibleState struct {
	sync.Mutex
	fingerprint string
}

// v7.15.2 keeps the UI fully event driven. The legacy Win32 timer is disarmed
// as soon as the window exists; no ticker or periodic GUI watcher remains.
func init() {
	if !windowsGUIRequested() {
		return
	}
	go func() {
		<-windowsGUI.ready
		windowsGUI.mu.Lock()
		hwnd := windowsGUI.window
		windowsGUI.mu.Unlock()
		if hwnd == 0 {
			return
		}
		procKillTimer.Call(hwnd, 1)
		rememberGUIView(windowsGUI.buildView())
	}()
}

// platformClientStateChanged is called by backend events. It compares the
// state the user can actually see and invalidates the top-level scene only
// when that rendered state changed. Stable backend synchronization therefore
// causes no UI repaint.
func platformClientStateChanged(a *app) {
	if !windowsGUIRequested() {
		return
	}

	windowsGUI.mu.Lock()
	if windowsGUI.app == nil && a != nil {
		windowsGUI.app = a
	}
	hwnd := windowsGUI.window
	windowsGUI.mu.Unlock()
	if hwnd == 0 {
		return
	}

	view := windowsGUI.buildView()
	fingerprint := guiViewFingerprint(view)
	guiVisibleState.Lock()
	if fingerprint == guiVisibleState.fingerprint {
		guiVisibleState.Unlock()
		return
	}
	guiVisibleState.fingerprint = fingerprint
	guiVisibleState.Unlock()

	procInvalidateRect.Call(hwnd, 0, 0)
	windowsGUI.updateTrayTip(view.Status)
}

func rememberGUIView(view guiView) {
	guiVisibleState.Lock()
	guiVisibleState.fingerprint = guiViewFingerprint(view)
	guiVisibleState.Unlock()
}

func guiViewFingerprint(view guiView) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%t\x00%t\x00%v",
		view.Status, view.Summary, view.Interface, view.StatusColor,
		view.Fatal, view.Stopping, view.Peers)
}
