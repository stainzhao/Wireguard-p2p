//go:build windows

package main

import (
	"fmt"
	"time"
)

// v7.15.0 used a one-second Win32 timer that called refreshUI even when
// nothing visible had changed. refreshUI rewrites the log EDIT control and
// invalidates the whole top-level window, which creates a very noticeable
// periodic flash on some Windows systems.
//
// Disable that unconditional timer after the window is ready. A lightweight
// snapshot watcher remains as a safety net for peer-state changes that do not
// emit a log line; it only asks the UI thread to repaint when the rendered
// state actually changes.
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

		last := guiViewFingerprint(windowsGUI.buildView())
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-windowsGUI.exit:
				return
			case <-ticker.C:
				view := windowsGUI.buildView()
				fingerprint := guiViewFingerprint(view)
				if fingerprint == last {
					continue
				}
				last = fingerprint
				windowsGUI.post(wmGUIRefresh)
			}
		}
	}()
}

func guiViewFingerprint(view guiView) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%t\x00%t\x00%v",
		view.Status, view.Summary, view.Interface, view.StatusColor,
		view.Fatal, view.Stopping, view.Peers)
}
