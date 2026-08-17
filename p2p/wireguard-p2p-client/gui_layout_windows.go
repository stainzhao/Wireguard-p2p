//go:build windows

package main

const (
	logTitleY      = 450
	logTitleHeight = 28
	logCardY       = 484
	logCardHeight  = 132
	logEditX       = 36
	logEditY       = 490
	logEditWidth   = 748
	logEditHeight  = 120

	swpNoZOrder   = 0x0004
	swpNoActivate = 0x0010
)

var procSetWindowPos = user32.NewProc("SetWindowPos")

func init() {
	if !windowsGUIRequested() {
		return
	}
	go func() {
		<-windowsGUI.ready
		windowsGUI.mu.Lock()
		logEdit := windowsGUI.logEdit
		windowsGUI.mu.Unlock()
		if logEdit == 0 {
			return
		}
		procSetWindowPos.Call(
			logEdit,
			0,
			uintptr(windowsGUI.px(logEditX)),
			uintptr(windowsGUI.px(logEditY)),
			uintptr(windowsGUI.px(logEditWidth)),
			uintptr(windowsGUI.px(logEditHeight)),
			swpNoZOrder|swpNoActivate,
		)
	}()
}
