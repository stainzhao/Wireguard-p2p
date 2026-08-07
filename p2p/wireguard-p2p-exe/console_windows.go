//go:build windows

package main

import (
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var instanceMutex uintptr

func acquireSingleInstance() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createMutex := kernel32.NewProc("CreateMutexW")
	name, _ := syscall.UTF16PtrFromString("Global\\WireGuardP2PExe")
	handle, _, callErr := createMutex.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if handle == 0 || callErr == syscall.ERROR_ALREADY_EXISTS {
		return false
	}
	instanceMutex = handle
	return true
}

func installConsoleCloseHandler() (<-chan struct{}, chan struct{}) {
	shutdown := make(chan struct{})
	cleanupDone := make(chan struct{})
	var once sync.Once

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setHandler := kernel32.NewProc("SetConsoleCtrlHandler")
	callback := syscall.NewCallback(func(controlType uint) uintptr {
		switch controlType {
		case 0, 1, 2, 5, 6: // Ctrl+C, Break, Close, Logoff, Shutdown
			once.Do(func() { close(shutdown) })
			select {
			case <-cleanupDone:
			case <-time.After(4 * time.Second):
			}
			return 1
		default:
			return 0
		}
	})
	_, _, _ = setHandler.Call(callback, 1)
	return shutdown, cleanupDone
}
