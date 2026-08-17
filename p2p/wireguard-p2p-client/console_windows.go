//go:build windows

package main

import (
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var instanceMutex uintptr
var updateStopEvent uintptr
var singleInstanceConflict bool

func acquireSingleInstance() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createMutex := kernel32.NewProc("CreateMutexW")
	closeHandle := kernel32.NewProc("CloseHandle")
	name, _ := syscall.UTF16PtrFromString("Global\\WireGuardP2PExe")
	handle, _, callErr := createMutex.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if handle == 0 {
		return false
	}
	if callErr == syscall.ERROR_ALREADY_EXISTS {
		singleInstanceConflict = true
		closeHandle.Call(handle)
		showExistingWindowsGUI()
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
	createEvent := kernel32.NewProc("CreateEventW")
	waitForSingleObject := kernel32.NewProc("WaitForSingleObject")
	eventName, _ := syscall.UTF16PtrFromString("Global\\WireGuardP2PUpdateStop")
	if handle, _, _ := createEvent.Call(0, 1, 0, uintptr(unsafe.Pointer(eventName))); handle != 0 {
		updateStopEvent = handle
		go func() {
			waitForSingleObject.Call(handle, 0xFFFFFFFF)
			once.Do(func() { close(shutdown) })
		}()
	}
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

func requestRunningInstanceStop() error {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	openEvent := kernel32.NewProc("OpenEventW")
	setEvent := kernel32.NewProc("SetEvent")
	closeHandle := kernel32.NewProc("CloseHandle")
	eventName, _ := syscall.UTF16PtrFromString("Global\\WireGuardP2PUpdateStop")
	handle, _, _ := openEvent.Call(0x0002, 0, uintptr(unsafe.Pointer(eventName)))
	if handle == 0 {
		return nil
	}
	defer closeHandle.Call(handle)
	result, _, callErr := setEvent.Call(handle)
	if result == 0 {
		return callErr
	}
	return nil
}
