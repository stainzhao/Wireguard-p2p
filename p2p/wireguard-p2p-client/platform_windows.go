//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const createNoWindow = 0x08000000

func resolveWGExecutable() (string, error) {
	if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
		candidate := filepath.Join(programFiles, "WireGuard", "wg.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	if candidate, err := exec.LookPath("wg.exe"); err == nil {
		return candidate, nil
	}
	return "", errors.New("WireGuard wg.exe was not found; install WireGuard for Windows first")
}

func configurePlatformCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
}

func legacyClientConflict() error {
	cmd := exec.Command("schtasks.exe", "/Query", "/TN", "WireGuard P2P Sync")
	configurePlatformCommand(cmd)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Run() == nil {
		return errors.New("old scheduled task 'WireGuard P2P Sync' still exists; remove it before starting the current client")
	}
	return nil
}

func platformPauseOnFatal() {
	if windowsGUIRequested() {
		waitWindowsGUIOnFatal()
		return
	}
	fmt.Println("Press Enter to close.")
	_, _ = fmt.Scanln()
}

func platformLabel() string { return "Windows" }
