//go:build !windows && !linux

package main

import (
	"errors"
	"os/exec"
	"runtime"
)

func resolveWGExecutable() (string, error) {
	candidate, err := exec.LookPath("wg")
	if err != nil {
		return "", errors.New("wg was not found in PATH")
	}
	return candidate, nil
}

func configurePlatformCommand(cmd *exec.Cmd) {}
func legacyClientConflict() error            { return nil }
func platformPauseOnFatal()                  {}
func platformLabel() string                  { return runtime.GOOS }
