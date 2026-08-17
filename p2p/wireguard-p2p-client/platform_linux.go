//go:build linux

package main

import (
	"errors"
	"os/exec"
)

func resolveWGExecutable() (string, error) {
	candidate, err := exec.LookPath("wg")
	if err != nil {
		return "", errors.New("wg was not found in PATH; install wireguard-tools first")
	}
	return candidate, nil
}

func configurePlatformCommand(cmd *exec.Cmd) {}
func legacyClientConflict() error            { return nil }
func platformPauseOnFatal()                  {}
func platformLabel() string                  { return "Linux" }
func platformClientStarted(a *app)           {}
func platformClientStopped()                 {}
