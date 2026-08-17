//go:build windows

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func psQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func applyPlatformUpdate(payload []byte, targetVersion string) error {
	current, err := os.Executable()
	if err != nil {
		return err
	}
	current, _ = filepath.Abs(current)
	next := current + ".update-new"
	backup := current + ".update-backup"
	if err := os.WriteFile(next, payload, 0755); err != nil {
		return err
	}

	// Ask a separately running client instance to clean up dynamic peers and exit.
	_ = requestRunningInstanceStop()
	time.Sleep(500 * time.Millisecond)

	scriptPath := filepath.Join(os.TempDir(), fmt.Sprintf("wireguard-p2p-update-%d.ps1", os.Getpid()))
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$pidToWait = %d
$current = %s
$next = %s
$backup = %s
$deadline = (Get-Date).AddSeconds(15)
while (Get-Process -Id $pidToWait -ErrorAction SilentlyContinue) { Start-Sleep -Milliseconds 200 }
while ((Get-Process | Where-Object { $_.Path -eq $current }) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
Get-Process | Where-Object { $_.Path -eq $current } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
if (Test-Path $backup) { Remove-Item -Force $backup }
try {
    if (Test-Path $current) { Move-Item -Force $current $backup }
    Move-Item -Force $next $current
    Start-Process -FilePath $current
} catch {
    if (Test-Path $backup) { Move-Item -Force $backup $current }
    throw
}
Remove-Item -Force $MyInvocation.MyCommand.Path
`, os.Getpid(), psQuote(current), psQuote(next), psQuote(backup))
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		_ = os.Remove(next)
		return err
	}

	// Encode the path to avoid quoting surprises when spawning the detached helper.
	encodedPath := base64.StdEncoding.EncodeToString([]byte(scriptPath))
	commandText := fmt.Sprintf("$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s')); & $p", encodedPath)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", commandText)
	configurePlatformCommand(cmd)
	if err := cmd.Start(); err != nil {
		_ = os.Remove(next)
		_ = os.Remove(scriptPath)
		return errors.New("could not start Windows update helper: " + err.Error())
	}
	fmt.Printf("Update to %s is staged. This updater will exit; the client will replace itself and restart.\n", targetVersion)
	return nil
}
