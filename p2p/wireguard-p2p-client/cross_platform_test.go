package main

import (
	"os"
	"strings"
	"testing"
)

func TestCrossPlatformClientRelease(t *testing.T) {
	if version != "7.13.0" {
		t.Fatalf("version = %q, want 7.13.0", version)
	}
}

func TestSharedMainHasNoWindowsBootstrap(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, forbidden := range []string{"schtasks.exe", "ProgramFiles", "wg.exe", "filepath.Join"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("shared main.go still contains Windows-only bootstrap %q", forbidden)
		}
	}
}

func TestLinuxDeploymentPayloadExists(t *testing.T) {
	for _, path := range []string{
		"deploy/linux/install.sh",
		"deploy/linux/uninstall.sh",
		"deploy/linux/wireguard-p2p-client.service",
		"platform_linux.go",
		"console_linux.go",
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing Linux client payload %s: %v", path, err)
		}
	}
}
