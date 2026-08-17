package main

import (
	"os"
	"strings"
	"testing"
)

func TestCrossPlatformClientRelease(t *testing.T) {
	if version != "7.14.1" {
		t.Fatalf("version = %q, want 7.14.1", version)
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
	if !strings.Contains(text, "configurePlatformCommand(cmd)") {
		t.Fatal("shared command execution is missing the platform window-suppression hook")
	}
}

func TestWindowsGUIRegressionGuards(t *testing.T) {
	gui, err := os.ReadFile("gui_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	guiText := string(gui)
	if !strings.Contains(guiText, "case wmClose:") || !strings.Contains(guiText, "procShowWindow.Call(hwnd, swMinimize)") {
		t.Fatal("Windows title-bar close must minimize instead of stopping the client")
	}

	platform, err := os.ReadFile("platform_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	platformText := string(platform)
	if !strings.Contains(platformText, "createNoWindow") || !strings.Contains(platformText, "HideWindow:    true") {
		t.Fatal("Windows child commands must run without visible console windows")
	}

	workflow, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(workflow), "-H=windowsgui") {
		t.Fatal("Windows release must use the GUI subsystem to avoid startup console flash")
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
