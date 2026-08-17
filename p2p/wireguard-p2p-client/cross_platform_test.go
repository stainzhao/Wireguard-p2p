package main

import (
	"os"
	"strings"
	"testing"
)

func TestCrossPlatformClientRelease(t *testing.T) {
	if version != "7.15.5" {
		t.Fatalf("version = %q, want 7.15.5", version)
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
	if !strings.Contains(text, "platformClientStarted(a)") || !strings.Contains(text, "defer platformClientStopped()") {
		t.Fatal("shared client lifecycle is not connected to platform UI lifecycle hooks")
	}
	if !strings.Contains(text, "platformClientStateChanged(a)") {
		t.Fatal("backend synchronization must emit a platform state-change event")
	}
}

func TestWindowsGUIHumanizedRegressionGuards(t *testing.T) {
	files := []string{"gui_windows.go", "gui_model_windows.go", "gui_paint_windows.go", "gui_tray_windows.go", "gui_events_windows.go", "gui_layout_windows.go"}
	combined := ""
	for _, path := range files {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		combined += string(body)
	}
	for _, required := range []string{
		"snapshotGUIPeers",
		"procPostMessageW",
		"hideToTray(true)",
		"showExistingWindowsGUI",
		"attachParentConsoleForCLI",
		"wmTray",
		"正在安全退出",
		"procKillTimer.Call(hwnd, 1)",
		"platformClientStateChanged",
		"guiViewFingerprint",
		"appendGUILogLine",
		"emReplaceSel",
		"procCreateCompatibleDC",
		"procCreateCompatibleBitmap",
		"procBitBlt.Call",
		"procSetWindowPos.Call",
		"logTitleY",
		"logCardY",
		"logEditY",
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Windows GUI is missing humanized/event-driven layout behavior %q", required)
		}
	}
	if strings.Contains(combined, "time.NewTicker") {
		t.Fatal("Windows GUI must not poll state with a ticker")
	}
	if strings.Contains(combined, "case wmClose:\n\t\twindowsGUI.requestStop()") {
		t.Fatal("title-bar close must not terminate the client")
	}

	layout, err := os.ReadFile("gui_layout_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	layoutText := string(layout)
	for _, required := range []string{
		"logTitleY      = 450",
		"logTitleHeight = 28",
		"logCardY       = 484",
		"logEditY       = 490",
		"logEditHeight  = 120",
	} {
		if !strings.Contains(layoutText, required) {
			t.Fatalf("Windows log layout regression guard missing %q", required)
		}
	}

	platform, err := os.ReadFile("platform_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	platformText := string(platform)
	if !strings.Contains(platformText, "createNoWindow") || !strings.Contains(platformText, "HideWindow:    true") {
		t.Fatal("Windows child commands must run without visible console windows")
	}

	manifest, err := os.ReadFile("app.manifest")
	if err != nil {
		t.Fatal(err)
	}
	manifestText := string(manifest)
	if !strings.Contains(manifestText, `level="requireAdministrator"`) || !strings.Contains(manifestText, `uiAccess="false"`) {
		t.Fatal("Windows application manifest must require administrator privileges for WireGuard interface access")
	}

	resourceScript, err := os.ReadFile("app.rc")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resourceScript), `1 24 "app.manifest"`) {
		t.Fatal("Windows resource script must embed app.manifest as RT_MANIFEST resource 1")
	}

	workflow, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflowText := string(workflow)
	if !strings.Contains(workflowText, "-H=windowsgui") {
		t.Fatal("Windows release must use the GUI subsystem to avoid startup console flash")
	}
	if !strings.Contains(workflowText, "requireAdministrator") {
		t.Fatal("Windows CI must verify the embedded administrator manifest")
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
