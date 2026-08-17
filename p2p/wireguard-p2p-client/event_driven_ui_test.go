package main

import (
	"os"
	"strings"
	"testing"
)

func TestEventDrivenWindowsGUIHasNoPollingWatcher(t *testing.T) {
	events, err := os.ReadFile("gui_events_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(events)
	for _, forbidden := range []string{"time.NewTicker", "time.Sleep", "wmTimer"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("event-driven Windows GUI contains polling primitive %q", forbidden)
		}
	}
	for _, required := range []string{"platformClientStateChanged", "guiViewFingerprint", "procInvalidateRect.Call"} {
		if !strings.Contains(text, required) {
			t.Fatalf("event-driven Windows GUI missing %q", required)
		}
	}
}

func TestWindowsLogsAppendInsteadOfFullRefresh(t *testing.T) {
	model, err := os.ReadFile("gui_model_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(model)
	for _, required := range []string{"appendGUILogLine", "emReplaceSel", "emLineIndex", "emScrollCaret"} {
		if !strings.Contains(text, required) {
			t.Fatalf("incremental log path missing %q", required)
		}
	}
}
