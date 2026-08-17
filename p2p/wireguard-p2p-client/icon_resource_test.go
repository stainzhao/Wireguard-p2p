package main

import (
	"os"
	"strings"
	"testing"
)

func TestWindowsExecutableIconResource(t *testing.T) {
	if info, err := os.Stat("assets/p2p.ico"); err != nil || info.Size() < 512 {
		t.Fatalf("Windows icon asset missing or too small: %v", err)
	}

	rc, err := os.ReadFile("app.rc")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rc), `1 ICON "assets/p2p.ico"`) {
		t.Fatal("app.rc must expose the executable icon as resource ID 1")
	}

	workflow, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	for _, required := range []string{
		"binutils-mingw-w64-x86-64",
		"x86_64-w64-mingw32-windres app.rc",
		"rsrc_windows_amd64.syso",
		"x86_64-w64-mingw32-objdump",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Windows icon build missing %q", required)
		}
	}
}
