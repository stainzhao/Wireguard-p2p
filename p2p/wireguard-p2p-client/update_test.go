package main

import "testing"

func TestUpdateAssetKeySupportedBuild(t *testing.T) {
	key, err := updateAssetKey()
	if err != nil {
		t.Fatal(err)
	}
	if key != "linux-amd64" && key != "linux-arm64" && key != "windows-amd64" {
		t.Fatalf("unexpected update asset key %q", key)
	}
}

func TestUpdateFilenameValidation(t *testing.T) {
	for _, good := range []string{"wireguard-p2p-linux-amd64.tar.gz", "wireguard-p2p.exe"} {
		if !validUpdateFilename(good) {
			t.Fatalf("expected %q to be valid", good)
		}
	}
	for _, bad := range []string{"../x", "a/b", `a\\b`, "", ".", ".."} {
		if validUpdateFilename(bad) {
			t.Fatalf("expected %q to be invalid", bad)
		}
	}
}
