package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

type updateAsset struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type updateManifest struct {
	Version  string                 `json:"version"`
	Protocol int                    `json:"protocol"`
	Assets   map[string]updateAsset `json:"assets"`
}

func updateAssetKey() (string, error) {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "windows/amd64":
		return "windows-amd64", nil
	case "linux/amd64":
		return "linux-amd64", nil
	case "linux/arm64":
		return "linux-arm64", nil
	default:
		return "", fmt.Errorf("automatic update is not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

func updateHTTPClient() *http.Client {
	return &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{Proxy: nil}}
}

func readUpdateURL(path string, limit int64) ([]byte, error) {
	request, err := http.NewRequest(http.MethodGet, apiBase+path, nil)
	if err != nil {
		return nil, err
	}
	response, err := updateHTTPClient().Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update server returned %s", response.Status)
	}
	reader := io.LimitReader(response.Body, limit+1)
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("update payload exceeds size limit")
	}
	return body, nil
}

func fetchUpdateManifest() (updateManifest, error) {
	body, err := readUpdateURL("/updates/manifest.json", 1<<20)
	if err != nil {
		return updateManifest{}, err
	}
	var manifest updateManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return updateManifest{}, err
	}
	if manifest.Version == "" || manifest.Protocol != 7 || len(manifest.Assets) == 0 {
		return updateManifest{}, errors.New("invalid update manifest")
	}
	return manifest, nil
}

func validUpdateFilename(name string) bool {
	return name != "" && !strings.ContainsAny(name, "/\\") && name != "." && name != ".."
}

func downloadUpdateAsset(asset updateAsset) ([]byte, error) {
	if !validUpdateFilename(asset.File) || len(asset.SHA256) != 64 {
		return nil, errors.New("invalid update asset metadata")
	}
	limit := int64(128 << 20)
	if asset.Size > 0 && asset.Size < limit {
		limit = asset.Size + (1 << 20)
	}
	body, err := readUpdateURL("/updates/"+asset.File, limit)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, asset.SHA256) {
		return nil, fmt.Errorf("SHA-256 mismatch: got %s", got)
	}
	if asset.Size > 0 && int64(len(body)) != asset.Size {
		return nil, fmt.Errorf("size mismatch: got %d, want %d", len(body), asset.Size)
	}
	return body, nil
}

func runUpdate(force bool) error {
	manifest, err := fetchUpdateManifest()
	if err != nil {
		return fmt.Errorf("cannot reach VPS update service: %w", err)
	}
	if manifest.Version == version && !force {
		fmt.Printf("WireGuard P2P %s is already current.\n", version)
		return nil
	}
	key, err := updateAssetKey()
	if err != nil {
		return err
	}
	asset, ok := manifest.Assets[key]
	if !ok {
		return fmt.Errorf("release %s has no asset for %s", manifest.Version, key)
	}
	fmt.Printf("Updating WireGuard P2P %s -> %s (%s)...\n", version, manifest.Version, key)
	payload, err := downloadUpdateAsset(asset)
	if err != nil {
		return err
	}
	return applyPlatformUpdate(payload, manifest.Version)
}
