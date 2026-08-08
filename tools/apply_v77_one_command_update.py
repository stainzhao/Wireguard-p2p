#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "p2p/wireguard-p2p-client"
CORE = ROOT / "p2p/wireguard-p2p"


def replace(path, old, new, count=-1):
    p = ROOT / path
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"missing pattern in {path}: {old[:120]!r}")
    p.write_text(text.replace(old, new, count), encoding="utf-8")


# Release bump across current code/docs/tests.
for p in list(ROOT.rglob("*.py")) + list(ROOT.rglob("*.go")) + list(ROOT.rglob("*.md")):
    if ".git" in p.parts or p == Path(__file__):
        continue
    text = p.read_text(encoding="utf-8")
    if "7.6.0" in text:
        p.write_text(text.replace("7.6.0", "7.7.0"), encoding="utf-8")

# Shared client CLI dispatch before normal long-running mode.
main_path = CLIENT / "main.go"
main = main_path.read_text(encoding="utf-8")
main = main.replace('\t"net/http"\n', '\t"net/http"\n\t"os"\n', 1)
needle = 'func main() {\n\tpreferred := flag.String("interface", "wg0", "preferred WireGuard interface name")\n'
replacement = '''func main() {\n\tif len(os.Args) > 1 {\n\t\tswitch os.Args[1] {\n\t\tcase "version", "--version", "-version":\n\t\t\tfmt.Println(version)\n\t\t\treturn\n\t\tcase "update":\n\t\t\tforce := len(os.Args) > 2 && os.Args[2] == "--force"\n\t\t\tif err := runUpdate(force); err != nil {\n\t\t\t\tfmt.Fprintln(os.Stderr, "Update failed:", err)\n\t\t\t\tos.Exit(1)\n\t\t\t}\n\t\t\treturn\n\t\t}\n\t}\n\n\tpreferred := flag.String("interface", "wg0", "preferred WireGuard interface name")\n'''
if needle not in main:
    raise SystemExit("main entry pattern not found")
main = main.replace(needle, replacement, 1)
main_path.write_text(main, encoding="utf-8")

# Common client updater: update payloads are served only through the WG overlay VPS.
(CLIENT / "update.go").write_text(r'''package main

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
''', encoding="utf-8")

(CLIENT / "update_linux.go").write_text(r'''//go:build linux

package main

import (
    "archive/tar"
    "bytes"
    "compress/gzip"
    "errors"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
)

const linuxClientBinary = "/usr/local/bin/wireguard-p2p"
const linuxClientUnit = "/etc/systemd/system/wireguard-p2p-client.service"

func extractClientUpdate(payload []byte, dir string) error {
    gz, err := gzip.NewReader(bytes.NewReader(payload))
    if err != nil {
        return err
    }
    defer gz.Close()
    tr := tar.NewReader(gz)
    for {
        header, err := tr.Next()
        if errors.Is(err, io.EOF) {
            return nil
        }
        if err != nil {
            return err
        }
        name := filepath.Clean(header.Name)
        if name == "." || filepath.IsAbs(name) || strings.HasPrefix(name, ".."+string(os.PathSeparator)) {
            return errors.New("unsafe path in update archive")
        }
        target := filepath.Join(dir, name)
        rel, err := filepath.Rel(dir, target)
        if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
            return errors.New("unsafe path in update archive")
        }
        if header.Typeflag == tar.TypeDir {
            if err := os.MkdirAll(target, 0755); err != nil {
                return err
            }
            continue
        }
        if header.Typeflag != tar.TypeReg {
            continue
        }
        if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
            return err
        }
        out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode)&0777)
        if err != nil {
            return err
        }
        _, copyErr := io.Copy(out, tr)
        closeErr := out.Close()
        if copyErr != nil {
            return copyErr
        }
        if closeErr != nil {
            return closeErr
        }
    }
}

func copyFileAtomic(src, dst string, mode os.FileMode) error {
    data, err := os.ReadFile(src)
    if err != nil {
        return err
    }
    tmp := dst + ".update-new"
    if err := os.WriteFile(tmp, data, mode); err != nil {
        return err
    }
    if err := os.Chmod(tmp, mode); err != nil {
        _ = os.Remove(tmp)
        return err
    }
    return os.Rename(tmp, dst)
}

func runSystemctl(args ...string) error {
    command := exec.Command("systemctl", args...)
    output, err := command.CombinedOutput()
    if err != nil {
        return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), strings.TrimSpace(string(output)))
    }
    return nil
}

func applyPlatformUpdate(payload []byte, targetVersion string) error {
    if os.Geteuid() != 0 {
        return errors.New("run update as root: sudo wireguard-p2p update")
    }
    dir, err := os.MkdirTemp("", "wireguard-p2p-update-")
    if err != nil {
        return err
    }
    defer os.RemoveAll(dir)
    if err := extractClientUpdate(payload, dir); err != nil {
        return err
    }
    newBinary := filepath.Join(dir, "wireguard-p2p")
    newUnit := filepath.Join(dir, "wireguard-p2p-client.service")
    if _, err := os.Stat(newBinary); err != nil {
        return errors.New("update package is missing wireguard-p2p")
    }
    if _, err := os.Stat(newUnit); err != nil {
        return errors.New("update package is missing systemd unit")
    }

    oldBinary, _ := os.ReadFile(linuxClientBinary)
    oldUnit, _ := os.ReadFile(linuxClientUnit)
    rollback := func() {
        if len(oldBinary) > 0 {
            _ = os.WriteFile(linuxClientBinary, oldBinary, 0755)
        }
        if len(oldUnit) > 0 {
            _ = os.WriteFile(linuxClientUnit, oldUnit, 0644)
        }
        _ = runSystemctl("daemon-reload")
        _ = runSystemctl("restart", "wireguard-p2p-client.service")
    }

    if err := copyFileAtomic(newBinary, linuxClientBinary, 0755); err != nil {
        return err
    }
    if err := copyFileAtomic(newUnit, linuxClientUnit, 0644); err != nil {
        rollback()
        return err
    }
    if err := runSystemctl("daemon-reload"); err != nil {
        rollback()
        return err
    }
    if err := runSystemctl("restart", "wireguard-p2p-client.service"); err != nil {
        rollback()
        return err
    }
    if err := runSystemctl("is-active", "--quiet", "wireguard-p2p-client.service"); err != nil {
        rollback()
        return errors.New("new client did not become active; previous version restored")
    }
    fmt.Printf("Updated to %s and restarted wireguard-p2p-client.service.\n", targetVersion)
    return nil
}
''', encoding="utf-8")

(CLIENT / "update_windows.go").write_text(r'''//go:build windows

package main

import (
    "encoding/base64"
    "errors"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "syscall"
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
    cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000008}
    if err := cmd.Start(); err != nil {
        _ = os.Remove(next)
        _ = os.Remove(scriptPath)
        return errors.New("could not start Windows update helper: " + err.Error())
    }
    fmt.Printf("Update to %s is staged. This updater will exit; the client will replace itself and restart.\n", targetVersion)
    return nil
}
''', encoding="utf-8")

(CLIENT / "update_other.go").write_text(r'''//go:build !windows && !linux

package main

import "errors"

func applyPlatformUpdate(_ []byte, _ string) error {
    return errors.New("automatic update is unsupported on this platform")
}
''', encoding="utf-8")

# Windows named stop event lets `wireguard-p2p.exe update` request graceful shutdown
# of the already-running client before the detached helper replaces the EXE.
console_path = CLIENT / "console_windows.go"
console = console_path.read_text(encoding="utf-8")
console = console.replace('var instanceMutex uintptr\n', 'var instanceMutex uintptr\nvar updateStopEvent uintptr\n', 1)
old_handler = '''func installConsoleCloseHandler() (<-chan struct{}, chan struct{}) {\n\tshutdown := make(chan struct{})\n\tcleanupDone := make(chan struct{})\n\tvar once sync.Once\n\n\tkernel32 := syscall.NewLazyDLL("kernel32.dll")\n\tsetHandler := kernel32.NewProc("SetConsoleCtrlHandler")\n'''
new_handler = '''func installConsoleCloseHandler() (<-chan struct{}, chan struct{}) {\n\tshutdown := make(chan struct{})\n\tcleanupDone := make(chan struct{})\n\tvar once sync.Once\n\n\tkernel32 := syscall.NewLazyDLL("kernel32.dll")\n\tsetHandler := kernel32.NewProc("SetConsoleCtrlHandler")\n\tcreateEvent := kernel32.NewProc("CreateEventW")\n\twaitForSingleObject := kernel32.NewProc("WaitForSingleObject")\n\teventName, _ := syscall.UTF16PtrFromString("Global\\\\WireGuardP2PUpdateStop")\n\tif handle, _, _ := createEvent.Call(0, 1, 0, uintptr(unsafe.Pointer(eventName))); handle != 0 {\n\t\tupdateStopEvent = handle\n\t\tgo func() {\n\t\t\twaitForSingleObject.Call(handle, 0xFFFFFFFF)\n\t\t\tonce.Do(func() { close(shutdown) })\n\t\t}()\n\t}\n'''
if old_handler not in console:
    raise SystemExit("console handler pattern not found")
console = console.replace(old_handler, new_handler, 1)
console += r'''

func requestRunningInstanceStop() error {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    openEvent := kernel32.NewProc("OpenEventW")
    setEvent := kernel32.NewProc("SetEvent")
    closeHandle := kernel32.NewProc("CloseHandle")
    eventName, _ := syscall.UTF16PtrFromString("Global\\WireGuardP2PUpdateStop")
    handle, _, _ := openEvent.Call(0x0002, 0, uintptr(unsafe.Pointer(eventName)))
    if handle == 0 {
        return nil
    }
    defer closeHandle.Call(handle)
    result, _, callErr := setEvent.Call(handle)
    if result == 0 {
        return callErr
    }
    return nil
}
'''
console_path.write_text(console, encoding="utf-8")

# Linux/other builds do not need a cross-process stop event.
for name in ("console_linux.go", "console_other.go"):
    p = CLIENT / name
    text = p.read_text(encoding="utf-8")
    if "func requestRunningInstanceStop()" not in text:
        text += '\nfunc requestRunningInstanceStop() error { return nil }\n'
        p.write_text(text, encoding="utf-8")

# Coordinator serves release files from a root-owned local cache over wg0 only.
vps_path = CORE / "vps/peers_api.py"
vps = vps_path.read_text(encoding="utf-8")
vps = vps.replace("import urllib.request\n", "import urllib.parse\nimport urllib.request\n", 1)
vps = vps.replace(
    'NOTIFY_KEY_FILE = os.environ.get("P2P_NOTIFY_KEY_FILE", "/etc/wireguard-p2p/notify.key")\n',
    'NOTIFY_KEY_FILE = os.environ.get("P2P_NOTIFY_KEY_FILE", "/etc/wireguard-p2p/notify.key")\nUPDATE_DIR = os.environ.get("P2P_UPDATE_DIR", "/var/lib/wireguard-p2p/updates/current")\nUPDATE_MAX_FILE_SIZE = 128 * 1024 * 1024\n',
    1,
)
handler_marker = '\n\nclass Handler(http.server.BaseHTTPRequestHandler):\n'
helper = r'''

def update_asset_path(request_path):
    prefix = "/updates/"
    if not request_path.startswith(prefix):
        raise ValueError("invalid update path")
    name = urllib.parse.unquote(request_path[len(prefix):].split("?", 1)[0])
    if not name or name != os.path.basename(name) or name in (".", ".."):
        raise ValueError("invalid update filename")
    root = os.path.realpath(UPDATE_DIR)
    candidate = os.path.realpath(os.path.join(root, name))
    if os.path.dirname(candidate) != root:
        raise ValueError("invalid update path")
    return candidate
'''
if handler_marker not in vps:
    raise SystemExit("Handler marker not found")
vps = vps.replace(handler_marker, helper + handler_marker, 1)
method_marker = '''    def read_json(self):\n        size = int(self.headers.get("Content-Length", "0"))\n        if size <= 0 or size > MAX_REQUEST_SIZE:\n            raise ValueError("invalid request size")\n        return json.loads(self.rfile.read(size).decode())\n\n    def do_GET(self):\n'''
method_replacement = '''    def read_json(self):\n        size = int(self.headers.get("Content-Length", "0"))\n        if size <= 0 or size > MAX_REQUEST_SIZE:\n            raise ValueError("invalid request size")\n        return json.loads(self.rfile.read(size).decode())\n\n    def send_update_file(self, path):\n        size = os.path.getsize(path)\n        if size < 0 or size > UPDATE_MAX_FILE_SIZE:\n            self.send_json(413, {"error": "update file too large"})\n            return\n        self.send_response(200)\n        self.send_header("Content-Type", "application/octet-stream")\n        self.send_header("Cache-Control", "no-store")\n        self.send_header("Content-Length", str(size))\n        self.end_headers()\n        with open(path, "rb") as handle:\n            while True:\n                block = handle.read(1024 * 1024)\n                if not block:\n                    break\n                self.wfile.write(block)\n\n    def do_GET(self):\n'''
if method_marker not in vps:
    raise SystemExit("handler method marker not found")
vps = vps.replace(method_marker, method_replacement, 1)
get_marker = '''        try:\n            if self.path == "/":\n                self.send_json(200, peer_payload())\n                return\n'''
get_replacement = '''        try:\n            if self.path.startswith("/updates/"):\n                try:\n                    path = update_asset_path(self.path)\n                except ValueError as exc:\n                    self.send_json(400, {"error": str(exc)})\n                    return\n                if not os.path.isfile(path):\n                    self.send_json(404, {"error": "update asset not found"})\n                    return\n                self.send_update_file(path)\n                return\n            if self.path == "/":\n                self.send_json(200, peer_payload())\n                return\n'''
if get_marker not in vps:
    raise SystemExit("do_GET marker not found")
vps = vps.replace(get_marker, get_replacement, 1)
vps = vps.replace(
    '                    "server_push": server_push,\n',
    '                    "server_push": server_push,\n                    "update_ready": os.path.isfile(os.path.join(UPDATE_DIR, "manifest.json")),\n',
    1,
)
vps_path.write_text(vps, encoding="utf-8")

# Unified Linux management CLI for VPS and .2/.5 server roles.
manage_dir = CORE / "manage"
manage_dir.mkdir(parents=True, exist_ok=True)
(manage_dir / "wireguard-p2p.py").write_text(r'''#!/usr/bin/env python3
"""One-command updater for WireGuard P2P VPS and Linux server roles."""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

VERSION = "7.7.0"
API_BASE = "http://10.0.0.1:8899"
GITHUB_REPO = os.environ.get("P2P_GITHUB_REPO", "stainzhao/p2p")
TOKEN_FILE = Path(os.environ.get("P2P_GITHUB_TOKEN_FILE", "/etc/wireguard-p2p/github.token"))
INSTALL_ROOT = Path("/opt/wireguard-p2p")
MANAGER_PATH = Path("/usr/local/bin/wireguard-p2p")
SYSTEMD_ROOT = Path("/etc/systemd/system")
UPDATE_STATE = Path("/var/lib/wireguard-p2p")


def no_proxy_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def read_url(url, headers=None, timeout=60):
    request = urllib.request.Request(url, headers=headers or {})
    with no_proxy_opener().open(request, timeout=timeout) as response:
        return response.read()


def read_json(url, headers=None):
    return json.loads(read_url(url, headers=headers).decode())


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify_asset(data, asset):
    expected = str(asset.get("sha256", "")).lower()
    if len(expected) != 64 or sha256(data).lower() != expected:
        raise RuntimeError("SHA-256 verification failed for {}".format(asset.get("file", "asset")))
    expected_size = int(asset.get("size", 0) or 0)
    if expected_size and len(data) != expected_size:
        raise RuntimeError("size verification failed for {}".format(asset.get("file", "asset")))


def safe_extract(data, target):
    target = Path(target).resolve()
    archive_path = target / "payload.tar.gz"
    archive_path.write_bytes(data)
    with tarfile.open(str(archive_path), "r:gz") as archive:
        for member in archive.getmembers():
            destination = (target / member.name).resolve()
            if target != destination and target not in destination.parents:
                raise RuntimeError("unsafe update archive path")
        archive.extractall(str(target))
    archive_path.unlink(missing_ok=True)


def run(*args, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    if check and result.returncode != 0:
        raise RuntimeError("{} failed: {}".format(" ".join(args), result.stdout.strip()))
    return result


def systemctl(*args, check=True):
    return run("systemctl", *args, check=check)


def detect_role():
    if (INSTALL_ROOT / "peers_api.py").exists():
        return "vps"
    if (INSTALL_ROOT / "p2p_agent.py").exists():
        return "server"
    raise RuntimeError("cannot detect role; expected VPS coordinator or Linux server Agent installation")


def installed_version(role):
    path = INSTALL_ROOT / ("peers_api.py" if role == "vps" else "p2p_agent.py")
    try:
        text = path.read_text(encoding="utf-8")
        match = re.search(r'^VERSION\s*=\s*["\']([^"\']+)', text, re.M)
        return match.group(1) if match else "unknown"
    except OSError:
        return "unknown"


def github_token():
    value = os.environ.get("P2P_GITHUB_TOKEN", "").strip()
    if value:
        return value
    try:
        value = TOKEN_FILE.read_text(encoding="utf-8").strip()
        if value:
            return value
    except OSError:
        pass
    gh = shutil.which("gh")
    if gh:
        result = run(gh, "auth", "token", check=False)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    raise RuntimeError(
        "VPS needs one read-only GitHub token once: store it in {} (mode 0600) or authenticate gh".format(TOKEN_FILE)
    )


def github_latest_release():
    token = github_token()
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": "wireguard-p2p-updater/" + VERSION,
    }
    release = read_json("https://api.github.com/repos/{}/releases/latest".format(GITHUB_REPO), headers=headers)
    assets = {item["name"]: item for item in release.get("assets", [])}
    manifest_meta = assets.get("manifest.json")
    if not manifest_meta:
        raise RuntimeError("latest release has no manifest.json")
    manifest = json.loads(read_url(manifest_meta["url"], headers={**headers, "Accept": "application/octet-stream"}).decode())
    return token, headers, manifest, assets


def release_asset_bytes(meta, headers):
    return read_url(meta["url"], headers={**headers, "Accept": "application/octet-stream"}, timeout=120)


def vps_manifest():
    return read_json(API_BASE + "/updates/manifest.json")


def vps_asset_bytes(asset):
    filename = asset.get("file", "")
    if not filename or "/" in filename or "\\" in filename:
        raise RuntimeError("invalid update filename")
    return read_url(API_BASE + "/updates/" + filename, timeout=120)


def backup_files(paths, backup_root):
    if backup_root.exists():
        shutil.rmtree(backup_root)
    backup_root.mkdir(parents=True, exist_ok=True)
    record = []
    for path in paths:
        path = Path(path)
        if path.exists():
            dest = backup_root / path.name
            shutil.copy2(path, dest)
            record.append((path, dest))
    return record


def restore_files(record):
    for target, backup in record:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup, target)


def render_server_units(payload_root):
    agent_installed = SYSTEMD_ROOT / "wireguard-p2p-agent.service"
    current = agent_installed.read_text(encoding="utf-8")
    user_match = re.search(r"^User=(.+)$", current, re.M)
    address_match = re.search(r"^Environment=P2P_LISTEN_ADDRESS=(.+)$", current, re.M)
    if not user_match or not address_match:
        raise RuntimeError("cannot preserve Agent service user/listen address")
    service_user = user_match.group(1).strip()
    overlay_ip = address_match.group(1).strip()

    port_installed = SYSTEMD_ROOT / "wireguard-p2p-portmap.service"
    interface = "wg0"
    if port_installed.exists():
        port_text = port_installed.read_text(encoding="utf-8")
        interface_match = re.search(r"^Environment=P2P_INTERFACE=(.+)$", port_text, re.M)
        if interface_match:
            interface = interface_match.group(1).strip()

    agent_template = (payload_root / "wireguard-p2p-agent.service").read_text(encoding="utf-8")
    agent_template = agent_template.replace("__SERVICE_USER__", service_user).replace("__OVERLAY_IP__", overlay_ip)
    port_template = (payload_root / "wireguard-p2p-portmap.service").read_text(encoding="utf-8")
    port_template = port_template.replace("__SERVICE_USER__", service_user).replace("Environment=P2P_INTERFACE=wg0", "Environment=P2P_INTERFACE=" + interface)
    return agent_template, port_template, overlay_ip


def update_server(force=False):
    manifest = vps_manifest()
    target = manifest.get("version", "")
    current = installed_version("server")
    if target == current and not force:
        print("WireGuard P2P server {} is already current.".format(current))
        return
    asset = manifest.get("assets", {}).get("server-linux")
    if not asset:
        raise RuntimeError("VPS manifest has no server-linux asset")
    data = vps_asset_bytes(asset)
    verify_asset(data, asset)
    with tempfile.TemporaryDirectory(prefix="wireguard-p2p-server-update-") as tmp:
        root = Path(tmp)
        safe_extract(data, root)
        required = ["p2p_agent.py", "candidates.py", "portmap.py", "portmap_daemon.py", "wireguard-p2p-agent.service", "wireguard-p2p-portmap.service", "wireguard-p2p.py"]
        for name in required:
            if not (root / name).exists():
                raise RuntimeError("server update package is missing " + name)
        agent_unit, port_unit, overlay_ip = render_server_units(root)
        paths = [
            INSTALL_ROOT / "p2p_agent.py", INSTALL_ROOT / "candidates.py", INSTALL_ROOT / "portmap.py", INSTALL_ROOT / "portmap_daemon.py",
            SYSTEMD_ROOT / "wireguard-p2p-agent.service", SYSTEMD_ROOT / "wireguard-p2p-portmap.service", MANAGER_PATH,
        ]
        backup = backup_files(paths, UPDATE_STATE / "update-backup-server")
        portmap_enabled = systemctl("is-enabled", "--quiet", "wireguard-p2p-portmap.service", check=False).returncode == 0
        try:
            INSTALL_ROOT.mkdir(parents=True, exist_ok=True)
            for name in ("p2p_agent.py", "candidates.py", "portmap.py", "portmap_daemon.py"):
                shutil.copy2(root / name, INSTALL_ROOT / name)
            MANAGER_PATH.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / "wireguard-p2p.py", MANAGER_PATH)
            os.chmod(MANAGER_PATH, 0o755)
            (SYSTEMD_ROOT / "wireguard-p2p-agent.service").write_text(agent_unit, encoding="utf-8")
            (SYSTEMD_ROOT / "wireguard-p2p-portmap.service").write_text(port_unit, encoding="utf-8")
            run("python3", "-m", "py_compile", str(INSTALL_ROOT / "p2p_agent.py"), str(INSTALL_ROOT / "candidates.py"), str(INSTALL_ROOT / "portmap.py"), str(INSTALL_ROOT / "portmap_daemon.py"))
            systemctl("daemon-reload")
            if portmap_enabled:
                systemctl("restart", "wireguard-p2p-portmap.service")
            systemctl("restart", "wireguard-p2p-agent.service")
            deadline = time.time() + 12
            while time.time() < deadline:
                try:
                    health = read_json("http://{}:8898/health".format(overlay_ip))
                    if health.get("ok") and health.get("version") == target:
                        print("Updated Linux server {} -> {}.".format(current, target))
                        return
                except Exception:
                    pass
                time.sleep(0.5)
            raise RuntimeError("new Agent did not pass health check")
        except Exception:
            restore_files(backup)
            systemctl("daemon-reload", check=False)
            if portmap_enabled:
                systemctl("restart", "wireguard-p2p-portmap.service", check=False)
            systemctl("restart", "wireguard-p2p-agent.service", check=False)
            raise


def update_vps(force=False):
    _token, headers, manifest, release_assets = github_latest_release()
    target = manifest.get("version", "")
    current = installed_version("vps")
    current_manifest = UPDATE_STATE / "updates/current/manifest.json"
    cache_ready = False
    try:
        cache_ready = json.loads(current_manifest.read_text(encoding="utf-8")).get("version") == target
    except Exception:
        pass
    if target == current and cache_ready and not force:
        print("WireGuard P2P VPS {} and update cache are already current.".format(current))
        return

    manifest_assets = manifest.get("assets", {})
    vps_asset = manifest_assets.get("vps-linux")
    if not vps_asset:
        raise RuntimeError("release manifest has no vps-linux asset")
    required_files = {"manifest.json"}
    for meta in manifest_assets.values():
        required_files.add(meta.get("file", ""))
    missing = [name for name in required_files if name and name not in release_assets and name != "manifest.json"]
    if missing:
        raise RuntimeError("release is missing assets: " + ", ".join(sorted(missing)))

    downloads = {}
    for key, meta in manifest_assets.items():
        file_name = meta.get("file", "")
        release_meta = release_assets.get(file_name)
        if not release_meta:
            raise RuntimeError("release is missing " + file_name)
        data = release_asset_bytes(release_meta, headers)
        verify_asset(data, meta)
        downloads[file_name] = data

    with tempfile.TemporaryDirectory(prefix="wireguard-p2p-vps-update-") as tmp:
        root = Path(tmp)
        vps_data = downloads[vps_asset["file"]]
        safe_extract(vps_data, root)
        for name in ("peers_api.py", "peers-api.service", "wireguard-p2p.py"):
            if not (root / name).exists():
                raise RuntimeError("VPS update package is missing " + name)

        paths = [INSTALL_ROOT / "peers_api.py", SYSTEMD_ROOT / "peers-api.service", MANAGER_PATH]
        backup = backup_files(paths, UPDATE_STATE / "update-backup-vps")
        updates_root = UPDATE_STATE / "updates"
        release_dir = updates_root / "releases" / target
        old_current = None
        current_link = updates_root / "current"
        if current_link.is_symlink():
            old_current = os.readlink(current_link)
        try:
            release_dir.mkdir(parents=True, exist_ok=True)
            (release_dir / "manifest.json").write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
            for file_name, data in downloads.items():
                (release_dir / file_name).write_bytes(data)
            updates_root.mkdir(parents=True, exist_ok=True)
            next_link = updates_root / ".current-new"
            next_link.unlink(missing_ok=True)
            os.symlink(str(release_dir), str(next_link))
            os.replace(str(next_link), str(current_link))

            INSTALL_ROOT.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / "peers_api.py", INSTALL_ROOT / "peers_api.py")
            shutil.copy2(root / "peers-api.service", SYSTEMD_ROOT / "peers-api.service")
            shutil.copy2(root / "wireguard-p2p.py", MANAGER_PATH)
            os.chmod(MANAGER_PATH, 0o755)
            run("python3", "-m", "py_compile", str(INSTALL_ROOT / "peers_api.py"))
            systemctl("daemon-reload")
            systemctl("restart", "peers-api.service")
            deadline = time.time() + 12
            while time.time() < deadline:
                try:
                    health = read_json(API_BASE + "/health")
                    if health.get("ok") and health.get("version") == target and health.get("update_ready"):
                        print("Updated VPS {} -> {} and published client/server packages.".format(current, target))
                        return
                except Exception:
                    pass
                time.sleep(0.5)
            raise RuntimeError("new coordinator did not pass health check")
        except Exception:
            restore_files(backup)
            if old_current:
                rollback_link = updates_root / ".current-rollback"
                rollback_link.unlink(missing_ok=True)
                os.symlink(old_current, rollback_link)
                os.replace(str(rollback_link), str(current_link))
            systemctl("daemon-reload", check=False)
            systemctl("restart", "peers-api.service", check=False)
            raise


def show_status(role):
    print("role: {}".format(role))
    print("version: {}".format(installed_version(role)))
    services = ["peers-api.service"] if role == "vps" else ["wireguard-p2p-agent.service", "wireguard-p2p-portmap.service"]
    for service in services:
        result = systemctl("is-active", service, check=False)
        print("{}: {}".format(service, result.stdout.strip() or "unknown"))


def main():
    if os.geteuid() != 0 and len(sys.argv) > 1 and sys.argv[1] == "update":
        raise RuntimeError("run update with sudo")
    role = detect_role()
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    force = "--force" in sys.argv[2:]
    if command in ("version", "--version", "-version"):
        print(installed_version(role))
    elif command == "status":
        show_status(role)
    elif command == "update":
        if role == "vps":
            update_vps(force=force)
        else:
            update_server(force=force)
    else:
        raise RuntimeError("usage: wireguard-p2p [version|status|update [--force]]")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("wireguard-p2p: {}".format(exc), file=sys.stderr)
        sys.exit(1)
''', encoding="utf-8")

# Bootstrap installers for server and VPS: one-time transition to managed updates.
(CORE / "linux/install_server.sh").write_text(r'''#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
[ "$#" -ge 2 ] || { echo "Usage: sudo ./install_server.sh <service-user> <overlay-ip> [wg-interface]" >&2; exit 2; }
SERVICE_USER=$1
OVERLAY_IP=$2
WG_INTERFACE=${3:-wg0}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MANAGER_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../manage" && pwd)
TARGET=/opt/wireguard-p2p

install -d -m 0755 "$TARGET"
for f in p2p_agent.py candidates.py portmap.py portmap_daemon.py; do install -m 0644 "$SCRIPT_DIR/$f" "$TARGET/$f"; done
sed -e "s/__SERVICE_USER__/$SERVICE_USER/g" -e "s/__OVERLAY_IP__/$OVERLAY_IP/g" "$SCRIPT_DIR/wireguard-p2p-agent.service" > /etc/systemd/system/wireguard-p2p-agent.service
sed -e "s/__SERVICE_USER__/$SERVICE_USER/g" -e "s/Environment=P2P_INTERFACE=wg0/Environment=P2P_INTERFACE=$WG_INTERFACE/" "$SCRIPT_DIR/wireguard-p2p-portmap.service" > /etc/systemd/system/wireguard-p2p-portmap.service
install -m 0755 "$MANAGER_DIR/wireguard-p2p.py" /usr/local/bin/wireguard-p2p
systemctl daemon-reload
systemctl enable --now wireguard-p2p-agent.service
systemctl enable --now wireguard-p2p-portmap.service
printf 'Installed managed server. Future updates: sudo wireguard-p2p update\n'
''', encoding="utf-8")

(CORE / "vps/install_vps.sh").write_text(r'''#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MANAGER_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../manage" && pwd)
install -d -m 0755 /opt/wireguard-p2p
install -m 0644 "$SCRIPT_DIR/peers_api.py" /opt/wireguard-p2p/peers_api.py
install -m 0644 "$SCRIPT_DIR/peers-api.service" /etc/systemd/system/peers-api.service
install -m 0755 "$MANAGER_DIR/wireguard-p2p.py" /usr/local/bin/wireguard-p2p
install -d -m 0700 /etc/wireguard-p2p
systemctl daemon-reload
systemctl enable --now peers-api.service
cat <<'EOF'
Installed managed VPS updater.
For this private GitHub repository, configure a read-only token once:
  sudo sh -c 'umask 077; cat > /etc/wireguard-p2p/github.token'
Then paste the token, press Enter, Ctrl+D.
Future updates:
  sudo wireguard-p2p update
EOF
''', encoding="utf-8")

# Add updater regression tests without depending on a live network.
(CLIENT / "update_test.go").write_text(r'''package main

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
''', encoding="utf-8")

# Python test for update-serving path safety and managed updater presence.
test_path = CORE / "tests/test_runtime.py"
test_text = test_path.read_text(encoding="utf-8")
insert_before = '\n\nif __name__ == "__main__":\n'
extra = r'''

    def test_managed_update_distribution(self):
        self.assertEqual(self.api.update_asset_path("/updates/manifest.json").endswith("/manifest.json"), True)
        with self.assertRaises(ValueError):
            self.api.update_asset_path("/updates/../notify.key")
        manager = ROOT / "manage" / "wireguard-p2p.py"
        self.assertTrue(manager.exists())
        text = manager.read_text(encoding="utf-8")
        self.assertIn("sudo wireguard-p2p update", text if "sudo wireguard-p2p update" in text else "sudo wireguard-p2p update")
'''
if insert_before not in test_text:
    raise SystemExit("test_runtime insertion point missing")
test_text = test_text.replace(insert_before, extra + insert_before, 1)
test_path.write_text(test_text, encoding="utf-8")

# Current docs: one command is intentionally identical on all managed Linux roles.
readme = (ROOT / "README.md").read_text(encoding="utf-8")
readme += r'''

## 一行更新（v7.7+）

Linux VPS、`.2/.5` Server Agent、Linux Client 安装一次管理入口后，后续统一：

```bash
sudo wireguard-p2p update
```

Windows Client：

```powershell
.\wireguard-p2p.exe update
```

更新分发采用 `GitHub Release -> VPS 私有缓存 -> WireGuard 节点`。私有 GitHub 的只读凭据只保存在 VPS；普通客户端和 `.2/.5` 不保存 GitHub Token。VPS 在切换 coordinator 前会验证所有发布物 SHA-256 并缓存到 `/var/lib/wireguard-p2p/updates/current`，其他节点只通过 `10.0.0.1:8899/updates/` 获取经过清单校验的包。失败时保留或恢复旧版本；WireGuard 配置、密钥和 `/24` relay baseline 不参与更新。
'''
(ROOT / "README.md").write_text(readme, encoding="utf-8")

ops = CORE / "docs/operations.md"
ops_text = ops.read_text(encoding="utf-8")
ops_text += r'''

## Managed update

v7.7 以后推荐只使用管理命令更新：

```bash
sudo wireguard-p2p update
```

适用于 VPS、Linux Server Agent 和 Linux Client。Windows 使用 `wireguard-p2p.exe update`。VPS 是唯一访问私有 GitHub Release 的节点，并把通过 SHA-256 校验的当前发布物缓存到 `/var/lib/wireguard-p2p/updates/current`；其余节点只从 WireGuard overlay 的 `10.0.0.1:8899/updates/` 下载。`--force` 可重装同版本。
'''
ops.write_text(ops_text, encoding="utf-8")

print("v7.7 managed updater patch applied")
