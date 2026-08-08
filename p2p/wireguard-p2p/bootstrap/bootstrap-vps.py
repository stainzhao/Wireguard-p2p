#!/usr/bin/env python3
"""Secure one-command bootstrap for a private GitHub VPS release."""
import hashlib
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import urllib.request

REPO = os.environ.get("P2P_GITHUB_REPO", "stainzhao/p2p")
TOKEN = os.environ.get("P2P_GITHUB_TOKEN", "").strip()
if not TOKEN:
    raise SystemExit("P2P_GITHUB_TOKEN is required")
HEADERS = {
    "Authorization": "Bearer " + TOKEN,
    "Accept": "application/vnd.github+json",
    "User-Agent": "wireguard-p2p-bootstrap",
}
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(url, accept=None):
    headers = dict(HEADERS)
    if accept:
        headers["Accept"] = accept
    with opener.open(urllib.request.Request(url, headers=headers), timeout=120) as response:
        return response.read()

release = json.loads(get(f"https://api.github.com/repos/{REPO}/releases/latest").decode())
assets = {item["name"]: item for item in release.get("assets", [])}
manifest_meta = assets.get("manifest.json")
if not manifest_meta:
    raise SystemExit("latest release has no manifest.json")
manifest = json.loads(get(manifest_meta["url"], "application/octet-stream").decode())
vps = manifest.get("assets", {}).get("vps-linux") or {}
name = vps.get("file", "")
meta = assets.get(name)
if not meta:
    raise SystemExit("latest release has no VPS package")
data = get(meta["url"], "application/octet-stream")
if hashlib.sha256(data).hexdigest() != vps.get("sha256") or len(data) != int(vps.get("size", 0)):
    raise SystemExit("VPS package verification failed")

with tempfile.TemporaryDirectory(prefix="wireguard-p2p-bootstrap-") as tmp:
    root = pathlib.Path(tmp).resolve()
    archive_path = root / "vps.tar.gz"
    archive_path.write_bytes(data)
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            destination = (root / member.name).resolve()
            if root != destination and root not in destination.parents:
                raise SystemExit("unsafe path in VPS archive")
        archive.extractall(root)
    installer = root / "install_vps.sh"
    if not installer.is_file():
        raise SystemExit("VPS package has no install_vps.sh")
    env = dict(os.environ)
    env["P2P_GITHUB_TOKEN"] = TOKEN
    subprocess.run(["sh", str(installer)], check=True, env=env)
    subprocess.run(["/usr/local/bin/wireguard-p2p", "update", "--force"], check=True, env=env)
print("WireGuard P2P VPS bootstrap complete.")
