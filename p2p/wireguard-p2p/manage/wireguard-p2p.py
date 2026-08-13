#!/usr/bin/env python3
"""One-command updater for WireGuard P2P VPS and Linux server roles."""

import hashlib
import ipaddress
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

VERSION = "7.12.1"
API_BASE = "http://10.0.0.1:8899"
GITHUB_REPO = os.environ.get("P2P_GITHUB_REPO", "stainzhao/p2p")
CONFIG_DIR = Path(os.environ.get("P2P_CONFIG_DIR", "/etc/wireguard-p2p"))
TOKEN_FILE = Path(os.environ.get("P2P_GITHUB_TOKEN_FILE", "/etc/wireguard-p2p/github.token"))
INSTALL_ROOT = Path("/opt/wireguard-p2p")
MANAGER_PATH = Path("/usr/local/bin/wireguard-p2p")
SYSTEMD_ROOT = Path("/etc/systemd/system")
UPDATE_STATE = Path("/var/lib/wireguard-p2p")
SERVER_REGISTRY_FILE = Path(os.environ.get("P2P_SERVER_REGISTRY_FILE", "/etc/wireguard-p2p/servers.conf"))
RELAY_ONLY_REGISTRY_FILE = Path(os.environ.get("P2P_RELAY_ONLY_REGISTRY_FILE", "/etc/wireguard-p2p/relay-only.conf"))
COORDINATOR_IP = "10.0.0.1"
OVERLAY_NETWORK = ipaddress.ip_network("10.0.0.0/24")


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


def unlink_if_exists(path):
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass


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
    unlink_if_exists(archive_path)


def run(*args, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, check=False)
    if check and result.returncode != 0:
        raise RuntimeError("{} failed: {}".format(" ".join(args), result.stdout.strip()))
    return result


def systemctl(*args, check=True):
    return run("systemctl", *args, check=check)



def repair_config_permissions(role):
    """Repair service-account access after the v7.10.0 fresh-install regression."""
    if not CONFIG_DIR.exists():
        return
    try:
        shutil.chown(CONFIG_DIR, user="root", group="wireguard-p2p")
    except LookupError as exc:
        raise RuntimeError("wireguard-p2p service account is missing") from exc
    os.chmod(CONFIG_DIR, 0o750)

    key_file = CONFIG_DIR / "notify.key"
    if key_file.exists():
        shutil.chown(key_file, user="wireguard-p2p", group="wireguard-p2p")
        os.chmod(key_file, 0o400)

    if role == "vps":
        for registry in (SERVER_REGISTRY_FILE, RELAY_ONLY_REGISTRY_FILE):
            if registry.exists():
                shutil.chown(registry, user="root", group="wireguard-p2p")
                os.chmod(registry, 0o640)


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
        client_enabled = systemctl("is-enabled", "--quiet", "wireguard-p2p-client.service", check=False).returncode == 0
        client_active = systemctl("is-active", "--quiet", "wireguard-p2p-client.service", check=False).returncode == 0
        if client_active:
            systemctl("stop", "wireguard-p2p-client.service", check=False)
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
                        # The dual-capability Agent owns server initiation now.
                        # Keep any legacy ordinary Linux Client service disabled.
                        systemctl("disable", "wireguard-p2p-client.service", check=False)
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
            if client_enabled:
                systemctl("enable", "wireguard-p2p-client.service", check=False)
            if client_active:
                systemctl("restart", "wireguard-p2p-client.service", check=False)
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

    sums_meta = release_assets.get("SHA256SUMS")
    if not sums_meta:
        raise RuntimeError("release is missing SHA256SUMS")
    sums_data = release_asset_bytes(sums_meta, headers)
    sums_lines = set(sums_data.decode("utf-8").splitlines())
    for meta in manifest_assets.values():
        expected = "{}  {}".format(meta.get("sha256", ""), meta.get("file", ""))
        if expected not in sums_lines:
            raise RuntimeError("SHA256SUMS does not match manifest for " + meta.get("file", "asset"))
    downloads["SHA256SUMS"] = sums_data

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
            unlink_if_exists(next_link)
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
                unlink_if_exists(rollback_link)
                os.symlink(old_current, rollback_link)
                os.replace(str(rollback_link), str(current_link))
            systemctl("daemon-reload", check=False)
            systemctl("restart", "peers-api.service", check=False)
            raise



def validate_role_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise RuntimeError("invalid overlay IP: " + str(value))
    normalized = str(address)
    if (
        address.version != 4
        or address not in OVERLAY_NETWORK
        or address in (OVERLAY_NETWORK.network_address, OVERLAY_NETWORK.broadcast_address)
        or normalized == COORDINATOR_IP
    ):
        raise RuntimeError("role IP must be an eligible 10.0.0.x address; coordinator/network/broadcast addresses are not assignable")
    return normalized


def validate_server_ip(value):
    # Compatibility API retained for existing automation/tests.
    return validate_role_ip(value)


def read_role_registry(registry_file):
    try:
        lines = registry_file.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return set()
    values = {line.split("#", 1)[0].strip() for line in lines}
    return {validate_role_ip(value) for value in values if value}


def write_role_registry(registry_file, values):
    values = {validate_role_ip(value) for value in values}
    registry_file.parent.mkdir(parents=True, exist_ok=True)
    temporary = registry_file.with_name(registry_file.name + ".tmp")
    ordered = sorted(values, key=lambda value: int(ipaddress.ip_address(value)))
    temporary.write_text("".join(value + "\n" for value in ordered), encoding="utf-8")
    os.chmod(temporary, 0o640)
    try:
        shutil.chown(temporary, user="root", group="wireguard-p2p")
    except LookupError:
        pass
    os.replace(temporary, registry_file)


def read_server_registry():
    return read_role_registry(SERVER_REGISTRY_FILE)


def write_server_registry(values):
    write_role_registry(SERVER_REGISTRY_FILE, values)


def read_relay_only_registry():
    return read_role_registry(RELAY_ONLY_REGISTRY_FILE)


def write_relay_only_registry(values):
    write_role_registry(RELAY_ONLY_REGISTRY_FILE, values)


def set_node_role(address, role):
    address = validate_role_ip(address)
    if role not in ("client", "server", "relay_only"):
        raise RuntimeError("role must be one of: client, server, relay_only")
    servers = read_server_registry()
    relay_only = read_relay_only_registry()
    servers.discard(address)
    relay_only.discard(address)
    if role == "server":
        servers.add(address)
    elif role == "relay_only":
        relay_only.add(address)
    write_server_registry(servers)
    write_relay_only_registry(relay_only)
    return address


def explicit_roles():
    result = {address: "server" for address in read_server_registry()}
    for address in read_relay_only_registry():
        result[address] = "relay_only"
    return result


def manage_servers(arguments):
    action = arguments[0] if arguments else "list"
    if action == "list":
        for value in sorted(read_server_registry(), key=lambda item: int(ipaddress.ip_address(item))):
            print(value)
        return
    if action not in ("add", "remove") or len(arguments) != 2:
        raise RuntimeError("usage: wireguard-p2p server [list|add <10.0.0.x>|remove <10.0.0.x>]")
    address = validate_role_ip(arguments[1])
    if action == "add":
        set_node_role(address, "server")
        print("Authorized P2P server {}.".format(address))
        print("On {} run:".format(address))
        print("curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-server.sh | sudo sh")
        return
    if address not in read_server_registry():
        print("Server {} is not authorized.".format(address))
        return
    set_node_role(address, "client")
    print("Removed server role from {}. The node is now a normal client unless another role is assigned.".format(address))


def manage_relay_only(arguments):
    action = arguments[0] if arguments else "list"
    if action == "list":
        for value in sorted(read_relay_only_registry(), key=lambda item: int(ipaddress.ip_address(item))):
            print(value)
        return
    if action not in ("add", "remove") or len(arguments) != 2:
        raise RuntimeError("usage: wireguard-p2p relay-only [list|add <10.0.0.x>|remove <10.0.0.x>]")
    address = validate_role_ip(arguments[1])
    if action == "add":
        set_node_role(address, "relay_only")
        print("Assigned relay_only role to {}.".format(address))
        return
    if address not in read_relay_only_registry():
        print("Node {} is not relay_only.".format(address))
        return
    set_node_role(address, "client")
    print("Removed relay_only role from {}. The node is now a normal client.".format(address))


def manage_roles(arguments):
    action = arguments[0] if arguments else "list"
    if action == "list":
        roles = explicit_roles()
        for address in sorted(roles, key=lambda item: int(ipaddress.ip_address(item))):
            print("{} {}".format(address, roles[address]))
        return
    if action == "get" and len(arguments) == 2:
        address = validate_role_ip(arguments[1])
        print(explicit_roles().get(address, "client"))
        return
    if action == "set" and len(arguments) == 3:
        address = set_node_role(arguments[1], arguments[2])
        print("{} -> {}".format(address, arguments[2]))
        return
    raise RuntimeError("usage: wireguard-p2p role [list|get <IP>|set <IP> <client|server|relay_only>]")


def show_status(role):
    print("role: {}".format(role))
    print("version: {}".format(installed_version(role)))
    services = ["peers-api.service"] if role == "vps" else ["wireguard-p2p-agent.service", "wireguard-p2p-portmap.service"]
    for service in services:
        result = systemctl("is-active", service, check=False)
        print("{}: {}".format(service, result.stdout.strip() or "unknown"))


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if os.geteuid() != 0 and command in ("update", "server", "relay-only", "role"):
        raise RuntimeError("run this command with sudo")
    role = detect_role()
    if os.geteuid() == 0:
        repair_config_permissions(role)
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
    elif command == "server":
        if role != "vps":
            raise RuntimeError("server authorization is managed on the VPS")
        manage_servers(sys.argv[2:])
    elif command == "relay-only":
        if role != "vps":
            raise RuntimeError("relay_only roles are managed on the VPS")
        manage_relay_only(sys.argv[2:])
    elif command == "role":
        if role != "vps":
            raise RuntimeError("node roles are managed on the VPS")
        manage_roles(sys.argv[2:])
    else:
        raise RuntimeError("usage: wireguard-p2p [version|status|update [--force]|server ...|relay-only ...|role ...]")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("wireguard-p2p: {}".format(exc), file=sys.stderr)
        sys.exit(1)
