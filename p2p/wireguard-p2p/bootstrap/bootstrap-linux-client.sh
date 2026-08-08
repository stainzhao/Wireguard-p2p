#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Run through sudo: curl ... | sudo sh" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required." >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required." >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required." >&2; exit 1; }
BASE=${P2P_UPDATE_BASE:-http://10.0.0.1:8899/updates}
WG_INTERFACE=${P2P_INTERFACE:-${1:-wg0}}
case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "Unsupported Linux architecture: $(uname -m)" >&2; exit 1 ;;
esac
FILE="wireguard-p2p-linux-$ARCH.tar.gz"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
curl -fsSL "$BASE/$FILE" -o "$TMP/$FILE"
curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
awk -v f="$FILE" '$2 == f {print; found=1} END {if (!found) exit 1}' "$TMP/SHA256SUMS" > "$TMP/check"
(cd "$TMP" && sha256sum -c check)
mkdir "$TMP/pkg"
tar -xzf "$TMP/$FILE" -C "$TMP/pkg"
"$TMP/pkg/install.sh" --interface "$WG_INTERFACE"
