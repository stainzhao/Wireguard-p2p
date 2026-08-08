#!/bin/sh
set -eu

IMAGE=${P2P_PYTHON36_IMAGE:-python:3.6.15-slim-buster}
exec docker run --rm \
  -v "$PWD:/src" \
  -w /src \
  "$IMAGE" \
  sh -c 'python -m compileall -q p2p/wireguard-p2p/linux p2p/wireguard-p2p/vps p2p/wireguard-p2p/manage p2p/wireguard-p2p/bootstrap && python -m unittest discover -s p2p/wireguard-p2p/tests -v'
