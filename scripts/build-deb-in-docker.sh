#!/usr/bin/env bash
# Build opensnitch daemon and UI deb packages inside a disposable Debian container.
set -euo pipefail

IMAGE="${IMAGE:-debian:12}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run this script" >&2
  exit 1
fi

docker run --rm \
  -v "${ROOT}":/src \
  -w /src \
  "${IMAGE}" \
  bash -lc '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  build-essential debhelper-compat debhelper dh-golang golang golang-any git ca-certificates pkg-config \
  golang-github-cilium-ebpf-dev \
  golang-github-vishvananda-netlink-dev golang-github-google-gopacket-dev golang-github-fsnotify-fsnotify-dev \
  golang-github-google-nftables-dev golang-github-google-uuid-dev golang-github-varlink-go-dev golang-golang-x-exp-dev \
  golang-golang-x-net-dev golang-google-grpc-dev golang-goprotobuf-dev libnetfilter-queue-dev libmnl-dev \
  pyqt6-dev-tools python3-grpc-tools python3-all dh-python python3-pyqt6 python3-pyqt6.qtsvg \
  python3-pyinotify python3-grpcio python3-protobuf python3-packaging python3-slugify python3-notify2 \
  xdg-user-dirs gtk-update-icon-cache

cd /src
[ -L debian ] || ln -s utils/packaging/daemon/deb/debian debian
dpkg-buildpackage -us -uc -b

cd /src/utils/packaging/ui
dpkg-buildpackage -us -uc -b
'
