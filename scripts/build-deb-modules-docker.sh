#!/usr/bin/env bash
# Build opensnitch daemon and UI deb packages using module mode inside a Debian container with Go >=1.22.
set -euo pipefail

IMAGE="${IMAGE:-debian:12}"
GO_VERSION="${GO_VERSION:-1.23.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run this script" >&2
  exit 1
fi

docker run --rm \
  -e GO_VERSION="${GO_VERSION}" \
  -v "${ROOT}":/src \
  -w /src \
  "${IMAGE}" \
  bash -lc '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  wget \
  rsync \
  build-essential ca-certificates pkg-config git \
  protobuf-compiler \
  python3 python3-venv python3-pip python3-setuptools python3-wheel \
  libnetfilter-queue-dev libmnl-dev \
  debhelper dh-python dh-make fakeroot

# Install Go toolchain
GO_VERSION="${GO_VERSION:-1.23.0}"
cd /tmp
wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
export PATH=/usr/local/go/bin:$PATH

# Use module mode explicitly.
export GO111MODULE=on
export GOPROXY=https://proxy.golang.org,direct

# Clean any previous build artifacts and ensure UI tree is writable.
rm -rf _build debian ui/build ui/dist ui/*.egg-info || true

# Build daemon binaries (module mode).
cd /src/daemon
go mod tidy
go build -o /src/opensnitchd .

# Build UI wheel inside a venv in a temp copy (avoid host perms issues).
python3 -m venv /tmp/venv
source /tmp/venv/bin/activate
pip install --upgrade pip
pip install --upgrade build wheel grpcio-tools PyQt6 PyQt6-Qt6 PyQt6-sip python-slugify packaging pyinotify notify2
rm -rf /tmp/ui-src
rsync -a /src/ui/ /tmp/ui-src/
cd /tmp/ui-src
/tmp/venv/bin/python -m grpc_tools.protoc -I/src/proto --python_out=opensnitch/proto --grpc_python_out=opensnitch/proto /src/proto/ui.proto
/tmp/venv/bin/python -m build --wheel
UI_WHL=$(ls /tmp/ui-src/dist/*.whl)

# Optionally assemble debs (simple checkinstall-style, not dh_golang). We package the built binaries manually.
cd /src

mkdir -p /tmp/pkg/daemon/DEBIAN
cat > /tmp/pkg/daemon/DEBIAN/control <<EOF
Package: opensnitch
Version: 1.8.0-custom
Section: net
Priority: optional
Architecture: amd64
Maintainer: local <local@localhost>
Description: Opensnitch daemon (module-mode build)
EOF
install -Dm755 /src/opensnitchd /tmp/pkg/daemon/usr/bin/opensnitchd
dpkg-deb --build /tmp/pkg/daemon /src/opensnitch_daemon_module.deb

mkdir -p /tmp/pkg/ui/DEBIAN
cat > /tmp/pkg/ui/DEBIAN/control <<EOF
Package: python3-opensnitch-ui
Version: 1.8.0-custom
Section: net
Priority: optional
Architecture: all
Maintainer: local <local@localhost>
Description: Opensnitch UI (module-mode build)
Depends: python3, python3-pyqt6, python3-grpcio, python3-protobuf, python3-packaging, python3-slugify, python3-pyinotify, python3-notify2
EOF
/tmp/venv/bin/pip install --prefix=/tmp/pkg/ui/usr "$UI_WHL"
dpkg-deb --build /tmp/pkg/ui /src/opensnitch_ui_module.deb
'
