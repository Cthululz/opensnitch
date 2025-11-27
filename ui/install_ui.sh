#!/usr/bin/env bash
set -euo pipefail

# Build and install the OpenSnitch UI from this repo.
# Installs into /usr/local and fixes the launcher shebang.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UI_DIR="${ROOT_DIR}/ui"
DIST_WHEEL="${UI_DIR}/dist/opensnitch_ui-1.8.0-py3-none-any.whl"
TMP="/tmp/opensnitch-wheel"

main() {
  cd "$UI_DIR"

  if [[ ! -x ".venv/bin/python" ]]; then
    echo "Missing .venv. Create one with: python3 -m venv .venv" >&2
    exit 1
  fi

  echo "Building wheel..."
  .venv/bin/python -m build --wheel --no-isolation

  echo "Unpacking wheel..."
  rm -rf "$TMP"
  unzip -o "$DIST_WHEEL" -d "$TMP" >/dev/null

  echo "Removing previous install..."
  sudo rm -rf /usr/local/lib/python3.12/dist-packages/opensnitch \
              /usr/local/lib/python3.12/dist-packages/opensnitch_ui-*.dist-info \
              /usr/local/bin/opensnitch-ui

  echo "Installing package..."
  sudo cp -r "$TMP/opensnitch" /usr/local/lib/python3.12/dist-packages/
  sudo cp -r "$TMP/opensnitch_ui-1.8.0.dist-info" /usr/local/lib/python3.12/dist-packages/

  echo "Installing launcher..."
  sudo sh -c 'sed "1s|^#\\!.*|#!/usr/bin/python3|" '"$TMP"'/opensnitch_ui-1.8.0.data/scripts/opensnitch-ui > /usr/local/bin/opensnitch-ui'
  sudo chmod +x /usr/local/bin/opensnitch-ui

  echo "Installing desktop resources..."
  sudo cp -r "$TMP/usr/share/applications/opensnitch_ui.desktop" /usr/share/applications/
  sudo cp -r "$TMP/usr/share/icons/hicolor" /usr/share/icons/
  sudo cp -r "$TMP/usr/share/metainfo/io.github.evilsocket.opensnitch.appdata.xml" /usr/share/metainfo/
  sudo cp -r "$TMP/usr/share/kservices5/kcm_opensnitch.desktop" /usr/share/kservices5/

  echo "Done. You can run: opensnitch-ui"
}

main "$@"
