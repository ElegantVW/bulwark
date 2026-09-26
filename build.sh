#!/usr/bin/env bash
# build.sh — build house (bulwark) + glass (seal); install into faeOS engine paths
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
cargo build --release
HOUSE_BIN="$ROOT/target/release/bulwark"
GLASS_BIN="$ROOT/target/release/seal"
echo "built: $HOUSE_BIN"
ls -la "$HOUSE_BIN"
echo "built: $GLASS_BIN"
ls -la "$GLASS_BIN"

if [[ "${1:-}" == "install" ]]; then
  LIB="$HOME/.local/lib/faeos"
  mkdir -p "$LIB" "$HOME/bin"
  cp -f "$HOUSE_BIN" "$LIB/bulwark"
  cp -f "$GLASS_BIN" "$LIB/seal"
  chmod +x "$LIB/bulwark" "$LIB/seal"

  install_launcher() {
    local src="$1" dest="$2"
    mkdir -p "$(dirname "$dest")"
    cp -f "$src" "$dest"
    chmod +x "$dest"
  }

  install_launcher "$ROOT/house/scripts/bulwark" "$HOME/bin/bulwark"
  install_launcher "$ROOT/glass/scripts/seal" "$HOME/bin/seal"
  install_launcher "$ROOT/glass/scripts/seal-login" "$HOME/bin/seal-login"
  install_launcher "$ROOT/glass/scripts/seald" "$HOME/bin/seald"
  if [[ -d "$HOME/faeos/bin" ]]; then
    install_launcher "$ROOT/house/scripts/bulwark" "$HOME/faeos/bin/bulwark"
  fi
  if [[ -d "$HOME/faeOS/bin" ]]; then
    install_launcher "$ROOT/house/scripts/bulwark" "$HOME/faeOS/bin/bulwark"
    install_launcher "$ROOT/glass/scripts/seal" "$HOME/faeOS/bin/seal"
    install_launcher "$ROOT/glass/scripts/seal-login" "$HOME/faeOS/bin/seal-login"
    install_launcher "$ROOT/glass/scripts/seald" "$HOME/faeOS/bin/seald"
  fi

  if [[ -w /usr/local/bin ]] || sudo -n true 2>/dev/null; then
    if [[ -w /usr/local/bin ]]; then
      install_launcher "$ROOT/house/scripts/bulwark" /usr/local/bin/bulwark
      echo "launcher        → /usr/local/bin/bulwark (sudo-visible)"
    else
      sudo install -m 755 "$ROOT/house/scripts/bulwark" /usr/local/bin/bulwark
      echo "launcher        → /usr/local/bin/bulwark (sudo-visible)"
    fi
  else
    echo "note: once for sudo PATH: sudo install -m 755 $ROOT/house/scripts/bulwark /usr/local/bin/bulwark"
  fi

  echo "installed engines → $LIB/bulwark + $LIB/seal"
  echo "launchers         → $HOME/bin/bulwark + $HOME/bin/seal"
  echo
  echo "Next (wall is still down until you raise it):"
  echo "  bulwark aegis apply desktop   # asks for password"
  echo "  bulwark aegis confirm"
  echo "  bulwark install --system      # keep wall after reboot"
  echo "  bulwark                       # look"
  echo "  seal --help                   # glass lock"
fi
