#!/usr/bin/env bash
# build.sh — produce release bulwark; install into faeOS engine paths
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
cargo build --release
BIN="$ROOT/target/release/bulwark"
echo "built: $BIN"
ls -la "$BIN"

if [[ "${1:-}" == "install" ]]; then
  LIB="$HOME/.local/lib/faeos"
  WRAP_SRC="$ROOT/scripts/bulwark"
  mkdir -p "$LIB" "$HOME/bin"
  cp -f "$BIN" "$LIB/bulwark"
  chmod +x "$LIB/bulwark"

  install_launcher() {
    local dest="$1"
    mkdir -p "$(dirname "$dest")"
    if [[ ! -e "$dest" ]]; then
      cp -f "$WRAP_SRC" "$dest"
      chmod +x "$dest"
      return
    fi
    # Replace leftover prebuilt ELF so ~/bin stays a launcher
    if file -b "$dest" 2>/dev/null | grep -q ELF; then
      cp -f "$WRAP_SRC" "$dest"
      chmod +x "$dest"
    fi
  }

  install_launcher "$HOME/bin/bulwark"
  if [[ -d "$HOME/faeos/bin" ]]; then
    install_launcher "$HOME/faeos/bin/bulwark"
  fi

  echo "installed engine → $LIB/bulwark"
  echo "launcher        → $HOME/bin/bulwark (thin script; never overwrites a good wrapper with ELF)"
fi
