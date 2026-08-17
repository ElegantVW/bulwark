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

  # Always refresh launchers (old scripts were sticky and broke sudo stories).
  install_launcher() {
    local dest="$1"
    mkdir -p "$(dirname "$dest")"
    cp -f "$WRAP_SRC" "$dest"
    chmod +x "$dest"
  }

  install_launcher "$HOME/bin/bulwark"
  if [[ -d "$HOME/faeos/bin" ]]; then
    install_launcher "$HOME/faeos/bin/bulwark"
  fi

  # sudo uses PATH without ~/bin — plant a copy in /usr/local/bin when allowed.
  if [[ -w /usr/local/bin ]] || sudo -n true 2>/dev/null; then
    if [[ -w /usr/local/bin ]]; then
      install_launcher /usr/local/bin/bulwark
      echo "launcher        → /usr/local/bin/bulwark (sudo-visible)"
    else
      sudo install -m 755 "$WRAP_SRC" /usr/local/bin/bulwark
      echo "launcher        → /usr/local/bin/bulwark (sudo-visible)"
    fi
  else
    echo "note: sudo cannot see ~/bin — raise Aegis with:"
    echo "  sudo $LIB/bulwark aegis apply desktop"
    echo "or once: sudo install -m 755 $WRAP_SRC /usr/local/bin/bulwark"
  fi

  echo "installed engine → $LIB/bulwark"
  echo "launcher        → $HOME/bin/bulwark"
fi
