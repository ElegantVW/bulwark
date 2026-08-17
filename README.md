# Bulwark

faeOS first-party host protection: firewall (**Aegis**), integrity (**Purity**),
listeners (**Sentinel**), and hostile-pattern hunt (**Ward**).

Rust single binary. **Zero** runtime security-product package deps — no ufw,
nft CLI, clamav, or fail2ban. Kernel talk is in-tree `NETLINK_NETFILTER`
(nf_tables).

Source-only repo (no prebuilt programs in git).

## Requirements

- Linux (nftables / netlink)
- Rust stable (`cargo`)
- Root for `aegis apply` / `undo`

## Build & install (plug-and-play with faeOS)

```bash
git clone git@github.com:ElegantVW/bulwark.git ~/bulwark
cd ~/bulwark && ./build.sh install
```

That writes:

| What | Where |
|------|--------|
| Real binary | `~/.local/lib/faeos/bulwark` |
| Public command | `~/bin/bulwark` (thin launcher) |

If faeOS is installed, its `bulwark` wrapper finds the engine automatically.
You can also only `cargo build --release` and keep the tree at `~/bulwark` —
launchers look there too.

### Discovery order

1. `$BULWARK_BIN`
2. `~/.local/lib/faeos/bulwark`
3. `~/bulwark/target/release/bulwark`

Full contract: [faeOS docs/engines.md](https://github.com/ElegantVW/faeOS/blob/main/docs/engines.md).

## CLI

```
bulwark                  # friendly TUI (default)
bulwark status|ports|ward
bulwark aegis show|status|apply <profile>|confirm|undo
bulwark purity baseline|check
bulwark install|uninstall [--purge]
bulwark tour
```

Profiles (embedded): `desktop`, `strict`, `server-ssh`.

### Firewall apply (root)

```bash
sudo bulwark aegis apply desktop
bulwark aegis confirm    # within deadman window (~90s)
sudo bulwark aegis undo
```

## Layers

| Layer | What |
|-------|------|
| **Sentinel** | `/proc/net/*` listeners → PID/comm |
| **Aegis** | Policy → nf_tables table `bulwark`; apply/undo; deadman confirm |
| **Purity** | SHA-256 baselines; change / SUID detection |
| **Ward** | Hostile patterns (writable PATH, LD_PRELOAD, deleted exe, …) |

## State

`$XDG_DATA_HOME/faeos/bulwark/` (or `BULWARK_DIR`).

## faeOS

Part of the [faeOS](https://github.com/ElegantVW/faeOS) terminal ecosystem.
Canonical tree is this repo (`ElegantVW/bulwark`), not a monorepo vendor copy.

```bash
git clone git@github.com:ElegantVW/faeOS.git ~/faeos
cd ~/faeos && ./install.sh
# then build bulwark as above — seamless
```

## License

MIT — see [LICENSE](LICENSE).
