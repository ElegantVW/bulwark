# Bulwark

faeOS **host ward**: front-door network lock (**Aegis**), file photo (**Purity**),
open windows (**Sentinel**), sneaky-stuff hunt (**Ward**).

**Seal** (screen lock / greeter) is a different tool — it seals the *glass*.
Bulwark watches the *house*. Do not merge them.

Linux personal host. Source-only (no prebuilt programs in git). Not an
enterprise claim: when Aegis is raised, strangers do not get a free inbound
door, and the shield **does not lie** about that.

## Requirements

- Linux (nftables / netlink)
- Rust stable (`cargo`)
- Root (sudo) to **raise / release** Aegis

## Build & plug into faeOS

```bash
git clone git@github.com:ElegantVW/bulwark.git ~/bulwark
cd ~/bulwark && ./build.sh install
```

| What | Where |
|------|--------|
| Real binary | `~/.local/lib/faeos/bulwark` |
| Public command | `~/bin/bulwark` (thin launcher) |

Install alone does **not** raise the wall. Next:

```bash
# sudo does not see ~/bin — build.sh install plants /usr/local/bin/bulwark.
# If needed once:  sudo install -m 755 ~/bulwark/scripts/bulwark /usr/local/bin/bulwark
# Or call the engine:  sudo ~/.local/lib/faeos/bulwark aegis apply desktop

sudo bulwark aegis apply desktop   # raise Aegis (deadman starts)
bulwark aegis confirm              # keep the lock
sudo bulwark install --system      # restore wall on reboot
bulwark                            # look — mood must tell truth
```

Profiles: **`desktop`** (default laptop — **no SSH**), `strict`, `server-ssh` (opens 22).

Boot restore uses `bulwark-aegis.service` → `aegis restore` with the last
**confirmed** policy under `/var/lib/bulwark/`. Release Aegis clears that so
reboot does not bring the wall back.

Full engines contract: [faeOS docs/engines.md](https://github.com/ElegantVW/faeOS/blob/main/docs/engines.md).

## Voice (humans)

| You say | Machine |
|---------|---------|
| bare `bulwark` | TUI — full look at the shield |
| `bulwark status` / look | one-shot plain report |
| Raise Aegis / Aegis protect | `sudo bulwark aegis apply desktop` + confirm |
| Release Aegis | `sudo bulwark aegis undo` |
| Ward report | `bulwark ward` |
| Purity photo | `bulwark purity baseline` |

No devops hospital words. All ages.

## SAFE / CARE / DANGER

- **SAFE** — Aegis ON in the kernel, Purity photo OK, no Ward crises, no fae AI ports on the LAN.
- **CARE** — wall off, cannot check wall, no photo yet, soft findings, or public windows.
- **DANGER** — Ward serious, files changed, or a magic service port faces the whole network.

Missing wall ⇒ **never** SAFE.

## CLI (scripts)

```
bulwark                  # TUI
bulwark status|ports|ward
bulwark aegis show|status|apply <profile>|confirm|undo
bulwark purity baseline|check
bulwark install|uninstall [--purge]
bulwark tour
```

## Break-glass (operator)

If a bad raise locks you out of something you need, from a local console:

```bash
sudo bulwark aegis undo
# or: sudo nft delete table inet bulwark
```

## State

`$XDG_DATA_HOME/faeos/bulwark/` (or `BULWARK_DIR`).

## License

MIT — see [LICENSE](LICENSE).
