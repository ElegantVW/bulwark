# AGENTS.md — Bulwark

Canonical repo: `ElegantVW/bulwark` → `~/bulwark`.  
faeOS keeps only a thin launcher; do **not** vendor this tree back into `faeos/`.

## North star (locked)

**Long-term:** Bulwark aims to survive **cold professional security review** (path **D**), and someday be the default host ward for most faeOS users — **small steps**, evidence each iteration.

**Near-term:** personal Linux host ward that **does not lie**, **does not become the attacker**, and is **attacked in a sandbox** before big claims.

**Not claims (yet):** nation-state defense, antivirus, “nobody can own this box”, multi-OS, EY-grade product.

## Product laws

| Law | Rule |
|-----|------|
| Voice | All-ages, wards/Aegis/Purity — see faeos `docs/cli-voice.md` + `docs/error-voice.md`. No `doctor`. |
| Seal | Separate. Glass vs house. Never merge. |
| Packages | No runtime dep on `nft`/`ufw`/firewalld for apply — raw netlink to kernel nf_tables. |
| Honesty | Missing/unknown wall ⇒ never SAFE. |
| Secrets | Elevate via sudo password prompt; never store/print passwords. |
| State | Under **invoking user** (`SUDO_USER`), not `/root/...`; chown back after elevate. |

## Trust docs (read before changing privilege paths)

- [docs/TRUST.md](docs/TRUST.md) — Bulwark must not *be* the attack  
- [docs/ADVERSARIAL.md](docs/ADVERSARIAL.md) — sandbox attack program  

## Iteration rule

1. Update these docs when behavior or threat assumptions change.  
2. Prefer a failing adversarial checklist item over a new TUI feature.  
3. Test after each change (unit tests + at least one hostile check from ADVERSARIAL).  
4. Push with messages that say what **evidence** exists, not only what shipped.

## Layout

| Path | Role |
|------|------|
| `policy/*.aegis` | Bundled profiles (`desktop` = no SSH) |
| `src/aegis/` + `src/netlink/` | Raise/release wall (kernel) |
| `src/words.rs` | Posture / exposure / error-facing honesty |
| `src/paths.rs` | XDG + SUDO_USER + chown |
| `scripts/bulwark` | Thin launcher |

## Quick verify

```bash
cargo test
bulwark status
bulwark aegis apply desktop && bulwark aegis confirm
# sandbox: see docs/ADVERSARIAL.md
```
