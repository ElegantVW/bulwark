# AGENTS.md — Bulwark

Canonical repo: `ElegantVW/bulwark` → `~/bulwark` (house + glass).
faeOS keeps only thin launchers; do **not** vendor this tree back into `faeos/`.

## North star (locked)

**Long-term:** Bulwark aims to survive **cold professional security review** (path **D**), and someday be the default host ward for most faeOS users — **small steps**, evidence each iteration.

**Near-term:** personal Linux host ward that **reports measurements with named sources, and says UNKNOWN when it cannot verify**, **does not become the attacker**, and is **attacked in a sandbox** before big claims.

**Not claims (yet):** nation-state defense, antivirus, “nobody can own this box”, multi-OS, EY-grade product.

## Product laws

| Law | Rule |
|-----|------|
| Voice | All-ages, wards/Aegis/Purity — see faeos `docs/cli-voice.md` + `docs/error-voice.md`. No `doctor`. |
| Seal | Same repo, separate domains. Glass (`glass/`, screen lock) vs house (`house/`, host ward). Never share privilege, state, or units. |
| Packages | No runtime dep on `nft`/`ufw`/firewalld for apply — raw netlink to kernel nf_tables. |
| Honesty | Missing/unknown wall ⇒ never SAFE. |
| Secrets | Elevate via sudo password prompt; never store/print passwords. |
| State | Under **invoking user** (`SUDO_USER`), not `/root/...`; chown back after elevate. |

## Trust docs (read before changing privilege paths)

- [house/docs/TRUST.md](house/docs/TRUST.md) — Bulwark must not *be* the attack
- [house/docs/ADVERSARIAL.md](house/docs/ADVERSARIAL.md) — sandbox attack program (house only; glass uses lock-bypass tests in `glass/docs/seal.md`)  

## Iteration rule

1. Update these docs when behavior or threat assumptions change.  
2. Prefer a failing adversarial checklist item over a new TUI feature.  
3. Test after each change (unit tests + at least one hostile check from ADVERSARIAL).  
4. Push with messages that say what **evidence** exists, not only what shipped.

## Layout

| Path | Role |
|------|------|
| `house/policy/*.aegis` | Bundled profiles (`desktop` = no SSH) |
| `house/src/aegis/` + `house/src/netlink/` | Raise/release wall (kernel) |
| `house/src/words.rs` | Posture / exposure / error-facing honesty |
| `house/src/paths.rs` | XDG + SUDO_USER + chown |
| `house/scripts/bulwark` | Thin launcher (house) |
| `glass/src/` | Seal screen lock / greeter (X11 + PAM, no netlink) |
| `glass/scripts/seal*` | Thin launchers (glass) |
| `glass/systemd/seald.service` | User idle-lock daemon |
| `glass/pam/seal.pam` | PAM stack for glass |

Boundary: no shared Rust code between `house/` and `glass/`; separate state (`house`: `~/.local/share/faeos/bulwark` + `/var/lib/bulwark`; `glass`: `~/.config/pixie/seal.json`); separate units.

## Quick verify

```bash
cargo test
bulwark status
bulwark aegis apply desktop && bulwark aegis confirm
# sandbox: see house/docs/ADVERSARIAL.md
# glass: see glass/docs/seal.md
```
