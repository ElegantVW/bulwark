# TRUST — Bulwark must not be the attacker

> Goal path **D**: someday impress a cold security reviewer.  
> First gate: **the shield itself is not a privilege escalation, persistence, or lying surface.**

This document is for humans and agents. Update it when install paths, elevation, or state layout change.

---

## Threat: Bulwark-as-attacker

| Abuse | How it could happen today | Desired law |
|-------|---------------------------|-------------|
| **Binary replacement** | Writable `~/…/bulwark` or world-writable `/usr/local/lib/faeos/bulwark` | Engine under root-owned path after `install --system`; Purity watches it; document checksum ritual |
| **State poisoning** | Malicious `confirmed_policy.aegis` / pending policy → restore opens the house or locks user out | Validate policy DSL; only restore **confirmed** text; root-owned `/var/lib/bulwark` mode `0600`/`0640` root |
| **sudo helper abuse** | Tricking user into elevating a trojaned `current_exe` | Elevate only known install paths; prefer `/usr/local/lib/faeos/bulwark` when present; never elevate relative weird paths blindly |
| **HOME / SUDO_USER confusion** | Writing secrets or policy under `/root` or wrong uid | Always `SUDO_USER` data dir + chown (implemented); tests must cover this |
| **Deadman / undo DoS** | Attacker with local code triggers undo or blocks confirm | Confirm marker user-only; undo still needs CAP; document; later: auth for release |
| **Lying SAFE** | Cosplay confidence → user disables other defenses | Posture math stays honest (missing wall ≠ SAFE) |
| **Log / stderr leaks** | Passwords, tokens in debug | Never print passwords; `FAE_DEBUG` may show OS errors only, not secrets |
| **Installer persistence** | `bulwark-aegis.service` runs attacker binary at boot | Unit `ExecStart=` absolute path to root-owned engine; `systemctl cat` in adversarial checklist |

---

## Trust boundaries (current architecture)

```
[user] --launcher(~/bin)--> [engine user or sudo]
                              |-- state: ~/.local/share/faeos/bulwark/  (user)
                              |-- boot:  /var/lib/bulwark/             (root)
                              |-- unit:  /etc/systemd/system/bulwark-aegis.service
                              \-- kernel nf_tables table `bulwark`
```

- **User** can mess their own state and launcher.  
- **Root** (via sudo) can change kernel table + system unit + `/var/lib/bulwark`.  
- **Network attacker** should not talk to Aegis control plane (no daemon listener for apply).

---

## Hardening backlog (small steps — implement later, track here)

Priority order for “not the attacker”:

1. **Permissions audit script / checklist** — modes of engine, unit, `/var/lib/bulwark`, user aegis dir  
2. **Elevate only absolute trusted binary** — if `/usr/local/lib/faeos/bulwark` exists and is root-owned, sudo that path  
3. **Policy allowlist** — restore rejects unknown verbs / oversized files  
4. **Purity default roots** already include `~/.local/lib/faeos` — extend to `/usr/local/lib/faeos/bulwark` when present  
5. **Release / checksum** — documented `sha256sum` of release binary (signed releases later)  
6. **No duplicate apply stacks** — flush/replace table cleanly so review of live rules is readable  

---

## Agent checklist before merging privilege changes

- [ ] Does elevate still avoid storing passwords?  
- [ ] Does state land under invoking user, not root home?  
- [ ] Are new files chowned or created with correct uid?  
- [ ] Can a user without root still run look/status/ward/purity?  
- [ ] Did you add/adjust a row in [ADVERSARIAL.md](ADVERSARIAL.md)?  
- [ ] Error strings follow faeos `docs/error-voice.md`?

---

## Explicit non-goals (trust edition)

- Secure Boot / TPM attestation (future OS pillar, not Bulwark vNow)  
- Stopping root who already owns the box (root wins; we slow and detect)  
- Hiding from the user what Bulwark does  
