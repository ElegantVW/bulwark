# ADVERSARIAL — sandbox attack program

> After TRUST (Bulwark is not the attacker), **attack Bulwark in a sandbox**.  
> Pass/fail with evidence. No production laptop as the first target.

North star **D**: cold reviewer. Method: **small cards**, one environment, iterate.

---

## Sandbox choice (pick one)

| Environment | Use when | Notes |
|-------------|----------|-------|
| **A. Dedicated VM** (Recommended) | Default for LAN + reboot tests | Snapshot before raise; throw away if locked out |
| **B. Second physical machine** | Brother / cold clone | Matches real faeOS install story |
| **C. netns + veth** | Fast loop for port/bind tests | Weak for “full OS”; good for Aegis packet checks |
| **Docker** | Avoid for Aegis | Netlink/nftables + CAP often lies; not a real host |

**Law:** never run destructive adversarial cards on the daily driver first.

### Minimal VM recipe (agent-facing)

1. Fresh Arch/Debian VM, snapshot `clean`.  
2. Install Rust + clone `ElegantVW/bulwark` + `./build.sh install`.  
3. Optional: clone faeOS and install launchers.  
4. Snapshot `pre-aegis`.  
5. Run cards below; record PASS/FAIL in a table (date, commit SHA).  
6. Revert to snapshot between catastrophic fails.

---

## Scoring

| Result | Meaning |
|--------|---------|
| **PASS** | Expected defense held; note commit SHA |
| **FAIL** | Bypass or lie observed; file issue / fix before new features |
| **WARN** | Held but unsafe UX / missing warning |
| **N/A** | Card needs hardware/peer not available |

Every FAIL blocks “professional review ready” language in README.

---

## Card deck — Tier 0: Trust (Bulwark ≠ attacker)

Run on sandbox **before** celebrating Aegis.

| ID | Attack | Expect | How |
|----|--------|--------|-----|
| T0 | World-writable engine | FAIL if mode allows user overwrite of system engine | `ls -la /usr/local/lib/faeos/bulwark` after `install --system` — root owned, not `o+w` |
| T1 | Unit points at user home binary | FAIL if ExecStart is under `/home/...` | `systemctl cat bulwark-aegis.service` |
| T2 | sudo apply leaves root files in user tree | FAIL if confirm EACCES | apply as elevated → `ls -la ~/.local/share/faeos/bulwark/aegis` all user-owned → `bulwark aegis confirm` works |
| T3 | Malicious relative cwd elevate | WARN/FAIL if sudo runs unexpected path | From weird cwd, `bulwark aegis apply`; ensure elevated exe is realpath of install |
| T4 | Oversized / garbage policy restore | FAIL if restore applies non-DSL junk from `/var/lib/bulwark` | (implement allowlist later; today document WARN) |

---

## Card deck — Tier 1: Aegis vs network stranger

Needs: VM with second interface or peer on same LAN (phone / host).

| ID | Attack | Expect | How |
|----|--------|--------|-----|
| A0 | Cold raise | Wall up, desktop, no SSH allow | `apply desktop` + `confirm`; `nft list table inet bulwark` |
| A1 | Peer TCP to random high port | Connection refused / timeout | From peer: `nc -vz $VM_IP 12345` |
| A2 | Peer TCP to 22 | Fail on desktop profile | Peer: `nc -vz $VM_IP 22` |
| A3 | Peer TCP to 8080–8091 | Fail while wall up | Even if something listens on lo only |
| A4 | Bind `0.0.0.0:8080` on VM | Posture DANGER / magic door | `python -m http.server 8080 --bind 0.0.0.0` then `bulwark status` |
| A5 | Reboot persistence | Table exists; **full** policy (≥ localhost AI allows or intentional strict) | reboot; `systemctl status bulwark-aegis`; list table |
| A6 | Undo then reboot | Table **absent** | `aegis undo`; reboot; list table → missing |
| A7 | Deadman no confirm | Wall auto-releases | apply; wait >90s without confirm; table gone |
| A8 | IPv6 peer (if available) | Same as A1–A3 on v6 | Peer `nc -vz $VM_IP6 …` |

---

## Card deck — Tier 2: Bypass / confuse

| ID | Attack | Expect | How |
|----|--------|--------|-----|
| B0 | Add second nft table allowing all | WARN: Bulwark may not own whole stack | Attacker root: `nft add table …`; document limitation — Bulwark owns table `bulwark`, not all netfilter |
| B1 | `nft flush table inet bulwark` as root | Wall gone until restore/reboot | Expected: root wins; SAFE must not claim wall if Missing |
| B2 | Replace system binary then reboot | FAIL if unit runs attacker payload unnoticed | Copy evil to ExecStart path (sandbox only!); reboot; detect via Purity / checksum ritual |
| B3 | Lie: status SAFE with wall down | FAIL | Stop unit; delete table; `bulwark status` mood |
| B4 | Duplicate rules / unreadable policy | WARN for reviewers | list table; cleanup is backlog |

---

## Card deck — Tier 3: Later (do not claim until written)

- Outbound control / per-app  
- Non-root local attacker without sudo (user namespace tricks)  
- Secure Boot / measured boot  
- Formal fuzzing of policy parser / netlink builders  

---

## Record template (copy per run)

```text
Date:
Commit:
Sandbox: VM / bare / netns
Tier cards run:
T0 __  T1 __  T2 __  T3 __  T4 __
A0 __  A1 __  A2 __  A3 __  A4 __  A5 __  A6 __  A7 __  A8 __
B0 __  B1 __  B2 __  B3 __  B4 __
Notes:
Next fix:
```

Store runs under `docs/adversarial-runs/` (optional; may gitignore secrets/IPs) or outside the repo.

---

## Order of work (agents)

1. Keep [TRUST.md](TRUST.md) accurate.  
2. Run **Tier 0** on a VM.  
3. Fix FAILs (permissions / elevate path / ownership).  
4. Run **Tier 1** with a peer.  
5. Only then expand features.  
6. Never mark README “professional-grade” until Tier 0+1 are mostly PASS with SHAs.
