//! Bulwark — faeOS first-party host protection.
//! Zero runtime package dependencies (no ufw/nft/clamav). Kernel via netlink + /proc.

mod aegis;
mod netlink;
mod paths;
mod purity;
mod sentinel;
mod tui;
mod tutorial;
mod ward;
mod words;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "bulwark",
    about = "faeOS Bulwark — host firewall, integrity, and hunt (first-party, zero package deps)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Aggregate posture report
    Status,
    /// Listening sockets + owning processes (/proc only)
    Ports,
    /// Sentinel snapshot once
    Sentinel,
    /// Aegis firewall engine
    Aegis {
        #[command(subcommand)]
        action: AegisCmd,
    },
    /// File integrity
    Purity {
        #[command(subcommand)]
        action: PurityCmd,
    },
    /// Hostile pattern hunt
    Ward,
    /// Install data dirs + user timer unit
    Install {
        #[arg(long)]
        system: bool,
    },
    /// Remove units; --purge wipes state
    Uninstall {
        #[arg(long)]
        purge: bool,
    },
    /// Interactive TUI (friendly home screen)
    Tui,
    /// Short first-time style tour (themed names explained)
    Tour,
    /// Alias for Tour
    Tutorial,
}

#[derive(Subcommand, Debug)]
enum AegisCmd {
    /// Show whether netlink is available + current policy summary
    Status,
    /// Apply a bundled profile (desktop|strict|server-ssh) with deadman
    Apply {
        profile: String,
        /// Seconds before auto-undo if not confirmed (0=disable deadman)
        #[arg(long, default_value_t = 90)]
        deadman: u64,
        /// Skip deadman (dangerous)
        #[arg(long)]
        no_deadman: bool,
    },
    /// Confirm apply (cancel deadman undo); keep wall after reboot if system install
    Confirm,
    /// Re-apply last confirmed policy (boot / no deadman)
    Restore,
    /// Remove bulwark nf_tables table
    Undo {
        #[arg(long, default_value = "bulwark")]
        table: String,
    },
    /// Print policy file / profile without applying
    Show {
        #[arg(default_value = "desktop")]
        profile: String,
    },
}

#[derive(Subcommand, Debug)]
enum PurityCmd {
    Baseline,
    Check,
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("bulwark: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Commands::Tui) {
        Commands::Status => cmd_status(),
        Commands::Ports | Commands::Sentinel => cmd_ports(),
        Commands::Aegis { action } => cmd_aegis(action),
        Commands::Purity { action } => cmd_purity(action),
        Commands::Ward => {
            print!("{}", ward::format_findings(&ward::hunt()));
            Ok(())
        }
        Commands::Install { system } => cmd_install(system),
        Commands::Uninstall { purge } => cmd_uninstall(purge),
        Commands::Tui => tui::run(),
        Commands::Tour | Commands::Tutorial => cmd_tour(),
    }
}

fn cmd_tour() -> Result<()> {
    let _ = paths::ensure_dirs()?;
    // Force tour even if already done: remove marker temporarily? Plan says re-run shows tour.
    // Don't delete marker permanently until finished — tour marks done at end.
    let mut term = tui::Term::new()?;
    let ok = tutorial::run_tour(&mut term)?;
    term.restore()?;
    if ok {
        println!("✦ tour finished — open: bulwark");
    }
    Ok(())
}

fn cmd_status() -> Result<()> {
    let _ = paths::ensure_dirs()?;
    let p = words::gather_posture();
    let listeners = sentinel::scan_listeners();
    let (public, exposed_ai) = words::exposure_counts(&listeners);

    println!("✦ Bulwark — look");
    println!("  mood:     {}", p.mood.banner());
    println!("  Aegis:    {}", p.aegis_line);
    println!("  Purity:   {}", p.purity_line);
    println!("  Ward:     {}", p.ward_line);
    println!("  Sentinel: {}", p.sentinel_line);
    if exposed_ai > 0 {
        println!(
            "  note:     {exposed_ai} fae port(s) face the network — not SAFE until fixed"
        );
    } else if public > 0 {
        println!("  note:     {public} window(s) strangers could knock on");
    }
    println!("  data:     {}", paths::data_dir().display());
    if p.mood == words::Mood::Safe {
        println!("  (wall ON, photo OK, no stranger magic doors)");
    } else if matches!(
        aegis::table_state("bulwark", aegis::policy::Family::Inet),
        aegis::TableState::Missing
    ) {
        println!("  next:     raise Aegis — sudo bulwark aegis apply desktop");
        println!("            then: bulwark aegis confirm");
    }
    Ok(())
}

fn aegis_state_line() -> String {
    let p = paths::aegis_snapshot_path();
    let snap = fs::read_to_string(&p)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    let table = snap
        .as_ref()
        .and_then(|v| v.get("table").and_then(|x| x.as_str()).map(String::from))
        .unwrap_or_else(|| "bulwark".into());
    match aegis::table_state(&table, aegis::policy::Family::Inet) {
        aegis::TableState::Exists => {
            let ts = snap
                .as_ref()
                .and_then(|v| v.get("ts").and_then(|x| x.as_i64()))
                .unwrap_or(0);
            format!("applied table={table} ts={ts} (verified in kernel)")
        }
        aegis::TableState::Missing => {
            "no table in kernel — lock OFF (snapshot may be stale)".into()
        }
        aegis::TableState::Unknown => {
            "cannot verify without root (try: sudo bulwark aegis status)".into()
        }
    }
}

fn cmd_ports() -> Result<()> {
    let list = sentinel::scan_listeners();
    print!("{}", sentinel::format_table(&list));
    let snap = sentinel::snapshot();
    let _ = paths::ensure_dirs();
    let _ = sentinel::save_snapshot(&paths::sentinel_last_path(), &snap);
    Ok(())
}

fn cmd_aegis(action: AegisCmd) -> Result<()> {
    let _ = paths::ensure_dirs()?;
    match action {
        AegisCmd::Status => {
            println!(
                "aegis netlink: {}",
                if aegis::aegis_available() {
                    "available"
                } else {
                    "unavailable (need CAP_NET_ADMIN to apply)"
                }
            );
            let pol_path = paths::policy_path();
            if pol_path.is_file() {
                let text = fs::read_to_string(&pol_path)?;
                let p = aegis::parse_policy(&text)?;
                print!("{}", aegis::policy_summary(&p));
            } else {
                println!("no active policy file at {}", pol_path.display());
                println!("try: bulwark aegis show desktop");
            }
            println!("{}", aegis_state_line());
            Ok(())
        }
        AegisCmd::Show { profile } => {
            let text = aegis::load_bundled_profile(&profile)?;
            println!("{text}");
            Ok(())
        }
        AegisCmd::Apply {
            profile,
            deadman,
            no_deadman,
        } => {
            let text = aegis::load_bundled_profile(&profile)?;
            let res = aegis::apply_policy_text(&text, &paths::aegis_snapshot_path())
                .context("aegis apply failed")?;
            fs::write(paths::policy_path(), &text)?;
            fs::write(paths::pending_policy_path(), &text)?;
            // unconfirmed until confirm — boot restore must not use this yet
            let _ = fs::remove_file(paths::confirmed_policy_path());
            println!("✦ {}", res.message);
            if !no_deadman && deadman > 0 {
                println!(
                    "✦ deadman: confirm within {deadman}s or rules auto-undo:\n  bulwark aegis confirm"
                );
                let secs = deadman;
                let marker = paths::data_dir().join("aegis").join("confirm.ok");
                let _ = fs::remove_file(&marker);
                deadman_spawn(secs, marker)?;
            } else {
                confirm_policy_persist()?;
            }
            Ok(())
        }
        AegisCmd::Confirm => {
            let marker = paths::data_dir().join("aegis").join("confirm.ok");
            fs::write(&marker, b"ok\n")?;
            confirm_policy_persist()?;
            println!("✦ Aegis kept — front door lock stays up");
            println!("  (for reboot: sudo bulwark install --system)");
            Ok(())
        }
        AegisCmd::Restore => cmd_aegis_restore(),
        AegisCmd::Undo { table } => {
            // deadman helper path
            if let Ok(secs) = std::env::var("BULWARK_DEADMAN") {
                let secs: u64 = secs.parse().unwrap_or(90);
                let marker = std::env::var("BULWARK_CONFIRM_PATH")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| paths::data_dir().join("aegis").join("confirm.ok"));
                for _ in 0..secs {
                    if marker.is_file() {
                        eprintln!("bulwark deadman: confirmed — keep rules");
                        return Ok(());
                    }
                    thread::sleep(Duration::from_secs(1));
                }
                eprintln!("bulwark deadman: no confirm — undoing table {table}");
            }
            aegis::flush_bulwark(&table, aegis::policy::Family::Inet)
                .context("undo/flush")?;
            let _ = fs::remove_file(paths::aegis_snapshot_path());
            let _ = fs::remove_file(paths::data_dir().join("aegis").join("confirm.ok"));
            let _ = fs::remove_file(paths::pending_policy_path());
            let _ = fs::remove_file(paths::confirmed_policy_path());
            let _ = fs::remove_file(paths::system_confirmed_policy_path());
            println!("✦ Aegis released — table '{table}' removed (will not restore on boot)");
            Ok(())
        }
    }
}

fn confirm_policy_persist() -> Result<()> {
    let pending = paths::pending_policy_path();
    let text = if pending.is_file() {
        fs::read_to_string(&pending)?
    } else if paths::policy_path().is_file() {
        fs::read_to_string(paths::policy_path())?
    } else if paths::confirmed_policy_path().is_file() {
        fs::read_to_string(paths::confirmed_policy_path())?
    } else {
        bail!("nothing to confirm — raise Aegis first (aegis apply)");
    };
    fs::write(paths::confirmed_policy_path(), &text)?;
    if nix_euid_root() {
        let _ = fs::create_dir_all(paths::system_state_dir());
        let _ = fs::write(paths::system_confirmed_policy_path(), &text);
    }
    Ok(())
}

fn nix_euid_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn cmd_aegis_restore() -> Result<()> {
    let _ = paths::ensure_dirs()?;
    let candidates = [
        paths::system_confirmed_policy_path(),
        paths::confirmed_policy_path(),
    ];
    let mut text = None;
    for p in &candidates {
        if p.is_file() {
            text = Some(fs::read_to_string(p)?);
            break;
        }
    }
    let text = text.ok_or_else(|| {
        anyhow::anyhow!("no confirmed policy — raise Aegis and confirm first")
    })?;
    let res = aegis::apply_policy_text(&text, &paths::aegis_snapshot_path())
        .context("aegis restore failed")?;
    fs::write(paths::policy_path(), &text)?;
    fs::write(paths::confirmed_policy_path(), &text)?;
    if nix_euid_root() {
        let _ = fs::create_dir_all(paths::system_state_dir());
        let _ = fs::write(paths::system_confirmed_policy_path(), &text);
    }
    println!("✦ Aegis restored — {}", res.message);
    Ok(())
}

/// Detached deadman watcher: runs `bulwark aegis undo` with the deadline in
/// the environment. Exactly one caller spawns it per apply.
fn deadman_spawn(secs: u64, marker: PathBuf) -> Result<()> {
    let exe = std::env::current_exe()?;
    // Use a background shell-less approach: spawn ourselves with env
    let mut child = Command::new(exe);
    child
        .args(["aegis", "undo", "--table", "bulwark"])
        .env("BULWARK_DEADMAN", secs.to_string())
        .env("BULWARK_CONFIRM_PATH", marker)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // detach
    child.spawn()?;
    Ok(())
}

fn cmd_purity(action: PurityCmd) -> Result<()> {
    let _ = paths::ensure_dirs()?;
    match action {
        PurityCmd::Baseline => {
            let roots = purity::default_roots();
            println!("✦ building purity baseline over {} root(s)…", roots.len());
            let (bl, errors) = purity::build_baseline(&roots);
            purity::save_baseline(&paths::purity_baseline_path(), &bl)?;
            println!(
                "✦ baseline saved ({} files) → {}",
                bl.files.len(),
                paths::purity_baseline_path().display()
            );
            if !errors.is_empty() {
                println!("  ({} path errors skipped)", errors.len());
            }
            Ok(())
        }
        PurityCmd::Check => {
            let path = paths::purity_baseline_path();
            if !path.is_file() {
                bail!("no baseline — run: bulwark purity baseline");
            }
            let bl = purity::load_baseline(&path)?;
            let f = purity::check(&bl);
            print!("{}", purity::format_findings(&f));
            if f.is_empty() {
                Ok(())
            } else {
                bail!("{} purity finding(s)", f.len());
            }
        }
    }
}

fn cmd_install(system: bool) -> Result<()> {
    let d = paths::ensure_dirs()?;
    println!("✦ bulwark data → {}", d.display());

    if system {
        if !nix_euid_root() {
            bail!("system install needs root: sudo bulwark install --system");
        }
        return cmd_install_system();
    }

    let unit_dir = dirs_user_unit()?;
    fs::create_dir_all(&unit_dir)?;
    let exe = std::env::current_exe()?.display().to_string();
    let log = d.join("logs").join("ward.log").display().to_string();
    let service = format!(
        r#"[Unit]
Description=Bulwark Sentinel (faeOS host watch — does not raise Aegis)
After=default.target

[Service]
Type=oneshot
ExecStart={exe} sentinel
ExecStartPost=/bin/sh -c '{exe} ward >> {log} 2>&1 || true'

[Install]
WantedBy=default.target
"#
    );
    let timer = r#"[Unit]
Description=Bulwark Sentinel timer

[Timer]
OnBootSec=2m
OnUnitActiveSec=15m
Persistent=true

[Install]
WantedBy=timers.target
"#;
    fs::write(unit_dir.join("bulwark-sentinel.service"), service)?;
    fs::write(unit_dir.join("bulwark-sentinel.timer"), timer)?;
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    let _ = Command::new("systemctl")
        .args(["--user", "enable", "--now", "bulwark-sentinel.timer"])
        .status();
    println!("✦ user timer bulwark-sentinel.timer installed (watch only)");
    println!("✦ next: Purity photo — bulwark purity baseline");
    println!("✦ next: Raise Aegis — sudo bulwark aegis apply desktop && bulwark aegis confirm");
    println!("✦ then:  sudo bulwark install --system   # keep wall after reboot");
    Ok(())
}

fn cmd_install_system() -> Result<()> {
    // Plant engine where the system unit can find it (not under $HOME).
    let lib = PathBuf::from("/usr/local/lib/faeos");
    fs::create_dir_all(&lib)?;
    let dest = lib.join("bulwark");
    let src = std::env::current_exe()?;
    fs::copy(&src, &dest)?;
    // make executable + sudo-visible name (sudo PATH has /usr/local/bin, not ~/bin)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dest)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&dest, perms)?;
        let link = PathBuf::from("/usr/local/bin/bulwark");
        let _ = fs::remove_file(&link);
        // Prefer hard copy of engine so `sudo bulwark` works even if launcher missing
        let _ = fs::copy(&dest, &link);
        let mut lp = fs::metadata(&link)?.permissions();
        lp.set_mode(0o755);
        fs::set_permissions(&link, lp)?;
    }

    let sys = paths::system_state_dir();
    fs::create_dir_all(&sys)?;
    // Prefer already-confirmed user policy
    let user_confirmed = paths::confirmed_policy_path();
    if user_confirmed.is_file() {
        fs::copy(&user_confirmed, paths::system_confirmed_policy_path())?;
        println!(
            "✦ planted confirmed policy → {}",
            paths::system_confirmed_policy_path().display()
        );
    } else if !paths::system_confirmed_policy_path().is_file() {
        println!("✦ warn: no confirmed policy yet — raise Aegis + confirm, then re-run install --system");
    }

    let exe = dest.display().to_string();
    let unit_dir = PathBuf::from("/etc/systemd/system");
    let aegis_unit = format!(
        r#"[Unit]
Description=Bulwark Aegis — restore front-door lock
DefaultDependencies=no
After=network-pre.target nftables.service
Wants=network-pre.target
Before=network.target multi-user.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={exe} aegis restore
# Failure must be visible in journal; do not soft-hide
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#
    );
    fs::write(unit_dir.join("bulwark-aegis.service"), aegis_unit)?;
    let _ = Command::new("systemctl").args(["daemon-reload"]).status();
    let st = Command::new("systemctl")
        .args(["enable", "--now", "bulwark-aegis.service"])
        .status()
        .context("systemctl enable bulwark-aegis")?;
    if !st.success() {
        bail!("could not enable bulwark-aegis.service (see systemctl status)");
    }
    println!("✦ system unit bulwark-aegis.service enabled (wall restores on boot)");
    println!("✦ engine → {exe}");
    Ok(())
}

fn cmd_uninstall(purge: bool) -> Result<()> {
    let unit_dir = dirs_user_unit()?;
    let _ = Command::new("systemctl")
        .args(["--user", "disable", "--now", "bulwark-sentinel.timer"])
        .status();
    let _ = fs::remove_file(unit_dir.join("bulwark-sentinel.timer"));
    let _ = fs::remove_file(unit_dir.join("bulwark-sentinel.service"));
    if nix_euid_root() {
        let _ = Command::new("systemctl")
            .args(["disable", "--now", "bulwark-aegis.service"])
            .status();
        let _ = fs::remove_file("/etc/systemd/system/bulwark-aegis.service");
        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
        let _ = fs::remove_file(paths::system_confirmed_policy_path());
    } else {
        println!("✦ tip: sudo bulwark uninstall  — also clears boot restore unit");
    }
    // flush firewall table best-effort
    let _ = aegis::flush_bulwark("bulwark", aegis::policy::Family::Inet);
    let _ = fs::remove_file(paths::confirmed_policy_path());
    let _ = fs::remove_file(paths::pending_policy_path());
    if purge {
        let d = paths::data_dir();
        let _ = fs::remove_dir_all(&d);
        println!("✦ purged {}", d.display());
    }
    println!("✦ bulwark uninstall done");
    Ok(())
}

fn dirs_user_unit() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user"))
}
