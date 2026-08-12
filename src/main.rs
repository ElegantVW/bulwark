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
    /// Confirm apply (cancel deadman undo)
    Confirm,
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
    let listeners = sentinel::scan_listeners();
    let netlink_ok = aegis::aegis_available();
    let baseline = paths::purity_baseline_path();
    let purity = if baseline.is_file() {
        match purity::load_baseline(&baseline) {
            Ok(bl) => {
                let f = purity::check(&bl);
                format!("baseline ok · {} files · {} findings", bl.files.len(), f.len())
            }
            Err(e) => format!("baseline unreadable: {e}"),
        }
    } else {
        "no baseline (run: bulwark purity baseline)".into()
    };
    let ward_n = ward::hunt().len();

    println!("✦ Bulwark status");
    println!("  aegis netlink:  {}", if netlink_ok { "available" } else { "unavailable" });
    println!("  aegis state:    {}", aegis_state_line());
    println!("  sentinel:       {} listening sockets", listeners.len());
    println!("  purity:         {purity}");
    println!("  ward:           {ward_n} finding(s)");
    println!("  data:           {}", paths::data_dir().display());
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
            // persist as current policy — only after the kernel accepted it
            fs::write(paths::policy_path(), &text)?;
            println!("✦ {}", res.message);
            if !no_deadman && deadman > 0 {
                println!(
                    "✦ deadman: confirm within {deadman}s or rules auto-undo:\n  bulwark aegis confirm"
                );
                let secs = deadman;
                let marker = paths::data_dir().join("aegis").join("confirm.ok");
                let _ = fs::remove_file(&marker);
                // one detached watcher: if no confirm within `secs`, it undoes
                // the table itself. It never deletes the marker — see Undo.
                deadman_spawn(secs, marker)?;
            }
            Ok(())
        }
        AegisCmd::Confirm => {
            let marker = paths::data_dir().join("aegis").join("confirm.ok");
            fs::write(&marker, b"ok\n")?;
            println!("✦ aegis confirm recorded — deadman cancelled");
            Ok(())
        }
        AegisCmd::Undo { table } => {
            // deadman helper path
            if let Ok(secs) = std::env::var("BULWARK_DEADMAN") {
                let secs: u64 = secs.parse().unwrap_or(90);
                let marker = std::env::var("BULWARK_CONFIRM_PATH")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| paths::data_dir().join("aegis").join("confirm.ok"));
                for _ in 0..secs {
                    if marker.is_file() {
                        // leave the marker in place: other deadman watchers
                        // must also see it, and a later apply removes it.
                        eprintln!("bulwark deadman: confirmed — keep rules");
                        return Ok(());
                    }
                    thread::sleep(Duration::from_secs(1));
                }
                eprintln!("bulwark deadman: no confirm — undoing table {table}");
            }
            // idempotent: undoing with no table is a success
            aegis::flush_bulwark(&table, aegis::policy::Family::Inet)
                .context("undo/flush")?;
            let _ = fs::remove_file(paths::aegis_snapshot_path());
            let _ = fs::remove_file(paths::data_dir().join("aegis").join("confirm.ok"));
            println!("✦ aegis undo: table '{table}' removed");
            Ok(())
        }
    }
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
    let (unit_dir, target, scope) = if system {
        (PathBuf::from("/etc/systemd/system"), "multi-user.target", "system")
    } else {
        (dirs_user_unit()?, "default.target", "user")
    };
    fs::create_dir_all(&unit_dir)?;
    let exe = std::env::current_exe()?.display().to_string();
    let log = d.join("logs").join("ward.log").display().to_string();
    let service = format!(
        r#"[Unit]
Description=Bulwark Sentinel (faeOS host watch)
After=default.target

[Service]
Type=oneshot
ExecStart={exe} sentinel
ExecStartPost=/bin/sh -c '{exe} ward >> {log} 2>&1 || true'

[Install]
WantedBy={target}
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
    // best-effort enable
    if system {
        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
        let _ = Command::new("systemctl")
            .args(["enable", "--now", "bulwark-sentinel.timer"])
            .status();
    } else {
        let _ = Command::new("systemctl").args(["--user", "daemon-reload"]).status();
        let _ = Command::new("systemctl")
            .args(["--user", "enable", "--now", "bulwark-sentinel.timer"])
            .status();
    }
    println!("✦ {scope} timer bulwark-sentinel.timer installed");
    println!("✦ next: bulwark purity baseline");
    println!("✦ next: sudo bulwark aegis apply desktop   # then bulwark aegis confirm");
    Ok(())
}

fn cmd_uninstall(purge: bool) -> Result<()> {
    let unit_dir = dirs_user_unit()?;
    let _ = Command::new("systemctl")
        .args(["--user", "disable", "--now", "bulwark-sentinel.timer"])
        .status();
    let _ = fs::remove_file(unit_dir.join("bulwark-sentinel.timer"));
    let _ = fs::remove_file(unit_dir.join("bulwark-sentinel.service"));
    // flush firewall table best-effort
    let _ = aegis::flush_bulwark("bulwark", aegis::policy::Family::Inet);
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
