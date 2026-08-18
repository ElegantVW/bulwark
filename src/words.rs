//! Plain-language helpers — themed names stay, kid sentences beside them.
//! Posture must not flatter: missing / unknown wall ⇒ never SAFE.

use crate::aegis;
use crate::paths;
use crate::purity::{self, Finding as PurityFinding};
use crate::sentinel::{self, Listener};
use crate::ward::{self, Finding as WardFinding};
use std::fs;

/// Overall computer mood.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mood {
    Safe,
    Care,
    Danger,
}

impl Mood {
    pub fn label(self) -> &'static str {
        match self {
            Mood::Safe => "SAFE",
            Mood::Care => "CARE",
            Mood::Danger => "DANGER",
        }
    }

    /// ANSI color for the big mood word.
    pub fn color(self) -> &'static str {
        match self {
            Mood::Safe => "\x1b[38;5;78m",   // green
            Mood::Care => "\x1b[38;5;214m",  // amber
            Mood::Danger => "\x1b[38;5;197m", // red
        }
    }

    pub fn banner(self) -> String {
        let c = self.color();
        format!("{c}✦✦  {}  ✦✦\x1b[0m", self.label())
    }
}

#[derive(Debug, Clone)]
pub struct Posture {
    pub mood: Mood,
    pub aegis_line: String,
    pub purity_line: String,
    pub ward_line: String,
    pub sentinel_line: String,
}

/// Inputs for mood math (pure — unit-tested).
#[derive(Debug, Clone, Copy)]
pub struct MoodInputs {
    pub aegis: aegis::TableState,
    pub purity_baseline_exists: bool,
    pub purity_changed: usize,
    pub ward_crit: usize,
    pub ward_total: usize,
    /// Sensitive fae ports bound on a non-loopback address.
    pub exposed_ai_ports: usize,
    /// Any non-loopback listening sockets (stranger-reachable binds).
    pub public_listeners: usize,
}

pub fn plain_name(layer: &str) -> &'static str {
    match layer {
        "Bulwark" => "keeps this computer safe",
        "Aegis" => "front-door lock (who can knock)",
        "Purity" => "photo of important files",
        "Ward" => "search for sneaky stuff",
        "Sentinel" => "watches open network windows",
        _ => "",
    }
}

/// faeOS local AI / service ports that must stay on loopback when the wall is honest.
pub fn fae_localhost_ports() -> &'static [u16] {
    &[8080, 8081, 8082, 8083, 8090, 8091]
}

fn bind_host(local: &str) -> &str {
    if let Some(rest) = local.strip_prefix('[') {
        match rest.split_once(']') {
            Some((h, _)) => h,
            None => local,
        }
    } else {
        match local.rsplit_once(':') {
            Some((h, _)) => h,
            None => local,
        }
    }
}

/// True if `local` (from /proc, e.g. `127.0.0.1:8080` or `[::1]:80`) is loopback-only.
pub fn is_loopback_bind(local: &str) -> bool {
    let host = bind_host(local);
    if host == "::1" || host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return ip.is_loopback();
    }
    false
}

/// `0.0.0.0` / `::` — listening on every face of the machine.
pub fn is_wildcard_bind(local: &str) -> bool {
    let host = bind_host(local);
    host == "0.0.0.0"
        || host == "*"
        || host == "::"
        || host.eq_ignore_ascii_case("::0")
}

pub fn listener_port(local: &str) -> Option<u16> {
    if let Some(rest) = local.strip_prefix('[') {
        let (_, after) = rest.split_once(']')?;
        let p = after.strip_prefix(':')?;
        return p.parse().ok();
    }
    local.rsplit_once(':')?.1.parse().ok()
}

/// Plain face label for Sentinel rows.
pub fn bind_face_label(local: &str) -> &'static str {
    if is_loopback_bind(local) {
        "only here"
    } else if is_wildcard_bind(local) {
        "whole network"
    } else {
        "network"
    }
}

/// Pixie / llama / kur family — should not face the LAN.
pub fn is_fae_service_comm(comm: Option<&str>) -> bool {
    let Some(c) = comm else {
        return false;
    };
    let c = c.to_ascii_lowercase();
    matches!(
        c.as_str(),
        "pixie"
            | "llama-server"
            | "llama_server"
            | "kur"
            | "kur-server"
            | "magpie"
            | "ask"
            | "imp"
            | "menagerie"
            | "murmur"
            | "siren"
    ) || c.contains("llama")
}

/// Count public binds and sensitive AI / fae doors past loopback.
pub fn exposure_counts(listeners: &[Listener]) -> (usize /*public*/, usize /*exposed_ai*/) {
    let mut public = 0usize;
    let mut exposed_ai = 0usize;
    let ai = fae_localhost_ports();
    for l in listeners {
        if is_loopback_bind(&l.local) {
            continue;
        }
        public += 1;
        let port_hit = listener_port(&l.local).is_some_and(|p| ai.contains(&p));
        let fae_hit = is_fae_service_comm(l.comm.as_deref());
        if port_hit || fae_hit {
            exposed_ai += 1;
        }
    }
    (public, exposed_ai)
}

/// Honest mood: never SAFE if wall missing/unknown, no photo, or AI port on the LAN.
pub fn compute_mood(i: MoodInputs) -> Mood {
    if i.ward_crit > 0 || i.purity_changed > 0 || i.exposed_ai_ports > 0 {
        return Mood::Danger;
    }
    match i.aegis {
        aegis::TableState::Exists => {}
        aegis::TableState::Missing | aegis::TableState::Unknown => return Mood::Care,
    }
    if !i.purity_baseline_exists {
        return Mood::Care;
    }
    if i.ward_total > 0 || i.public_listeners > 0 {
        return Mood::Care;
    }
    Mood::Safe
}

pub fn gather_posture() -> Posture {
    let snap_table = paths::aegis_snapshot_path();
    let table_name = fs::read_to_string(&snap_table)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("table").and_then(|x| x.as_str()).map(String::from))
        .unwrap_or_else(|| "bulwark".into());
    let aegis_state = aegis::table_state(&table_name, aegis::policy::Family::Inet);
    let aegis_line = match aegis_state {
        aegis::TableState::Exists => "ON — front door lock is set".into(),
        aegis::TableState::Missing => "OFF — front door is open to the network".into(),
        aegis::TableState::Unknown => {
            "? — need permission to check the wall (ask a grown-up for sudo)".into()
        }
    };

    let bl_path = paths::purity_baseline_path();
    let (purity_line, purity_changed, purity_exists) = if !bl_path.is_file() {
        ("none — no photo yet (Purity photo)".into(), 0usize, false)
    } else {
        match purity::load_baseline(&bl_path) {
            Ok(bl) => {
                let f = purity::check(&bl);
                let n = f.len();
                if n == 0 {
                    (
                        format!("OK — photo of {} files matches", bl.files.len()),
                        0,
                        true,
                    )
                } else {
                    (
                        format!("CHANGED! — {n} file(s) look different"),
                        n,
                        true,
                    )
                }
            }
            Err(_) => ("photo unreadable".into(), 0, true),
        }
    };

    let ward_f = ward::hunt();
    let ward_crit = ward_f
        .iter()
        .filter(|f| f.severity == "crit")
        .count();
    let ward_total = ward_f.len();
    let ward_line = if ward_total == 0 {
        "clean — nothing sneaky found".into()
    } else if ward_crit > 0 {
        format!("found {ward_total} thing(s) · {ward_crit} serious")
    } else {
        format!("found {ward_total} thing(s) — take a look")
    };

    let listeners = sentinel::scan_listeners();
    let (public_listeners, exposed_ai) = exposure_counts(&listeners);
    let n = listeners.len();
    let sentinel_line = if n == 0 {
        "no open windows".into()
    } else if exposed_ai > 0 {
        format!(
            "{n} open window(s) · {exposed_ai} magic door(s) open to the whole network"
        )
    } else if public_listeners > 0 {
        format!("{n} open window(s) · {public_listeners} stranger(s) could knock")
    } else {
        format!("{n} open window(s) — only this computer")
    };

    let mood = compute_mood(MoodInputs {
        aegis: aegis_state,
        purity_baseline_exists: purity_exists,
        purity_changed,
        ward_crit,
        ward_total,
        exposed_ai_ports: exposed_ai,
        public_listeners,
    });

    Posture {
        mood,
        aegis_line,
        purity_line,
        ward_line,
        sentinel_line,
    }
}

/// Map Ward kind → plain sentence.
pub fn ward_plain(f: &WardFinding) -> String {
    let plain = match f.kind.as_str() {
        "path-world-writable" => "A program folder is open so anyone can change it",
        "ld-preload" => "A program loads a secret add-on (LD_PRELOAD)",
        "ld-so-preload" => "The system loads add-ons for every program (ld.so.preload)",
        "deleted-exe" => "A program is still running after its file was deleted",
        "timer-tmp-exec" => "A timer may run something from a temp folder",
        "home-bin-writable" => "Your personal tools folder is open to everyone",
        "suid-home-bin" => "A personal tool has super powers (SUID)",
        other => other,
    };
    format!("[{}] {plain}", f.severity)
}

pub fn purity_plain(f: &PurityFinding) -> String {
    match f {
        PurityFinding::Missing { path } => format!("missing — {path}"),
        PurityFinding::New { path } => format!("new file — {path}"),
        PurityFinding::Changed { path, reason } => format!("changed ({reason}) — {path}"),
    }
}

pub fn sentinel_plain_lines() -> Vec<String> {
    let listeners = sentinel::scan_listeners();
    let mut lines = Vec::new();
    let (public, exposed_ai) = exposure_counts(&listeners);
    lines.push("Windows strangers can knock on  ·  only-here = safe face".into());
    if exposed_ai > 0 {
        lines.push(format!(
            "⚠ A magic door is open to the whole network ({exposed_ai})."
        ));
    } else if public > 0 {
        lines.push(format!(
            "{public} window(s) face the network (not only this computer)."
        ));
    } else {
        lines.push("All listed doors are only on this computer.".into());
    }
    lines.push(String::new());
    // Strangers first, then localhost.
    let mut ordered: Vec<&Listener> = listeners.iter().collect();
    ordered.sort_by_key(|l| is_loopback_bind(&l.local));
    for l in ordered.iter().take(14) {
        let face = bind_face_label(&l.local);
        let mark = if !is_loopback_bind(&l.local)
            && (listener_port(&l.local).is_some_and(|p| fae_localhost_ports().contains(&p))
                || is_fae_service_comm(l.comm.as_deref()))
        {
            "✦ "
        } else if !is_loopback_bind(&l.local) {
            "· "
        } else {
            "  "
        };
        lines.push(format!(
            "{mark}{:<5} {:<22} [{face}] {}",
            l.proto,
            l.local,
            l.comm.as_deref().unwrap_or("?")
        ));
    }
    if listeners.len() > 14 {
        lines.push(format!("… and {} more", listeners.len() - 14));
    }
    if listeners.is_empty() {
        lines.push("no open windows".into());
    }
    lines
}

pub fn help_lines() -> Vec<String> {
    vec![
        "Bulwark — your shield for this computer.".into(),
        "Seal locks the glass (screen). Bulwark watches the house (network).".into(),
        "".into(),
        "Aegis   — front-door lock (who can knock)".into(),
        "Purity  — photo of important files".into(),
        "Ward    — search for sneaky stuff".into(),
        "Sentinel— open network windows".into(),
        "".into(),
        "SAFE  = wall ON, photo OK, no stranger doors".into(),
        "CARE  = something to do (wall off, no photo, …)".into(),
        "DANGER= look at Ward, Purity, or open magic doors".into(),
        "".into(),
        "Install alone does not raise the wall.".into(),
        "Raise Aegis (menu) may need a grown-up password.".into(),
        "Human: Ward report · Aegis protect · Purity photo".into(),
    ]
}

pub fn tutorial_done() -> bool {
    paths::data_dir().join("tutorial.done").is_file()
}

pub fn mark_tutorial_done() {
    let _ = paths::ensure_dirs();
    let _ = fs::write(paths::data_dir().join("tutorial.done"), b"1\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aegis::TableState;

    fn base() -> MoodInputs {
        MoodInputs {
            aegis: TableState::Exists,
            purity_baseline_exists: true,
            purity_changed: 0,
            ward_crit: 0,
            ward_total: 0,
            exposed_ai_ports: 0,
            public_listeners: 0,
        }
    }

    #[test]
    fn mood_safe_only_when_all_green() {
        assert_eq!(compute_mood(base()), Mood::Safe);
    }

    #[test]
    fn mood_never_safe_if_wall_missing() {
        let mut i = base();
        i.aegis = TableState::Missing;
        assert_eq!(compute_mood(i), Mood::Care);
    }

    #[test]
    fn mood_never_safe_if_wall_unknown() {
        let mut i = base();
        i.aegis = TableState::Unknown;
        assert_eq!(compute_mood(i), Mood::Care);
    }

    #[test]
    fn mood_never_safe_without_purity_photo() {
        let mut i = base();
        i.purity_baseline_exists = false;
        assert_eq!(compute_mood(i), Mood::Care);
    }

    #[test]
    fn mood_danger_if_ai_port_on_lan() {
        let mut i = base();
        i.exposed_ai_ports = 1;
        assert_eq!(compute_mood(i), Mood::Danger);
    }

    #[test]
    fn mood_danger_on_ward_crit() {
        let mut i = base();
        i.ward_crit = 1;
        i.ward_total = 1;
        assert_eq!(compute_mood(i), Mood::Danger);
    }

    #[test]
    fn loopback_binds_detected() {
        assert!(is_loopback_bind("127.0.0.1:8080"));
        assert!(is_loopback_bind("[::1]:8080"));
        assert!(!is_loopback_bind("0.0.0.0:8080"));
        assert!(!is_loopback_bind("192.168.1.5:22"));
        assert!(is_wildcard_bind("0.0.0.0:8080"));
        assert!(is_wildcard_bind("[::]:443"));
        assert!(!is_wildcard_bind("192.168.1.5:22"));
        assert!(is_fae_service_comm(Some("llama-server")));
        assert!(!is_fae_service_comm(Some("firefox")));
    }

    #[test]
    fn desktop_profile_has_no_ssh() {
        let text = include_str!("../policy/desktop.aegis");
        for line in text.lines() {
            let t = line.split('#').next().unwrap_or("").trim();
            if t.is_empty() {
                continue;
            }
            assert!(
                !(t.contains("tcp 22") && t.starts_with("allow")),
                "desktop must not allow SSH: {t}"
            );
        }
        let ssh = include_str!("../policy/server-ssh.aegis");
        assert!(ssh.contains("tcp 22"), "server-ssh should allow 22");
    }
}
