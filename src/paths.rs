//! XDG state roots for Bulwark (no external deps).
//!
//! When raised via `sudo`, state still lives under the **invoking user**
//! (`SUDO_USER`), never under `/root/...`, and files are chowned back to them.

use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("BULWARK_DIR") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let base = std::env::var("XDG_DATA_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| invoking_home().join(".local").join("share"));
    base.join("faeos").join("bulwark")
}

/// Root-owned state for boot restore (system install).
pub fn system_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/bulwark")
}

/// Home of the human who invoked Bulwark (not root's home under sudo).
pub fn invoking_home() -> PathBuf {
    if euid_root() {
        if let Ok(u) = std::env::var("SUDO_USER") {
            if !u.is_empty() && u != "root" {
                if let Some(h) = home_for_user(&u) {
                    return h;
                }
            }
        }
    }
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn home_for_user(user: &str) -> Option<PathBuf> {
    // getent passwd user → name:x:uid:gid:gecos:home:shell
    let out = std::process::Command::new("getent")
        .args(["passwd", user])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout);
    let home = line.trim().split(':').nth(5)?;
    if home.is_empty() {
        return None;
    }
    Some(PathBuf::from(home))
}

pub fn euid_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// After writing into the user's tree as root, give the files back.
pub fn chown_invoking_user(path: &std::path::Path) {
    if !euid_root() {
        return;
    }
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());
    let (Some(uid), Some(gid)) = (uid, gid) else {
        return;
    };
    let c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).ok();
    let Some(c) = c else {
        return;
    };
    unsafe {
        let _ = libc::chown(c.as_ptr(), uid, gid);
    }
}

pub fn ensure_dirs() -> std::io::Result<PathBuf> {
    let d = data_dir();
    std::fs::create_dir_all(d.join("purity"))?;
    std::fs::create_dir_all(d.join("sentinel"))?;
    std::fs::create_dir_all(d.join("logs"))?;
    std::fs::create_dir_all(d.join("aegis"))?;
    // If we created dirs as root under the user's tree, hand them back.
    chown_invoking_user(&d);
    chown_invoking_user(&d.join("purity"));
    chown_invoking_user(&d.join("sentinel"));
    chown_invoking_user(&d.join("logs"));
    chown_invoking_user(&d.join("aegis"));
    // Repair root-owned leftovers from older sudo apply.
    repair_aegis_ownership(&d.join("aegis"));
    Ok(d)
}

fn repair_aegis_ownership(aegis: &std::path::Path) {
    if !euid_root() {
        return;
    }
    let Ok(rd) = std::fs::read_dir(aegis) else {
        return;
    };
    for ent in rd.flatten() {
        chown_invoking_user(&ent.path());
    }
}

pub fn policy_path() -> PathBuf {
    data_dir().join("aegis").join("policy.aegis")
}

/// Policy text from the last apply (pending deadman confirm).
pub fn pending_policy_path() -> PathBuf {
    data_dir().join("aegis").join("pending_policy.aegis")
}

/// Last confirmed policy (user tree) — used for restore / system install.
pub fn confirmed_policy_path() -> PathBuf {
    data_dir().join("aegis").join("confirmed_policy.aegis")
}

pub fn system_confirmed_policy_path() -> PathBuf {
    system_state_dir().join("confirmed_policy.aegis")
}

pub fn aegis_snapshot_path() -> PathBuf {
    data_dir().join("aegis").join("last_apply.json")
}

pub fn confirm_marker_path() -> PathBuf {
    data_dir().join("aegis").join("confirm.ok")
}

pub fn purity_baseline_path() -> PathBuf {
    data_dir().join("purity").join("baseline.json")
}

pub fn sentinel_last_path() -> PathBuf {
    data_dir().join("sentinel").join("last.json")
}

pub fn tutorial_done_path() -> PathBuf {
    data_dir().join("tutorial_done")
}
