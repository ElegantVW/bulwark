//! XDG state roots for Bulwark (no external deps).

use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("BULWARK_DIR") {
        return PathBuf::from(p);
    }
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs_fallback_home().join(".local").join("share")
        });
    base.join("faeos").join("bulwark")
}

/// Root-owned state for boot restore (system install).
pub fn system_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/bulwark")
}

fn dirs_fallback_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

pub fn ensure_dirs() -> std::io::Result<PathBuf> {
    let d = data_dir();
    std::fs::create_dir_all(d.join("purity"))?;
    std::fs::create_dir_all(d.join("sentinel"))?;
    std::fs::create_dir_all(d.join("logs"))?;
    std::fs::create_dir_all(d.join("aegis"))?;
    Ok(d)
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

pub fn purity_baseline_path() -> PathBuf {
    data_dir().join("purity").join("baseline.json")
}

pub fn sentinel_last_path() -> PathBuf {
    data_dir().join("sentinel").join("last.json")
}

pub fn tutorial_done_path() -> PathBuf {
    data_dir().join("tutorial_done")
}
