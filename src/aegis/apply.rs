//! Apply / flush Aegis policy via netlink.

use super::policy::{parse_policy, Family, Policy, Proto, Rule, Verdict};
use crate::netlink::{self, Netlink};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct AegisApplyResult {
    pub ok: bool,
    pub message: String,
    pub table: String,
    pub ts_unix: i64,
}

/// Live kernel state of a table, probed via GETTABLE (not snapshot files).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableState {
    /// Table present in the kernel right now.
    Exists,
    /// Kernel confirms there is no such table.
    Missing,
    /// Cannot tell (no netlink / no CAP_NET_ADMIN).
    Unknown,
}

pub fn aegis_available() -> bool {
    Netlink::open().is_ok()
}

/// Probe whether a table currently exists in the kernel.
pub fn table_state(table: &str, family: Family) -> TableState {
    let mut nl = match Netlink::open() {
        Ok(nl) => nl,
        Err(_) => return TableState::Unknown,
    };
    let seq = nl.next_seq();
    let msg = netlink::msg_get_table(seq, netlink::family_byte(family), table);
    match nl.send_ack(&msg) {
        Ok(()) => TableState::Exists,
        Err(e) => match e.downcast_ref::<io::Error>() {
            Some(ioe) => match ioe.raw_os_error() {
                Some(libc::ENOENT) => TableState::Missing,
                Some(libc::EPERM) | Some(libc::EACCES) => TableState::Unknown,
                _ => TableState::Unknown,
            },
            None => TableState::Unknown,
        },
    }
}

pub fn apply_policy_text(text: &str, snapshot_path: &Path) -> Result<AegisApplyResult> {
    let policy = parse_policy(text)?;
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    let sha = hex::encode(&h.finalize()[..6]);
    apply_policy(&policy, &sha, snapshot_path)
}

fn apply_policy(policy: &Policy, policy_sha: &str, snapshot_path: &Path) -> Result<AegisApplyResult> {
    let mut nl = Netlink::open().context("open netlink (need CAP_NET_ADMIN / root for apply)")?;
    let fam = netlink::family_byte(policy.family);
    let table = policy.table.as_str();

    // Best-effort delete of a previous table — outside the batch, because a
    // missing table (ENOENT) must not abort the new apply.
    let seq = nl.next_seq();
    let _ = nl.send_ack(&netlink::msg_del_table(seq, fam, table));

    // Everything else goes in one atomic batch: if any step NACKs, the kernel
    // rolls the whole table back — no half-applied firewall.
    let seq = nl.next_seq();
    let mut msgs: Vec<Vec<u8>> = Vec::new();
    msgs.push(netlink::batch_begin(seq));
    msgs.push(netlink::msg_new_table(seq, fam, table));
    for (name, hook, policy_v) in [
        (
            "input",
            netlink::NF_INET_LOCAL_IN,
            verdict_u32(policy.default_input),
        ),
        (
            "forward",
            netlink::NF_INET_FORWARD,
            verdict_u32(policy.default_forward),
        ),
        (
            "output",
            netlink::NF_INET_LOCAL_OUT,
            verdict_u32(policy.default_output),
        ),
    ] {
        msgs.push(netlink::msg_new_base_chain(
            seq, fam, table, name, hook, 0, policy_v,
        ));
    }
    for rule in &policy.rules {
        build_rule_msgs(&mut msgs, seq, fam, table, rule)?;
    }
    msgs.push(netlink::batch_end(seq));
    if std::env::var("BULWARK_NL_DEBUG").is_ok() {
        for (i, m) in msgs.iter().enumerate() {
            eprintln!("batch msg[{i}] len={}", m.len());
        }
        eprintln!("chain msg hex: {}", hex::encode(&msgs[2]));
    }
    nl.send_batch(&msgs).context(
        "Aegis could not raise the wall (kernel firewall said no)",
    )?;

    // Only record intent once the kernel actually holds the table.
    if let Some(parent) = snapshot_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let snap = serde_json::json!({
        "table": policy.table,
        "family": format!("{:?}", policy.family),
        "ts": now(),
        "policy_sha256": policy_sha,
    });
    fs::write(snapshot_path, serde_json::to_string_pretty(&snap)?)?;

    Ok(AegisApplyResult {
        ok: true,
        message: format!(
            "Aegis raised — table '{}' holding ({} wards in the wall)",
            table,
            policy.rules.len()
        ),
        table: table.to_string(),
        ts_unix: now(),
    })
}

/// Remove the table; idempotent — a missing table is a successful flush.
pub fn flush_bulwark(table: &str, family: Family) -> Result<()> {
    let mut nl = Netlink::open()?;
    let fam = netlink::family_byte(family);
    let seq = nl.next_seq();
    match nl.send_ack(&netlink::msg_del_table(seq, fam, table)) {
        Ok(()) => Ok(()),
        Err(e) => {
            let missing = e
                .downcast_ref::<io::Error>()
                .map(|i| i.raw_os_error() == Some(libc::ENOENT))
                .unwrap_or(false);
            if missing {
                Ok(())
            } else {
                Err(e).context("DELTABLE")
            }
        }
    }
}

fn verdict_u32(v: Verdict) -> u32 {
    match v {
        Verdict::Accept => netlink::NF_ACCEPT,
        Verdict::Drop => netlink::NF_DROP,
    }
}

/// Build rule messages for one Rule. `AllowIn { from }` is fully enforced
/// (meta nfproto + network payload source match); loopback sources get a
/// dual-stack pair so 127.0.0.1 / ::1 both mean "this computer only".
fn build_rule_msgs(
    msgs: &mut Vec<Vec<u8>>,
    seq: u32,
    fam: u8,
    table: &str,
    rule: &Rule,
) -> Result<()> {
    match rule {
        Rule::AllowLo => {
            // meta iifname "lo" accept — on input and output
            for chain in ["input", "output"] {
                let mut exprs = Vec::new();
                exprs.extend(netlink::expr_meta_iifname(netlink::NFT_REG_1));
                exprs.extend(netlink::expr_cmp_eq_str(netlink::NFT_REG_1, "lo"));
                exprs.extend(netlink::expr_immediate_verdict(netlink::NF_ACCEPT));
                msgs.push(netlink::msg_new_rule(seq, fam, table, chain, &exprs));
            }
        }
        Rule::AllowEstablished => {
            // ct state established,related accept on input
            let mut exprs = Vec::new();
            exprs.extend(netlink::expr_ct_state(netlink::NFT_REG_1));
            // mask & (EST|REL) != 0  →  bitwise and then neq 0
            let mask = netlink::CT_STATE_ESTABLISHED | netlink::CT_STATE_RELATED;
            exprs.extend(netlink::expr_bitwise_and_u32(
                netlink::NFT_REG_1,
                netlink::NFT_REG_1,
                mask,
            ));
            exprs.extend(netlink::expr_cmp_neq_u32(netlink::NFT_REG_1, 0));
            exprs.extend(netlink::expr_immediate_verdict(netlink::NF_ACCEPT));
            msgs.push(netlink::msg_new_rule(seq, fam, table, "input", &exprs));
        }
        Rule::AllowIn { proto, port, from } => {
            let l4: u8 = match proto {
                Proto::Tcp => 6,
                Proto::Udp => 17,
            };
            // (nfproto, saddr payload offset, source bytes); None = any source.
            let mut sources: Vec<Option<(u8, u32, Vec<u8>)>> = vec![None];
            if let Some(addr) = from {
                sources.clear();
                match addr {
                    IpAddr::V4(v4) => {
                        sources.push(Some((netlink::NFPROTO_IPV4, 12, v4.octets().to_vec())));
                        if v4.is_loopback() {
                            sources.push(Some((
                                netlink::NFPROTO_IPV6,
                                8,
                                Ipv6Addr::LOCALHOST.octets().to_vec(),
                            )));
                        }
                    }
                    IpAddr::V6(v6) => {
                        sources.push(Some((netlink::NFPROTO_IPV6, 8, v6.octets().to_vec())));
                        if v6.is_loopback() {
                            sources.push(Some((
                                netlink::NFPROTO_IPV4,
                                12,
                                Ipv4Addr::LOCALHOST.octets().to_vec(),
                            )));
                        }
                    }
                }
            }
            for src in &sources {
                let mut exprs = Vec::new();
                if let Some((nfproto, off, bytes)) = src {
                    exprs.extend(netlink::expr_meta_nfproto(netlink::NFT_REG_1));
                    exprs.extend(netlink::expr_cmp_eq_u8(netlink::NFT_REG_1, *nfproto));
                    exprs.extend(netlink::expr_payload_network(
                        netlink::NFT_REG_2,
                        *off,
                        bytes.len() as u32,
                    ));
                    if bytes.len() == 4 {
                        let v =
                            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                        exprs.extend(netlink::expr_cmp_eq_u32_be(netlink::NFT_REG_2, v));
                    } else {
                        exprs.extend(netlink::expr_cmp_eq_bytes(netlink::NFT_REG_2, bytes));
                    }
                }
                exprs.extend(netlink::expr_meta_l4proto(netlink::NFT_REG_1));
                exprs.extend(netlink::expr_cmp_eq_u8(netlink::NFT_REG_1, l4));
                // dport at offset 2 for tcp/udp
                exprs.extend(netlink::expr_payload_transport(netlink::NFT_REG_2, 2, 2));
                exprs.extend(netlink::expr_cmp_eq_u16_be(netlink::NFT_REG_2, *port));
                exprs.extend(netlink::expr_immediate_verdict(netlink::NF_ACCEPT));
                msgs.push(netlink::msg_new_rule(seq, fam, table, "input", &exprs));
            }
        }
        Rule::AllowOut { proto, port } => {
            let mut exprs = Vec::new();
            let l4: u8 = match proto {
                Proto::Tcp => 6,
                Proto::Udp => 17,
            };
            exprs.extend(netlink::expr_meta_l4proto(netlink::NFT_REG_1));
            exprs.extend(netlink::expr_cmp_eq_u8(netlink::NFT_REG_1, l4));
            exprs.extend(netlink::expr_payload_transport(netlink::NFT_REG_2, 2, 2));
            exprs.extend(netlink::expr_cmp_eq_u16_be(netlink::NFT_REG_2, *port));
            exprs.extend(netlink::expr_immediate_verdict(netlink::NF_ACCEPT));
            msgs.push(netlink::msg_new_rule(seq, fam, table, "output", &exprs));
        }
        Rule::DenyIn { proto, port } => {
            let mut exprs = Vec::new();
            let l4: u8 = match proto {
                Proto::Tcp => 6,
                Proto::Udp => 17,
            };
            exprs.extend(netlink::expr_meta_l4proto(netlink::NFT_REG_1));
            exprs.extend(netlink::expr_cmp_eq_u8(netlink::NFT_REG_1, l4));
            exprs.extend(netlink::expr_payload_transport(netlink::NFT_REG_2, 2, 2));
            exprs.extend(netlink::expr_cmp_eq_u16_be(netlink::NFT_REG_2, *port));
            exprs.extend(netlink::expr_immediate_verdict(netlink::NF_DROP));
            msgs.push(netlink::msg_new_rule(seq, fam, table, "input", &exprs));
        }
    }
    Ok(())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn load_bundled_profile(name: &str) -> Result<String> {
    // search relative to executable and common faeos paths
    let candidates = [
        format!("policy/{name}.aegis"),
        format!("bulwark/policy/{name}.aegis"),
        format!(
            "{}/faeos/bulwark/policy/{name}.aegis",
            std::env::var("HOME").unwrap_or_default()
        ),
    ];
    for c in candidates {
        let p = Path::new(&c);
        if p.is_file() {
            return Ok(fs::read_to_string(p)?);
        }
    }
    // embed defaults
    let embedded = match name {
        "strict" => include_str!("../../policy/strict.aegis"),
        "server-ssh" => include_str!("../../policy/server-ssh.aegis"),
        "desktop" => include_str!("../../policy/desktop.aegis"),
        "goblind" => include_str!("../../policy/goblind.aegis"),
        _ => anyhow::bail!("unknown profile {name} (try desktop|strict|server-ssh|goblind)"),
    };
    Ok(embedded.to_string())
}
