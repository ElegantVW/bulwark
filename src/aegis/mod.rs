//! Aegis — policy DSL + apply via our netlink nf_tables code.

pub mod policy;
pub mod apply;

pub use apply::{
    aegis_available, apply_policy_text, flush_bulwark, load_bundled_profile, table_state,
    TableState,
};
pub use policy::{parse_policy, policy_summary};
