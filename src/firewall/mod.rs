//! The actual guarantee: kernel filtering that drops everything a `Policy` does not pass.
//! It lives in the kernel, so it keeps holding when Clash or this daemon dies.
//!
//! Compiling a policy is pure and tested on every host (`pf`, `wfp`); talking to the
//! kernel lives in `platform::{macos,windows}`.

pub mod pf;
pub mod wfp;

use crate::policy::Policy;
use anyhow::Result;

/// A kernel firewall we own a slice of (a pf anchor, a WFP sublayer).
pub trait Firewall {
    /// Whether `validate` needs elevation on this OS.
    const VALIDATE_NEEDS_ELEVATION: bool;

    /// The native form of `policy`. Equal output means equal kernel state is wanted, so it
    /// must include anything resolved at runtime (e.g. interface LUIDs).
    fn render(&self, policy: &Policy) -> String;
    /// Dry run against the OS; changes nothing.
    fn validate(&self, policy: &Policy) -> Result<()>;
    fn state(&self) -> Result<FwState>;
    /// Atomically make `policy` the only rules we own, ahead of all other system rules.
    fn apply(&self, policy: &Policy) -> Result<()>;
    /// Cut connections that were authorised before the current rules.
    fn revoke_connections(&self) -> Result<()>;
    /// Remove everything we own. Traffic is unrestricted afterwards.
    fn remove(&self) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct FwState {
    /// Our slice is in place and evaluated before other rules (pf enabled and anchor first;
    /// WFP sublayer present).
    pub active: bool,
    /// The block-everything-else rule is loaded (it is absent while paused).
    pub blocking: bool,
    /// Canonical kernel view of our rules, to notice added or removed rules.
    pub fingerprint: String,
    pub summary: String,
}

impl FwState {
    /// Nothing of ours is loaded.
    pub fn is_empty(&self) -> bool {
        !self.active && !self.blocking && self.fingerprint.trim().is_empty()
    }

    pub fn describe(&self) -> String {
        format!(
            "{}, rules {}",
            self.summary,
            if self.blocking { "blocking" } else { "OPEN" }
        )
    }
}

pub fn native(cfg: &crate::config::Config) -> crate::platform::NativeFirewall {
    crate::platform::NativeFirewall::new(cfg)
}
