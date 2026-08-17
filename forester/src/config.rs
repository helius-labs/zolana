//! Environment configuration, resolved once at the process boundary.
//!
//! Every value the forester needs from the environment is read here, in `main`,
//! before any work starts. Previously each of `RPC_URL`, `PHOTON_URL`,
//! `PROVER_URL`, and `PAYER` was read with `env::var` from inside `run` and
//! `info`, which had three costs:
//!
//! - a missing variable surfaced partway through an operation instead of at
//!   startup, sometimes after network calls had already been made;
//! - the same variable was read with different strictness in different places
//!   (`PROVER_URL` was required by `run` and optional in `info`);
//! - neither entry point could be exercised without mutating process
//!   environment, so they had no unit tests.
//!
//! Resolving into a struct fixes all three and leaves the environment as an
//! implementation detail of `main`.

use std::env;

use anyhow::{Context, Result};
use solana_keypair::Keypair;

/// Endpoints and credentials resolved from the environment.
#[derive(Debug)]
pub struct ForesterConfig {
    pub rpc_url: String,
    pub photon_url: String,
    /// `None` when `PROVER_URL` is unset. Required to submit, optional for
    /// read-only commands, so the requirement is enforced where it applies
    /// rather than at load time.
    pub prover_url: Option<String>,
    /// Raw `PAYER` value, not yet parsed into a keypair.
    ///
    /// Held as the unparsed string so a caller that does not sign never
    /// materialises key bytes. `info` reports the forester pubkey when it is
    /// present and degrades gracefully when it is not.
    payer: Option<String>,
}

impl ForesterConfig {
    /// Read every supported variable. Fails only on the two that no command can
    /// work without.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            rpc_url: env::var("RPC_URL").context("RPC_URL is not set")?,
            photon_url: env::var("PHOTON_URL").context("PHOTON_URL is not set")?,
            prover_url: env::var("PROVER_URL").ok().filter(|url| !url.is_empty()),
            payer: env::var("PAYER").ok().filter(|payer| !payer.is_empty()),
        })
    }

    /// The prover endpoint, for operations that must submit.
    pub fn require_prover_url(&self) -> Result<&str> {
        self.prover_url
            .as_deref()
            .context("PROVER_URL is not set (required to prove and submit)")
    }

    /// Whether a signing key is configured, without parsing it.
    pub fn has_payer(&self) -> bool {
        self.payer.is_some()
    }

    /// Parse `PAYER` into the forester's signing keypair.
    ///
    /// A JSON byte array, as `solana-keygen` writes. This is the one place key
    /// bytes are materialised; see the mainnet gap list for why a remote signer
    /// should replace it.
    pub fn signer(&self) -> Result<Keypair> {
        let payer = self
            .payer
            .as_deref()
            .context("PAYER is not set (forester signing keypair)")?;
        crate::parse_payer_keypair(payer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of the refactor: a config can be built without touching process
    /// environment, so callers become testable.
    fn config(prover: Option<&str>, payer: Option<&str>) -> ForesterConfig {
        ForesterConfig {
            rpc_url: "http://rpc".into(),
            photon_url: "http://photon".into(),
            prover_url: prover.map(str::to_string),
            payer: payer.map(str::to_string),
        }
    }

    #[test]
    fn require_prover_url_reports_the_missing_variable_by_name() {
        let err = config(None, None).require_prover_url().unwrap_err();
        assert!(err.to_string().contains("PROVER_URL"));
    }

    #[test]
    fn require_prover_url_returns_the_configured_endpoint() {
        assert_eq!(
            config(Some("http://prover"), None)
                .require_prover_url()
                .unwrap(),
            "http://prover"
        );
    }

    #[test]
    fn has_payer_does_not_require_a_parseable_key() {
        assert!(config(None, Some("not-a-keypair")).has_payer());
        assert!(!config(None, None).has_payer());
    }

    #[test]
    fn signer_rejects_a_non_json_payer() {
        let err = config(None, Some("not-json")).signer().unwrap_err();
        assert!(err.to_string().contains("JSON byte array"));
    }

    #[test]
    fn signer_reports_a_missing_payer_by_name() {
        let err = config(None, None).signer().unwrap_err();
        assert!(err.to_string().contains("PAYER"));
    }
}
