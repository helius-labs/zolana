//! Forester for shielded-pool nullifier-tree maintenance.
//!
//! Proof generation lives in `prover/client`; this crate handles the on-chain
//! submission path only.

pub mod cli;
pub mod forest;
pub mod info;
pub mod logging;
pub mod run;

pub use forest::{batch_update_nullifier_tree_once, ForestError, ForestParams};

use anyhow::{anyhow, Context, Result};
use solana_keypair::Keypair;

/// Parse a `PAYER` JSON byte-array keypair. Shared by `run` (requires PAYER)
/// and `info` (tolerates it unset) so the encoding lives in one place.
pub(crate) fn parse_payer_keypair(payer: &str) -> Result<Keypair> {
    let bytes: Vec<u8> =
        serde_json::from_str(payer).context("PAYER must be a JSON byte array keypair")?;
    Keypair::try_from(bytes.as_slice())
        .map_err(|err| anyhow!("PAYER is not a valid keypair: {err}"))
}
