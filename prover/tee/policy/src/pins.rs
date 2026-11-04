//! The release keys and policy URL the SDK pins per network, read from the Rust
//! client's own `signers.json`.

use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use spr_prover_tee::PolicySigners;

const SIGNERS: &str = include_str!("../../../../sdk-libs/client/src/prover/tee/signers.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pinned {
    url: String,
    public_keys: Vec<String>,
    threshold: usize,
}

/// The signers and policy URL the SDK pins for `network`.
pub fn pinned(network: &str) -> Result<(PolicySigners, String)> {
    let mut networks: BTreeMap<String, Pinned> =
        serde_json::from_str(SIGNERS).context("read signers.json")?;
    let pinned = networks
        .remove(network)
        .with_context(|| format!("the SDK pins no policy for {network}"))?;
    let keys = pinned
        .public_keys
        .iter()
        .map(|key| {
            hex::decode(key)?
                .try_into()
                .map_err(|_| anyhow!("pinned key {key} is not 32 bytes"))
        })
        .collect::<Result<_>>()?;
    Ok((
        PolicySigners::new(network, keys, pinned.threshold)?,
        pinned.url,
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_pinned_network_reads() {
        for network in ["mainnet", "devnet"] {
            let (_, url) = super::pinned(network).unwrap();
            assert!(url.ends_with(&format!("/tee-policy/{network}.json")));
        }
        assert!(super::pinned("nowhere").is_err());
    }
}
