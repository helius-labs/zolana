//! The ring's on-chain policy: read, applied from `ring.toml`, or changed.

use anyhow::{anyhow, Result};
use custom_ring_sdk::{RingPolicy, SetPolicy, SOL};
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};

use crate::{config::PolicyConfig, init::read_config};

/// `SOL` in `ring.toml` and on the command line stands for native SOL.
pub fn parse_asset(text: &str) -> Result<Address> {
    if text.eq_ignore_ascii_case("sol") {
        return Ok(SOL);
    }
    text.parse()
        .map_err(|error| anyhow!("asset {text} is not SOL or a base58 mint: {error}"))
}

pub fn format_asset(asset: &Address) -> String {
    if *asset == SOL {
        "SOL".to_owned()
    } else {
        asset.to_string()
    }
}

/// The policy `ring.toml` asks for. Absent keys leave that part open.
pub fn from_config(policy: &PolicyConfig) -> Result<RingPolicy> {
    Ok(RingPolicy {
        allowed_assets: policy
            .allowed_assets
            .as_ref()
            .map(|assets| assets.iter().map(|asset| parse_asset(asset)).collect())
            .transpose()?,
        withdrawals_blocked: match policy.withdrawals.as_deref() {
            None | Some("open") => false,
            Some("blocked") => true,
            Some(other) => return Err(anyhow!("withdrawals must be open or blocked, got {other}")),
        },
    })
}

pub fn read_policy<R: Rpc>(rpc: &R) -> Result<RingPolicy> {
    let config =
        read_config(rpc)?.ok_or_else(|| anyhow!("ring config not created, run `init` first"))?;
    Ok(RingPolicy::from_config(&config))
}

/// Writes `policy` unless the chain already carries it. Returns whether a
/// transaction was sent.
pub fn apply(rpc: &SolanaRpc, authority: &dyn Signer, policy: &RingPolicy) -> Result<bool> {
    if read_policy(rpc)? == *policy {
        return Ok(false);
    }
    let ix = SetPolicy {
        authority: authority.pubkey(),
        policy: policy.clone(),
    }
    .instruction()?;
    rpc.create_and_send_transaction(&[ix], authority.pubkey(), &[authority])?;
    Ok(true)
}

pub fn print(policy: &RingPolicy) {
    println!(
        "assets      {}",
        match &policy.allowed_assets {
            None => "any".to_owned(),
            Some(assets) => assets
                .iter()
                .map(format_asset)
                .collect::<Vec<_>>()
                .join(", "),
        }
    );
    println!(
        "withdrawals {}",
        if policy.withdrawals_blocked {
            "blocked"
        } else {
            "open"
        }
    );
}
