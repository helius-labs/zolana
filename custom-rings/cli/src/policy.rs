//! The ring's on-chain policy: read, applied from `ring.toml`, or changed.

use anyhow::{anyhow, Result};
use custom_ring_sdk::{AssetRule, RingPolicy, SetPolicy, WithdrawalRule, SOL};
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

pub fn parse_rule(text: &str) -> Result<WithdrawalRule> {
    WithdrawalRule::parse(text)
        .ok_or_else(|| anyhow!("withdrawal rule must be open, blocked or approval, got {text}"))
}

/// The policy `ring.toml` asks for. Absent keys leave that part open.
pub fn from_config(policy: &PolicyConfig) -> Result<RingPolicy> {
    let mut assets: Vec<AssetRule> = Vec::new();
    for asset in policy.allowed_assets.iter().flatten() {
        assets.push(AssetRule {
            mint: parse_asset(asset)?,
            withdrawals: WithdrawalRule::Open,
        });
    }
    let withdrawals = policy
        .withdrawals
        .as_deref()
        .map(parse_rule)
        .transpose()?
        .unwrap_or_default();
    // Listed mints inherit the default rule until an entry names its own.
    for asset in &mut assets {
        asset.withdrawals = withdrawals;
    }
    for (mint, rule) in &policy.asset_withdrawals {
        let mint = parse_asset(mint)?;
        let rule = parse_rule(rule)?;
        match assets.iter_mut().find(|asset| asset.mint == mint) {
            Some(asset) => asset.withdrawals = rule,
            None if policy.allowed_assets.is_some() => {
                return Err(anyhow!(
                    "asset_withdrawals names {} which is not in allowed_assets",
                    format_asset(&mint)
                ))
            }
            None => assets.push(AssetRule {
                mint,
                withdrawals: rule,
            }),
        }
    }
    Ok(RingPolicy {
        allowlist: policy.allowed_assets.is_some(),
        assets,
        withdrawals,
        approver: policy
            .approver
            .as_deref()
            .map(|key| {
                key.parse()
                    .map_err(|error| anyhow!("approver {key} is not a base58 pubkey: {error}"))
            })
            .transpose()?,
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
        if policy.allowlist { "allowlist" } else { "any" }
    );
    println!("withdrawals {} (default)", policy.withdrawals.as_str());
    for asset in &policy.assets {
        println!(
            "  {:<44} withdrawals {}",
            format_asset(&asset.mint),
            asset.withdrawals.as_str()
        );
    }
    if let Some(approver) = policy.approver {
        println!("approver    {approver}");
    }
}
