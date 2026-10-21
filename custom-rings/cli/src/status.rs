use std::fmt::Write;

use anyhow::Result;
use custom_ring_sdk::{CustomRing, QueueStatus, RegistryStatus, RingError, RingMode};
use solana_signer::Signer;
use zolana_client::Rpc;

use crate::{
    config::{redact_text, redact_url, RingConfig, Target},
    controls, deploy, line,
    policy::{print_pinned, Pinned},
    release::RingProgram,
    ui::{self, icon},
    Context,
};

const EXPLORER: &str = "https://explorer.solana.com/address";

/// What ring.toml records, then what the chain holds, an unreachable chain ends the listing.
pub fn run(ctx: &Context) -> Result<()> {
    let config = &ctx.config;
    line("ring", &config.name);
    line("target", config.target);
    line("program id", config.program_id);
    for (label, key) in [
        ("config key", config.config_authority()),
        ("upgrade key", config.upgrade_authority()),
    ] {
        match key {
            Ok(key) => line(label, key.pubkey()),
            Err(error) => line(label, format_args!("unavailable ({error})")),
        }
    }
    let urls = config.urls();
    for (label, url) in [
        ("rpc", &urls.rpc),
        ("indexer", &urls.indexer),
        ("prover", &urls.prover),
        ("ring rpc", &urls.ring_rpc),
    ] {
        line(label, redact_url(url));
    }
    match RingProgram::from_lock() {
        Ok(program) => line(
            "release",
            format_args!("{} {}", program.tag, program.asset.name),
        ),
        Err(error) => line("release", error),
    }
    if let Err(error) = print_chain(ctx) {
        let (rpc, error) = (redact_url(&urls.rpc), redact_text(&error.to_string()));
        line("chain", format_args!("unreachable at {rpc} ({error})"));
    }
    Ok(())
}

pub fn announce(config: &RingConfig) {
    println!();
    ui::heading(
        icon::RING,
        &format!("ring {} is live on {}", config.program_id, config.target),
    );
    line("explorer", explorer_link(config));
}

fn explorer_link(config: &RingConfig) -> String {
    let cluster = match config.target {
        Target::Devnet => "cluster=devnet".to_owned(),
        Target::Localnet => format!(
            "cluster=custom&customUrl={}",
            percent_encode(&config.urls().rpc)
        ),
    };
    format!("{EXPLORER}/{}?{cluster}", config.program_id)
}

fn percent_encode(text: &str) -> String {
    text.bytes().fold(String::new(), |mut out, byte| {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            out.push(byte as char);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
        out
    })
}

fn print_chain(ctx: &Context) -> Result<()> {
    let (ring, chain) = (ctx.ring, ctx.chain());
    if let Ok(authority) = ctx.authority() {
        let lamports = ctx.rpc().get_balance(authority.pubkey())?;
        let sol = lamports as f64 / 1e9;
        line("balance", format_args!("{sol} SOL ({lamports} lamports)"));
    }
    line("program", program_state(ctx)?);
    let status = match ctx.block(ring.status(chain)) {
        Ok(status) => status,
        Err(RingError::MissingRingConfig) => {
            line(
                "config",
                format_args!("not created ({})", ring.config_pda()),
            );
            // Until the config exists, ring.toml names the tier.
            if ctx.config.policy.is_none() {
                line("policy", "none (audit-only ring)");
            }
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let config = &status.config;
    let auditor = hex::encode(config.auditor_pubkey.as_bytes());
    line(
        "config",
        format_args!(
            "{} authority {} auditor {auditor}",
            ring.config_pda(),
            config.authority
        ),
    );
    line("mode", mode(config.mode));
    controls::print_insert_fee(config);
    match &config.co_signer {
        Some(cosigner) => controls::print_cosigner(cosigner),
        None => line("co-signer", "none"),
    }
    match config.delegate {
        Some(delegate) => line("delegate", delegate),
        None => line("delegate", "none"),
    }
    match &status.registry {
        Some(registry) => print_registry(ring, registry),
        None => line(
            "registry",
            format_args!("not created ({})", ring.registry_pda()),
        ),
    }
    if let Some(queue) = &status.queue {
        print_queue(ring, queue);
    }
    let pinned = match &status.registry {
        Some(registry) => Pinned::of(Box::new(*registry.account()))?,
        None => None,
    };
    if !config.has_policy {
        line("policy", "none (audit-only ring)");
    } else if let Some(pinned) = pinned {
        line("policy", ring.registry_pda());
        print_pinned(ring, &pinned);
    } else {
        line("policy", "not pinned");
    }
    match status.registration {
        Some(registration) => line(
            "spp ring",
            format_args!(
                "{} activated={} paused={} authority_transact={}",
                ring.ring_auth_pda(),
                registration.activated,
                registration.paused,
                registration.authority_rail
            ),
        ),
        None => line(
            "spp ring",
            format_args!("not registered ({})", ring.ring_auth_pda()),
        ),
    }
    Ok(())
}

fn mode(mode: RingMode) -> &'static str {
    match mode {
        RingMode::Off => "confidential",
        RingMode::Registry => "confidential, every output key escrowed",
        RingMode::Anonymous => "anonymous",
    }
}

/// Every own-ring proof binds a root at or above the floor.
fn print_registry(ring: CustomRing, registry: &RegistryStatus) {
    line(
        "registry",
        format_args!("{} next index {}", ring.registry_pda(), registry.next_index),
    );
    if let Some(newest) = registry.roots.first() {
        line(
            "root",
            format_args!(
                "{} applied {} at slot {}",
                hex::encode(newest.root),
                newest.applied,
                newest.slot
            ),
        );
    }
    line("roots", format_args!("{} in history", registry.roots.len()));
    line(
        "floor",
        format_args!(
            "{} raised at slot {}, prior {}",
            registry.floor, registry.floor_slot, registry.prior_floor
        ),
    );
}

fn print_queue(ring: CustomRing, queue: &QueueStatus) {
    line(
        "queue",
        format_args!(
            "{} pending {} at positions {}..{}",
            ring.queue_pda(),
            queue.pending,
            queue.head,
            queue.tail
        ),
    );
    line(
        "next apply",
        format_args!("from slot {}", queue.next_apply_slot),
    );
}

fn program_state(ctx: &Context) -> Result<String> {
    let Some(account) = ctx.rpc().get_account(ctx.ring.program_id())? else {
        return Ok("not deployed".to_owned());
    };
    if !account.executable {
        return Ok("account exists but is not executable".to_owned());
    }
    let Some(data) = deploy::program_data(ctx)? else {
        return Ok("deployed (not upgradeable)".to_owned());
    };
    let configured = ctx.config.upgrade_authority().map(|key| key.pubkey());
    let relation = match (data.upgrade_authority, &configured) {
        (Some(authority), Ok(configured)) if authority == *configured => "matches",
        _ => "differs from",
    };
    Ok(format!(
        "deployed, upgrade authority {}, {relation} ring.toml {}, capacity {} bytes",
        data.upgrade_authority
            .map_or_else(|| "none (immutable)".to_owned(), |key| key.to_string()),
        configured.map_or_else(
            |error| format!("unavailable ({error})"),
            |key| key.to_string()
        ),
        data.capacity
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOML: &str = r#"
name = "x"
target = "devnet"
program_id = "11111111111111111111111111111111"
authority_keypair = "a.json"

[localnet]
rpc = "http://127.0.0.1:8899"
indexer = "i"
prover = "p"
ring_rpc = "r"

[devnet]
rpc = "https://api.devnet.solana.com"
indexer = "i"
prover = "p"
ring_rpc = "r"
"#;

    #[test]
    fn explorer_link_names_the_cluster() {
        let mut config: RingConfig = toml::from_str(TOML).expect("parse");
        assert_eq!(
            explorer_link(&config),
            "https://explorer.solana.com/address/11111111111111111111111111111111?cluster=devnet"
        );
        config.target = Target::Localnet;
        assert_eq!(
            explorer_link(&config),
            "https://explorer.solana.com/address/11111111111111111111111111111111?cluster=custom&customUrl=http%3A%2F%2F127.0.0.1%3A8899"
        );
    }
}
