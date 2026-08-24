use std::fmt::Write;

use custom_ring_sdk::{AccountReadError, CustomRing};
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, Rpc, SolanaRpc};

use crate::{
    config::{RingConfig, Target},
    deploy::{read_program_data, DeployError},
    Context,
};

const EXPLORER: &str = "https://explorer.solana.com/address";

#[derive(Debug, Error)]
pub enum StatusError {
    #[error(transparent)]
    Client(Box<ClientError>),
    #[error(transparent)]
    Deploy(#[from] DeployError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
}

impl From<ClientError> for StatusError {
    fn from(error: ClientError) -> Self {
        Self::Client(Box::new(error))
    }
}

pub fn run(ctx: &Context) {
    let config = &ctx.config;
    println!("ring        {}", config.name);
    println!("target      {}", config.target.as_str());
    println!("program id  {}", config.program_id);
    match config.authority() {
        Ok(authority) => println!("authority   {}", authority.pubkey()),
        Err(error) => println!("authority   unavailable ({error})"),
    }
    println!("rpc         {}", config.urls().rpc);
    println!("indexer     {}", config.urls().indexer);
    println!("prover      {}", config.urls().prover);
    println!("ring rpc    {}", config.urls().ring_rpc);
    let features: Vec<&str> = config.enabled_features().collect();
    println!("features    {}", features.join(", "));

    if let Err(error) = print_chain(config, ctx.ring, &ctx.rpc) {
        println!("chain       unreachable at {} ({error})", config.urls().rpc);
    }
}

pub fn announce(config: &RingConfig) {
    println!();
    println!(
        "🎉 ring {} is live on {}",
        config.program_id,
        config.target.as_str()
    );
    println!("🔗 {}", explorer_link(config));
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

fn print_chain(config: &RingConfig, ring: CustomRing, rpc: &SolanaRpc) -> Result<(), StatusError> {
    if let Ok(authority) = config.authority() {
        let lamports = rpc.get_balance(authority.pubkey())?;
        println!(
            "balance     {} SOL ({lamports} lamports)",
            lamports as f64 / 1_000_000_000.0
        );
    }
    match rpc.get_account(ring.program_id())? {
        Some(account) if account.executable => match read_program_data(rpc, ring)? {
            Some(info) => println!(
                "program     deployed, upgrade authority {}, capacity {} bytes",
                info.upgrade_authority
                    .map(|key| key.to_string())
                    .unwrap_or_else(|| "none (immutable)".to_owned()),
                info.capacity
            ),
            None => println!("program     deployed (not upgradeable)"),
        },
        Some(_) => println!("program     account exists but is not executable"),
        None => println!("program     not deployed"),
    }
    match ring.read_config(rpc)? {
        Some(state) => println!(
            "config      {} authority {} auditor {}",
            ring.config_pda(),
            state.authority,
            hex::encode(state.auditor_pubkey.as_bytes())
        ),
        None => println!("config      not created ({})", ring.config_pda()),
    }
    match ring.read_spp_ring_config(rpc)? {
        Some(state) => println!(
            "spp ring    {} paused={} authority_transact={}",
            ring.ring_auth_pda(),
            state.is_paused(),
            state.enabled()
        ),
        None => println!("spp ring    not registered ({})", ring.ring_auth_pda()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOML: &str = r#"
name = "x"
target = "devnet"
program_id = "11111111111111111111111111111111"
authority_keypair = "a.json"
zolana_revision = "851680f7fcc99ccbd88119942760e9309ace0a58"

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
