//! What the operator sees: the recorded answers and the on-chain state.

use anyhow::Result;
use custom_ring_sdk::{config_pda, ring_auth_pda, PROGRAM_ID};
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};

use crate::{
    config::RingConfig,
    deploy::read_program_data,
    init::{read_config, read_ring_config},
};

pub fn print_status(config: &RingConfig, rpc: &SolanaRpc) -> Result<()> {
    println!("ring        {}", config.name);
    println!("target      {:?}", config.target);
    println!(
        "program id  {} (compiled {})",
        config.program_id, PROGRAM_ID
    );
    match config.authority() {
        Ok(authority) => println!("authority   {}", authority.pubkey()),
        Err(error) => println!("authority   unavailable ({error})"),
    }
    println!("rpc         {}", config.urls.rpc);
    println!("indexer     {}", config.urls.indexer);
    println!("prover      {}", config.urls.prover);
    println!("ring rpc    {}", config.urls.ring_rpc);
    let features: Vec<&str> = config.enabled_features().collect();
    println!("features    {}", features.join(", "));

    let chain = || -> Result<()> {
        match rpc.get_account(config.program_id)? {
            Some(account) if account.executable => match read_program_data(rpc, config.program_id)?
            {
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
        match read_config(rpc)? {
            Some(state) => {
                println!(
                    "config      {} auditor {}",
                    config_pda(),
                    hex::encode(state.auditor_pubkey)
                );
                crate::policy::print(&custom_ring_sdk::RingPolicy::from_config(&state));
            }
            None => println!("config      not created ({})", config_pda()),
        }
        match read_ring_config(rpc)? {
            Some(state) => println!(
                "spp ring    {} paused={} authority_transact={}",
                ring_auth_pda(),
                state.paused != 0,
                state.ring_authority_transact_is_enabled != 0
            ),
            None => println!("spp ring    not registered ({})", ring_auth_pda()),
        }
        Ok(())
    };
    if let Err(error) = chain() {
        println!("chain       unreachable at {} ({error})", config.urls.rpc);
    }
    Ok(())
}
