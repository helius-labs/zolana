use std::path::Path;

use anyhow::{bail, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{
    instruction::{CreateAssetCounter, CreateSplInterface},
    pda,
    state::{ProtocolConfig, SplAssetRegistry},
    PROGRAM_ID_PUBKEY, SPL_TOKEN_INITIALIZE_MINT2_DISCRIMINATOR, SPL_TOKEN_MINT_ACCOUNT_LEN,
    SPL_TOKEN_MINT_TO_DISCRIMINATOR, SPL_TOKEN_PROGRAM_ID,
};
use zolana_transaction::Address;

use super::{
    material::load_existing_wallet,
    util::{
        ensure_owner_spl_token_account, ensure_positive, fetch_protocol_config,
        system_create_account_ix,
    },
};
use crate::{
    args::TestMintOptions,
    cli_config::{resolve_keypair_path, resolve_rpc_url, CliConfigFile},
};

pub(crate) fn run_test_mint(opts: TestMintOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let mut config = CliConfigFile::load()?;
    let keypair_path = resolve_keypair_path(opts.keypair.keypair.as_deref(), &config);
    let material = load_existing_wallet(&keypair_path)?;
    let authority_material = opts
        .authority_path
        .as_deref()
        .map(|path| load_existing_wallet(Path::new(path)))
        .transpose()?;
    let authority_material = authority_material.as_ref().unwrap_or(&material);
    let authority = &authority_material.funding;
    let mut rpc = SolanaRpc::new(resolve_rpc_url(None, &config));

    preflight_protocol_config(&rpc, authority.pubkey())?;

    if let Some(lamports) = opts.airdrop_lamports {
        let signature = rpc.airdrop(&authority.pubkey(), lamports)?;
        println!(
            "ok airdrop authority={} signature={signature}",
            authority.pubkey()
        );
    }

    let mint = create_mint(&rpc, authority)?;
    let token_account = ensure_owner_spl_token_account(
        &rpc,
        authority,
        material.funding.pubkey(),
        Address::new_from_array(mint.to_bytes()),
    )?
    .ok_or_else(|| anyhow::anyhow!("SPL mint unexpectedly resolved to the SOL asset"))?;
    mint_to(&rpc, authority, &mint, &token_account, opts.amount)?;
    ensure_asset_counter(&rpc, authority)?;
    ensure_spl_interface(&rpc, authority, &mint)?;
    let asset_id = fetch_asset_id(&rpc, &mint)?;

    config.upsert_asset(mint, asset_id)?;

    println!(
        "ok test_mint mint={} asset_id={} token_account={} owner={} amount={}",
        mint,
        asset_id,
        token_account,
        material.funding.pubkey(),
        opts.amount
    );
    Ok(())
}

fn preflight_protocol_config<R: Rpc>(rpc: &R, authority: Pubkey) -> Result<()> {
    let protocol_config = pda::protocol_config();
    let config = fetch_protocol_config(rpc)?.ok_or_else(|| {
        anyhow::anyhow!(
            "protocol config not found at {protocol_config}; run `zolana create-tree` first"
        )
    })?;
    let asset_counter_exists = rpc
        .get_account(Address::new_from_array(pda::spl_asset_counter().to_bytes()))?
        .is_some();
    validate_spl_creation_policy(&config, authority, asset_counter_exists)
}

fn validate_spl_creation_policy(
    config: &ProtocolConfig,
    authority: Pubkey,
    asset_counter_exists: bool,
) -> Result<()> {
    let authority_address = Address::new_from_array(authority.to_bytes());
    let is_protocol_authority = config.check_protocol_authority(&authority_address).is_ok();

    if !asset_counter_exists && !is_protocol_authority {
        bail!(
            "SPL asset counter is not initialized and wallet {authority} is not the protocol authority"
        );
    }
    if !is_protocol_authority && !config.allows_permissionless_spl_interface_creation() {
        bail!(
            "wallet {authority} is not the protocol authority and SPL interface creation is not permissionless"
        );
    }
    Ok(())
}

fn token_program_id() -> Pubkey {
    Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID)
}

fn create_mint(rpc: &SolanaRpc, authority: &Keypair) -> Result<Pubkey> {
    let mint = Keypair::new();
    let rent = rpc.get_minimum_balance_for_rent_exemption(SPL_TOKEN_MINT_ACCOUNT_LEN)?;
    let create_ix = system_create_account_ix(
        &authority.pubkey(),
        &mint.pubkey(),
        rent,
        SPL_TOKEN_MINT_ACCOUNT_LEN as u64,
        &token_program_id(),
    );
    let mut data = vec![SPL_TOKEN_INITIALIZE_MINT2_DISCRIMINATOR, 9];
    data.extend_from_slice(&authority.pubkey().to_bytes());
    data.push(0);
    let init_ix = Instruction {
        program_id: token_program_id(),
        accounts: vec![AccountMeta::new(mint.pubkey(), false)],
        data,
    };
    let payer = Address::new_from_array(authority.pubkey().to_bytes());
    let signature =
        rpc.create_and_send_transaction(&[create_ix, init_ix], payer, &[authority, &mint])?;
    println!(
        "ok create_mint mint={} signature={signature}",
        mint.pubkey()
    );
    Ok(mint.pubkey())
}

fn mint_to(
    rpc: &SolanaRpc,
    authority: &Keypair,
    mint: &Pubkey,
    token_account: &Pubkey,
    amount: u64,
) -> Result<()> {
    let mut data = vec![SPL_TOKEN_MINT_TO_DISCRIMINATOR];
    data.extend_from_slice(&amount.to_le_bytes());
    let ix = Instruction {
        program_id: token_program_id(),
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new(*token_account, false),
            AccountMeta::new_readonly(authority.pubkey(), true),
        ],
        data,
    };
    let payer = Address::new_from_array(authority.pubkey().to_bytes());
    let signature = rpc.create_and_send_transaction(&[ix], payer, &[authority])?;
    println!("ok mint_to amount={amount} signature={signature}");
    Ok(())
}

fn ensure_asset_counter(rpc: &SolanaRpc, authority: &Keypair) -> Result<()> {
    let counter = pda::spl_asset_counter();
    if rpc
        .get_account(Address::new_from_array(counter.to_bytes()))?
        .is_some()
    {
        println!("ok spl_asset_counter account={counter} status=exists");
        return Ok(());
    }
    let ix = CreateAssetCounter {
        authority: authority.pubkey(),
    }
    .instruction();
    let payer = Address::new_from_array(authority.pubkey().to_bytes());
    let signature = rpc.create_and_send_transaction(&[ix], payer, &[authority])?;
    println!("ok create_asset_counter account={counter} signature={signature}");
    Ok(())
}

fn ensure_spl_interface(rpc: &SolanaRpc, authority: &Keypair, mint: &Pubkey) -> Result<()> {
    let registry = pda::spl_asset_registry(mint);
    if rpc
        .get_account(Address::new_from_array(registry.to_bytes()))?
        .is_some()
    {
        println!("ok spl_interface mint={mint} registry={registry} status=exists");
        return Ok(());
    }
    let ix = CreateSplInterface {
        authority: authority.pubkey(),
        mint: *mint,
    }
    .instruction();
    let payer = Address::new_from_array(authority.pubkey().to_bytes());
    let signature = rpc.create_and_send_transaction(&[ix], payer, &[authority])?;
    println!("ok create_spl_interface mint={mint} registry={registry} signature={signature}");
    Ok(())
}

fn fetch_asset_id(rpc: &SolanaRpc, mint: &Pubkey) -> Result<u64> {
    let registry = pda::spl_asset_registry(mint);
    let account = rpc
        .get_account(Address::new_from_array(registry.to_bytes()))?
        .ok_or_else(|| anyhow::anyhow!("SPL asset registry not found for mint {mint}"))?;
    if account.owner != PROGRAM_ID_PUBKEY {
        bail!(
            "SPL asset registry {registry} has unexpected owner {}",
            account.owner
        );
    }
    if account.data.len() != SplAssetRegistry::SIZE {
        bail!(
            "SPL asset registry {registry} has invalid size {}; expected {}",
            account.data.len(),
            SplAssetRegistry::SIZE
        );
    }
    if account.data[0] != zolana_interface::state::discriminator::SPL_ASSET_REGISTRY {
        bail!("SPL asset registry {registry} has invalid discriminator");
    }
    if account.data[8..40] != mint.to_bytes() {
        bail!("SPL asset registry {registry} has mismatched mint");
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&account.data[40..48]);
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_interface::state::discriminator::PROTOCOL_CONFIG;

    fn protocol_config(authority: Pubkey, permissionless: bool) -> ProtocolConfig {
        let authority = Address::new_from_array(authority.to_bytes());
        ProtocolConfig {
            discriminator: PROTOCOL_CONFIG,
            protocol_authority: authority,
            tree_creation_authority: authority,
            forester_authority: authority,
            zone_creation_authority: authority,
            tree_creation_is_permissionless: 0,
            zone_creation_is_permissionless: 0,
            spl_interface_creation_is_permissionless: u8::from(permissionless),
        }
    }

    #[test]
    fn protocol_authority_can_create_counter_and_interface() {
        let authority = Pubkey::new_unique();
        let config = protocol_config(authority, false);

        validate_spl_creation_policy(&config, authority, false).expect("protocol authority");
    }

    #[test]
    fn permissionless_creator_still_requires_initialized_counter() {
        let authority = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        let config = protocol_config(authority, true);

        validate_spl_creation_policy(&config, other, true).expect("permissionless interface");
        assert!(validate_spl_creation_policy(&config, other, false).is_err());
    }

    #[test]
    fn non_authority_is_rejected_when_interface_creation_is_restricted() {
        let config = protocol_config(Pubkey::new_unique(), false);

        assert!(validate_spl_creation_policy(&config, Pubkey::new_unique(), true).is_err());
    }
}
