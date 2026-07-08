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
    state::SplAssetRegistry,
    PROGRAM_ID_PUBKEY, SPL_TOKEN_ACCOUNT_LEN, SPL_TOKEN_INITIALIZE_ACCOUNT3_DISCRIMINATOR,
    SPL_TOKEN_INITIALIZE_MINT2_DISCRIMINATOR, SPL_TOKEN_MINT_ACCOUNT_LEN,
    SPL_TOKEN_MINT_TO_DISCRIMINATOR, SPL_TOKEN_PROGRAM_ID,
};
use zolana_transaction::Address;

use super::{
    material::{load_existing_wallet, load_sender_from_resolved_sync},
    resolve::resolve_sync,
    util::{ensure_positive, system_create_account_ix},
};
use crate::{args::TestMintOptions, cli_config::CliConfigFile};

pub(crate) fn run_test_mint(opts: TestMintOptions) -> Result<()> {
    ensure_positive(opts.amount)?;
    let sync = resolve_sync(&opts.sync)?;
    let material = load_sender_from_resolved_sync(&sync)?;
    let authority_material = opts
        .authority_path
        .as_deref()
        .map(|path| load_existing_wallet(Path::new(path)))
        .transpose()?;
    let authority_material = authority_material.as_ref().unwrap_or(&material);
    let authority = &authority_material.funding;
    let mut rpc = SolanaRpc::new(sync.rpc_url);

    if let Some(lamports) = opts.airdrop_lamports {
        let signature = rpc.airdrop(&authority.pubkey(), lamports)?;
        println!(
            "ok airdrop authority={} signature={signature}",
            authority.pubkey()
        );
    }

    let mint = create_mint(&rpc, authority)?;
    let token_account = create_token_account(&rpc, authority, &mint, &material.funding.pubkey())?;
    mint_to(&rpc, authority, &mint, &token_account, opts.amount)?;
    ensure_asset_counter(&rpc, authority)?;
    ensure_spl_interface(&rpc, authority, &mint)?;
    let asset_id = fetch_asset_id(&rpc, &mint)?;

    let mut config = CliConfigFile::load()?;
    config.upsert_asset(mint, asset_id, Some(token_account))?;

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

fn create_token_account(
    rpc: &SolanaRpc,
    payer: &Keypair,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Result<Pubkey> {
    let token_account = Keypair::new();
    let rent = rpc.get_minimum_balance_for_rent_exemption(SPL_TOKEN_ACCOUNT_LEN)?;
    let create_ix = system_create_account_ix(
        &payer.pubkey(),
        &token_account.pubkey(),
        rent,
        SPL_TOKEN_ACCOUNT_LEN as u64,
        &token_program_id(),
    );
    let mut data = vec![SPL_TOKEN_INITIALIZE_ACCOUNT3_DISCRIMINATOR];
    data.extend_from_slice(&owner.to_bytes());
    let init_ix = Instruction {
        program_id: token_program_id(),
        accounts: vec![
            AccountMeta::new(token_account.pubkey(), false),
            AccountMeta::new_readonly(*mint, false),
        ],
        data,
    };
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let signature = rpc.create_and_send_transaction(
        &[create_ix, init_ix],
        payer_address,
        &[payer, &token_account],
    )?;
    println!(
        "ok create_token_account account={} owner={} signature={signature}",
        token_account.pubkey(),
        owner
    );
    Ok(token_account.pubkey())
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
