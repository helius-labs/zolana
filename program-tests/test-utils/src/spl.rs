//! SPL mint / token-account / interface setup against the client `Rpc` trait, so
//! tests on a real validator can build the SPL state a deposit needs. Mirrors the
//! litesvm helpers on `RingsProgramTest`, but sends through `Rpc`.

use rings_client::{ClientError, Rpc};
use rings_interface::{
    instruction::{CreateAssetCounter, CreateSplInterface},
    pda, SPL_TOKEN_ACCOUNT_LEN, SPL_TOKEN_INITIALIZE_ACCOUNT3_DISCRIMINATOR,
    SPL_TOKEN_INITIALIZE_MINT2_DISCRIMINATOR, SPL_TOKEN_MINT_ACCOUNT_LEN,
    SPL_TOKEN_MINT_TO_DISCRIMINATOR, SPL_TOKEN_PROGRAM_ID,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

fn token_program_id() -> Pubkey {
    Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID)
}

fn to_address(pubkey: &Pubkey) -> Address {
    Address::new_from_array(pubkey.to_bytes())
}

fn system_create_account_ix(
    payer: &Pubkey,
    new_account: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let mut data = vec![0u8; 4 + 8 + 8 + 32];
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    data[12..20].copy_from_slice(&space.to_le_bytes());
    data[20..52].copy_from_slice(&owner.to_bytes());
    Instruction {
        program_id: Pubkey::default(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*new_account, true),
        ],
        data,
    }
}

/// Create and initialize a fresh SPL mint (9 decimals, mint authority = `payer`).
pub fn create_mint<R: Rpc>(rpc: &R, payer: &Keypair) -> Result<Pubkey, ClientError> {
    let mint = Keypair::new();
    let rent = rpc.get_minimum_balance_for_rent_exemption(SPL_TOKEN_MINT_ACCOUNT_LEN)?;
    let create_ix = system_create_account_ix(
        &payer.pubkey(),
        &mint.pubkey(),
        rent,
        SPL_TOKEN_MINT_ACCOUNT_LEN as u64,
        &token_program_id(),
    );
    let mut data = vec![SPL_TOKEN_INITIALIZE_MINT2_DISCRIMINATOR, 9];
    data.extend_from_slice(&payer.pubkey().to_bytes());
    data.push(0);
    let init_ix = Instruction {
        program_id: token_program_id(),
        accounts: vec![AccountMeta::new(mint.pubkey(), false)],
        data,
    };
    rpc.create_and_send_transaction(
        &[create_ix, init_ix],
        to_address(&payer.pubkey()),
        &[payer, &mint],
    )?;
    Ok(mint.pubkey())
}

/// Create and initialize an SPL token account for `mint` owned by `owner`.
pub fn create_token_account<R: Rpc>(
    rpc: &R,
    payer: &Keypair,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Result<Pubkey, ClientError> {
    let account = Keypair::new();
    let rent = rpc.get_minimum_balance_for_rent_exemption(SPL_TOKEN_ACCOUNT_LEN)?;
    let create_ix = system_create_account_ix(
        &payer.pubkey(),
        &account.pubkey(),
        rent,
        SPL_TOKEN_ACCOUNT_LEN as u64,
        &token_program_id(),
    );
    let mut data = vec![SPL_TOKEN_INITIALIZE_ACCOUNT3_DISCRIMINATOR];
    data.extend_from_slice(&owner.to_bytes());
    let init_ix = Instruction {
        program_id: token_program_id(),
        accounts: vec![
            AccountMeta::new(account.pubkey(), false),
            AccountMeta::new_readonly(*mint, false),
        ],
        data,
    };
    rpc.create_and_send_transaction(
        &[create_ix, init_ix],
        to_address(&payer.pubkey()),
        &[payer, &account],
    )?;
    Ok(account.pubkey())
}

/// Mint `amount` of `mint` to `account` (authority = `payer`).
pub fn mint_to<R: Rpc>(
    rpc: &R,
    payer: &Keypair,
    mint: &Pubkey,
    account: &Pubkey,
    amount: u64,
) -> Result<(), ClientError> {
    let mut data = vec![SPL_TOKEN_MINT_TO_DISCRIMINATOR];
    data.extend_from_slice(&amount.to_le_bytes());
    let ix = Instruction {
        program_id: token_program_id(),
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new(*account, false),
            AccountMeta::new_readonly(payer.pubkey(), true),
        ],
        data,
    };
    rpc.create_and_send_transaction(&[ix], to_address(&payer.pubkey()), &[payer])?;
    Ok(())
}

/// Create the singleton SPL asset counter if it does not exist yet.
pub fn ensure_asset_counter<R: Rpc>(rpc: &R, authority: &Keypair) -> Result<(), ClientError> {
    if rpc
        .get_account(to_address(&pda::spl_asset_counter()))?
        .is_none()
    {
        let ix = CreateAssetCounter {
            authority: authority.pubkey(),
        }
        .instruction();
        rpc.create_and_send_transaction(&[ix], to_address(&authority.pubkey()), &[authority])?;
    }
    Ok(())
}

/// Register `mint` with the shielded pool (creates its registry + vault PDAs).
/// Returns `(registry, vault)`.
pub fn create_spl_interface<R: Rpc>(
    rpc: &R,
    authority: &Keypair,
    mint: &Pubkey,
) -> Result<(Pubkey, Pubkey), ClientError> {
    let registry = pda::spl_asset_registry(mint);
    let vault = pda::spl_asset_vault(mint);
    let ix = CreateSplInterface {
        authority: authority.pubkey(),
        mint: *mint,
    }
    .instruction();
    rpc.create_and_send_transaction(&[ix], to_address(&authority.pubkey()), &[authority])?;
    Ok((registry, vault))
}
