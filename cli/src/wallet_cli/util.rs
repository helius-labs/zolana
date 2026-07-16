use anyhow::{bail, Context, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use zolana_client::Rpc;
use zolana_wallet::create_associated_token_account;
use zolana_interface::{pda, state::ProtocolConfig, PROGRAM_ID_PUBKEY};
use zolana_transaction::{Address, SOL_MINT};

use crate::cli_config::CliConfigFile;

pub(super) fn ensure_positive(amount: u64) -> Result<()> {
    if amount == 0 {
        bail!("amount must be greater than zero");
    }
    Ok(())
}

pub(super) fn parse_address(value: &str) -> Result<Address> {
    if value.eq_ignore_ascii_case("SOL") {
        return Ok(SOL_MINT);
    }
    Ok(Address::new_from_array(parse_pubkey(value)?.to_bytes()))
}

pub(super) fn parse_pubkey(value: &str) -> Result<Pubkey> {
    value
        .parse::<Pubkey>()
        .with_context(|| format!("invalid pubkey `{value}`"))
}

pub(super) fn format_address(address: Address) -> String {
    if address == SOL_MINT {
        "SOL".to_string()
    } else {
        Pubkey::new_from_array(address.to_bytes()).to_string()
    }
}

pub(super) fn configured_spl_token_account(
    config: &CliConfigFile,
    asset: Address,
) -> Result<Option<Pubkey>> {
    if asset == SOL_MINT {
        return Ok(None);
    }
    let mint = Pubkey::new_from_array(asset.to_bytes());
    config
        .token_account_for_mint(mint)?
        .ok_or_else(|| anyhow::anyhow!("no token account configured for SPL mint {mint}; run `zolana dev pool test-mint` or `zolana config asset add --mint {mint} --asset-id <ID> --token-account <ACCOUNT>`"))
        .map(Some)
}

pub(super) fn parse_hex_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).with_context(|| "invalid hex string")?;
    if bytes.len() != N {
        bail!(
            "invalid hex length: expected {N} bytes, got {}",
            bytes.len()
        );
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(super) fn system_create_account_ix(
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

/// Fetch and validate the singleton protocol-config account. Returns `None` when
/// the account does not exist yet (protocol not initialized), and errors only on
/// a present-but-invalid account (wrong owner or malformed payload).
pub(super) fn fetch_protocol_config<R: Rpc + ?Sized>(rpc: &R) -> Result<Option<ProtocolConfig>> {
    let protocol_config = pda::protocol_config();
    let Some(account) = rpc.get_account(Address::new_from_array(protocol_config.to_bytes()))?
    else {
        return Ok(None);
    };
    if account.owner != PROGRAM_ID_PUBKEY {
        bail!(
            "protocol config {protocol_config} has unexpected owner {}; expected {}",
            account.owner,
            PROGRAM_ID_PUBKEY
        );
    }
    let config = ProtocolConfig::from_account_bytes(&account.data).map_err(|err| {
        anyhow::anyhow!("invalid protocol config account {protocol_config}: {err:?}")
    })?;
    Ok(Some(*config))
}

/// Ensure `owner` has an associated token account for `asset`, creating it
/// (funded by `payer`) when needed. No-op for the native SOL asset. Returns the
/// ATA address for SPL assets so callers can settle into it.
pub(super) fn ensure_owner_spl_token_account<R: Rpc>(
    rpc: &R,
    payer: &Keypair,
    owner: Pubkey,
    asset: Address,
) -> Result<Option<Pubkey>> {
    if asset == SOL_MINT {
        return Ok(None);
    }
    let mint = Pubkey::new_from_array(asset.to_bytes());
    let expected = pda::associated_token_address(&owner, &mint);
    let (signature, token_account) = create_associated_token_account(rpc, payer, &owner, &mint)?;
    if token_account != expected {
        bail!("associated token account derivation returned {token_account}; expected {expected}");
    }
    println!(
        "ok associated_token_account account={token_account} owner={owner} mint={mint} signature={signature}"
    );
    Ok(Some(token_account))
}
