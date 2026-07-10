use anyhow::{bail, Context, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_keypair::ShieldedAddress;
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

pub(super) fn parse_shielded_address(value: &str) -> Result<ShieldedAddress> {
    value.parse::<ShieldedAddress>().with_context(|| {
        format!(
            "invalid shielded address `{value}`; use the value printed by `zolana wallet address`"
        )
    })
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
        .ok_or_else(|| anyhow::anyhow!("no token account configured for SPL mint {mint}; run `zolana wallet test-mint` or `zolana config add-asset --mint {mint} --asset-id <ID> --token-account <ACCOUNT>`"))
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

#[cfg(test)]
mod tests {
    use zolana_keypair::ShieldedKeypair;

    use super::*;

    #[test]
    fn shielded_address_round_trips_through_cli_parser() {
        let address = ShieldedKeypair::new()
            .expect("keypair")
            .shielded_address()
            .expect("address");

        assert_eq!(
            parse_shielded_address(&address.to_string()).expect("parse address"),
            address
        );
    }

    #[test]
    fn shielded_address_rejects_solana_pubkey_with_actionable_hint() {
        let pubkey = Pubkey::new_unique().to_string();
        let err = parse_shielded_address(&pubkey).expect_err("pubkey is not shielded address");

        assert!(err.to_string().contains("invalid shielded address"));
        assert!(err.to_string().contains("wallet address"));
    }
}
