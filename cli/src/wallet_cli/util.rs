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

/// A `--to` recipient: either a self-contained shielded address (shared
/// directly) or a Solana pubkey (resolved through the user registry).
pub(super) enum RecipientInput {
    Shielded(ShieldedAddress),
    Pubkey(Pubkey),
}

/// Disambiguate a `--to` value. A versioned Base58Check shielded address parses
/// as `Shielded`; anything else must be a Solana pubkey. The caller decides how
/// to resolve a pubkey (registry lookup, public fallback, etc.).
pub(super) fn parse_recipient(value: &str) -> Result<RecipientInput> {
    if let Ok(address) = value.parse::<ShieldedAddress>() {
        return Ok(RecipientInput::Shielded(address));
    }
    let owner = value.parse::<Pubkey>().map_err(|_| {
        anyhow::anyhow!(
            "invalid recipient `{value}`: expected a shielded address (from `zolana wallet address`) or a Solana pubkey"
        )
    })?;
    Ok(RecipientInput::Pubkey(owner))
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
    fn parse_recipient_accepts_shielded_address() {
        let address = ShieldedKeypair::new()
            .expect("keypair")
            .shielded_address()
            .expect("address");

        match parse_recipient(&address.to_string()).expect("parse recipient") {
            RecipientInput::Shielded(parsed) => assert_eq!(parsed, address),
            RecipientInput::Pubkey(_) => panic!("a shielded address must parse as Shielded"),
        }
    }

    #[test]
    fn parse_recipient_accepts_solana_pubkey() {
        let pubkey = Pubkey::new_unique();

        match parse_recipient(&pubkey.to_string()).expect("parse recipient") {
            RecipientInput::Pubkey(parsed) => assert_eq!(parsed, pubkey),
            RecipientInput::Shielded(_) => panic!("a Solana pubkey must parse as Pubkey"),
        }
    }

    #[test]
    fn parse_recipient_rejects_invalid_input() {
        let err = match parse_recipient("definitely-not-valid") {
            Ok(_) => panic!("must reject an input that is neither an address nor a pubkey"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("shielded address"));
        assert!(err.to_string().contains("Solana pubkey"));
    }
}
