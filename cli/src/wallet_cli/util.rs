use anyhow::{bail, Context, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_transaction::{Address, SOL_MINT};

use super::material::load_existing_wallet;
use crate::cli_config::{wallet_file, CliConfigFile};

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

pub(super) fn ensure_positive(amount: u64) -> Result<()> {
    if amount == 0 {
        bail!("amount must be greater than zero");
    }
    Ok(())
}

/// Parse a decimal SOL string into lamports. Rejects negative/NaN input and more
/// than 9 fractional digits (finer than a lamport), and errors on overflow.
pub(super) fn parse_sol_amount(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        bail!("amount must not be empty");
    }
    if s.starts_with('-') {
        bail!("amount must not be negative: `{s}`");
    }
    let (whole_str, frac_str) = match s.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (s, ""),
    };
    // Reject anything that is not pure decimal digits (rules out `NaN`, `1e9`,
    // `+1`, `0x..`, embedded signs, and stray separators).
    let is_digits = |part: &str| part.bytes().all(|b| b.is_ascii_digit());
    if whole_str.is_empty() && frac_str.is_empty() {
        bail!("invalid SOL amount: `{s}`");
    }
    if !is_digits(whole_str) || !is_digits(frac_str) {
        bail!("invalid SOL amount: `{s}`");
    }
    if frac_str.len() > 9 {
        bail!("SOL amount `{s}` has more than 9 fractional digits (finer than a lamport)");
    }
    let whole: u64 = if whole_str.is_empty() {
        0
    } else {
        whole_str
            .parse()
            .with_context(|| format!("SOL amount `{s}` overflows"))?
    };
    let whole_lamports = whole
        .checked_mul(LAMPORTS_PER_SOL)
        .with_context(|| format!("SOL amount `{s}` overflows"))?;
    // Right-pad the fractional part to 9 digits so it reads as lamports directly.
    let mut frac_lamports = 0u64;
    if !frac_str.is_empty() {
        let padded = format!("{frac_str:0<9}");
        frac_lamports = padded
            .parse()
            .with_context(|| format!("invalid SOL amount: `{s}`"))?;
    }
    whole_lamports
        .checked_add(frac_lamports)
        .with_context(|| format!("SOL amount `{s}` overflows"))
}

/// Format lamports as a trimmed decimal SOL string (e.g. 50_000_000 -> "0.05").
pub(super) fn lamports_to_sol_string(lamports: u64) -> String {
    let whole = lamports / LAMPORTS_PER_SOL;
    let frac = lamports % LAMPORTS_PER_SOL;
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:09}");
    let frac = frac.trim_end_matches('0');
    format!("{whole}.{frac}")
}

/// Convert a raw amount argument into base units for the given asset. Human SOL
/// units apply to the SOL mint only; SPL assets do not store decimals, so their
/// amount is interpreted as raw base units.
pub(super) fn parse_amount_for_asset(amount: &str, asset: Address) -> Result<u64> {
    if asset == SOL_MINT {
        parse_sol_amount(amount)
    } else {
        amount
            .trim()
            .parse::<u64>()
            .with_context(|| format!("invalid base-unit amount `{amount}`"))
    }
}

/// Resolve a `<to>` recipient argument to a pubkey. A local wallet name resolves
/// to that wallet's owner pubkey; anything else is parsed as a Solana pubkey.
pub(super) fn resolve_recipient_pubkey(value: &str, _config: &CliConfigFile) -> Result<Pubkey> {
    let path = wallet_file(value);
    if path.exists() {
        return Ok(load_existing_wallet(&path)?.owner_pubkey());
    }
    parse_pubkey(value)
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

/// System-program `Transfer` instruction (instruction index 2), mirroring the
/// raw layout used by `system_create_account_ix`.
pub(super) fn system_transfer_ix(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = vec![0u8; 4 + 8];
    data[0..4].copy_from_slice(&2u32.to_le_bytes());
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: Pubkey::default(),
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sol_amount_handles_round_and_fractional_values() {
        assert_eq!(parse_sol_amount("1").unwrap(), 1_000_000_000);
        assert_eq!(parse_sol_amount("0").unwrap(), 0);
        assert_eq!(parse_sol_amount("0.05").unwrap(), 50_000_000);
        assert_eq!(parse_sol_amount("0.5").unwrap(), 500_000_000);
        assert_eq!(parse_sol_amount("1.5").unwrap(), 1_500_000_000);
        assert_eq!(parse_sol_amount("0.000000001").unwrap(), 1);
        assert_eq!(parse_sol_amount(".5").unwrap(), 500_000_000);
        assert_eq!(parse_sol_amount("2.").unwrap(), 2_000_000_000);
        assert_eq!(parse_sol_amount("  1.25  ").unwrap(), 1_250_000_000);
    }

    #[test]
    fn parse_sol_amount_rejects_bad_input() {
        assert!(parse_sol_amount("").is_err());
        assert!(parse_sol_amount("-1").is_err());
        assert!(parse_sol_amount("abc").is_err());
        assert!(parse_sol_amount("NaN").is_err());
        assert!(parse_sol_amount("1e9").is_err());
        assert!(parse_sol_amount("+1").is_err());
        assert!(parse_sol_amount("1.2.3").is_err());
        // More than 9 fractional digits is finer than a lamport.
        assert!(parse_sol_amount("0.0000000001").is_err());
    }

    #[test]
    fn parse_sol_amount_errors_on_overflow() {
        // u64::MAX lamports is ~18.4B SOL; 19B SOL overflows.
        assert!(parse_sol_amount("19000000000").is_err());
        assert!(parse_sol_amount("99999999999999999999").is_err());
    }

    #[test]
    fn lamports_to_sol_string_formats_trimmed_decimals() {
        assert_eq!(lamports_to_sol_string(0), "0");
        assert_eq!(lamports_to_sol_string(1_000_000_000), "1");
        assert_eq!(lamports_to_sol_string(50_000_000), "0.05");
        assert_eq!(lamports_to_sol_string(1_500_000_000), "1.5");
        assert_eq!(lamports_to_sol_string(1), "0.000000001");
    }

    #[test]
    fn parse_amount_for_asset_switches_on_mint() {
        // SOL mint -> human units.
        assert_eq!(
            parse_amount_for_asset("0.05", SOL_MINT).unwrap(),
            50_000_000
        );
        // SPL mint -> raw base units, no decimal interpretation.
        let spl = parse_address("Mint111111111111111111111111111111111111111").unwrap();
        assert_eq!(parse_amount_for_asset("1000000", spl).unwrap(), 1_000_000);
        // A decimal for an SPL mint is not valid base units.
        assert!(parse_amount_for_asset("0.05", spl).is_err());
    }
}
