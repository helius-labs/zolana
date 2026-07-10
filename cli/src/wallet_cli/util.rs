use anyhow::{bail, Context, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use zolana_client::{create_associated_token_account, Rpc};
use zolana_interface::{pda, state::ProtocolConfig, PROGRAM_ID_PUBKEY};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Address, SOL_MINT};

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

pub(super) fn ensure_positive(amount: u64) -> Result<()> {
    if amount == 0 {
        bail!("amount must be greater than zero");
    }
    Ok(())
}

pub(super) fn fetch_protocol_config<R: Rpc>(rpc: &R) -> Result<Option<ProtocolConfig>> {
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

pub(super) fn resolve_recipient_pubkey(value: &str) -> Result<Pubkey> {
    parse_pubkey(value)
}

pub(super) fn parse_shielded_address(value: &str) -> Result<ShieldedAddress> {
    value.parse::<ShieldedAddress>().with_context(|| {
        format!(
            "invalid shielded address `{value}` (use the value printed by `zolana wallet address`)"
        )
    })
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

pub(super) fn ensure_owner_spl_token_account<R: Rpc>(
    rpc: &R,
    payer: &Keypair,
    owner: Pubkey,
    asset: Address,
) -> Result<Option<Pubkey>> {
    let Some(expected_token_account) = owner_spl_token_account(owner, asset) else {
        return Ok(None);
    };
    let mint = Pubkey::new_from_array(asset.to_bytes());
    let (signature, token_account) = create_associated_token_account(rpc, payer, &owner, &mint)?;
    debug_assert_eq!(token_account, expected_token_account);
    println!(
        "ok associated_token_account account={token_account} owner={owner} mint={mint} signature={signature}"
    );
    Ok(Some(token_account))
}

pub(super) fn owner_spl_token_account(owner: Pubkey, asset: Address) -> Option<Pubkey> {
    (asset != SOL_MINT).then(|| {
        let mint = Pubkey::new_from_array(asset.to_bytes());
        pda::associated_token_address(&owner, &mint)
    })
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
    let mut data = Vec::with_capacity(4 + 8 + 8 + 32);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(&owner.to_bytes());
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
    use std::cell::Cell;

    use super::*;
    use solana_signature::Signature;
    use solana_signer::Signer;
    use zolana_client::ClientError;
    use zolana_keypair::ShieldedKeypair;

    #[derive(Default)]
    struct RecordingRpc {
        sends: Cell<usize>,
    }

    impl Rpc for RecordingRpc {
        fn create_and_send_transaction(
            &self,
            instructions: &[Instruction],
            _payer: Address,
            signers: &[&Keypair],
        ) -> std::result::Result<Signature, ClientError> {
            assert_eq!(instructions.len(), 1);
            assert_eq!(instructions[0].data, vec![1u8]);
            assert_eq!(signers.len(), 1);
            self.sends.set(self.sends.get() + 1);
            Ok(Signature::default())
        }
    }

    #[test]
    fn spl_token_account_is_the_selected_owners_ata() {
        let rpc = RecordingRpc::default();
        let payer = Keypair::new();
        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let asset = Address::new_from_array(mint.to_bytes());

        let token_account = ensure_owner_spl_token_account(&rpc, &payer, owner, asset)
            .expect("ensure ATA")
            .expect("SPL account");

        assert_eq!(token_account, pda::associated_token_address(&owner, &mint));
        assert_eq!(rpc.sends.get(), 1);
        assert_ne!(owner, payer.pubkey());
    }

    #[test]
    fn sol_does_not_create_a_token_account() {
        let rpc = RecordingRpc::default();
        let payer = Keypair::new();

        assert_eq!(
            ensure_owner_spl_token_account(&rpc, &payer, payer.pubkey(), SOL_MINT)
                .expect("SOL account resolution"),
            None
        );
        assert_eq!(rpc.sends.get(), 0);
    }

    #[test]
    fn shielded_recipient_round_trips_through_cli_parser() {
        let address = ShieldedKeypair::new().unwrap().shielded_address().unwrap();

        assert_eq!(
            parse_shielded_address(&address.to_string()).unwrap(),
            address
        );
    }

    #[test]
    fn solana_pubkey_is_not_a_private_recipient() {
        let pubkey = Pubkey::new_unique().to_string();
        let error = parse_shielded_address(&pubkey).unwrap_err().to_string();

        assert!(error.contains("invalid shielded address"));
        assert!(error.contains("zolana wallet address"));
    }

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
