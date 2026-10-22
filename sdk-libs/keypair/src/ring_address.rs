//! An anonymous ring member's address, its pairing policy and its `zolana:` request form.

use std::{fmt, str::FromStr};

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};
use solana_address::Address;

use crate::{
    error::KeypairError,
    shielded::{ShieldedAddress, SHIELDED_ADDRESS_LEN},
};

pub const RING_ADDRESS_VERSION: u8 = 2;

pub const RING_ADDRESS_CHECKSUM_DOMAIN: &[u8] = b"zolana/ring-addr/v2";

pub const RING_PAYMENT_SCHEME: &str = "zolana:";

pub const MAX_PAIRING_ROWS: usize = 4;

/// `mint(32) ‖ u64be(min_amount)`.
const PAIRING_ROW_LEN: usize = 40;

const CHECKSUM_LEN: usize = 4;

/// `version ‖ recipient ‖ ring_program_id ‖ pairing count`.
const HEADER_LEN: usize = 1 + SHIELDED_ADDRESS_LEN + 32 + 1;

pub const MAX_RING_ADDRESS_PAYLOAD_LEN: usize =
    HEADER_LEN + MAX_PAIRING_ROWS * PAIRING_ROW_LEN + CHECKSUM_LEN;

/// RFC 3986 unreserved characters stay literal, everything else is percent-encoded.
const LABEL_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// A first contact of `mint` worth `min_amount` or more anchors a pair stream, the zero mint
/// matches every asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingRow {
    pub mint: Address,
    pub min_amount: u64,
}

impl PairingRow {
    /// Every asset at any amount, the row a new address carries.
    pub const ANY: Self = Self {
        mint: Address::new_from_array([0; 32]),
        min_amount: 0,
    };

    fn admits(&self, mint: &Address, amount: u64) -> bool {
        (self.mint == Self::ANY.mint || self.mint == *mint) && amount >= self.min_amount
    }
}

/// The first contacts a recipient keeps a pair stream for, a note the recipient never scans for is lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pairing(Vec<PairingRow>);

impl Pairing {
    /// No pair streams, every payment takes the inbox stream.
    pub const fn off() -> Self {
        Self(Vec::new())
    }

    pub fn new(rows: Vec<PairingRow>) -> Result<Self, KeypairError> {
        if rows.len() > MAX_PAIRING_ROWS {
            return Err(KeypairError::InvalidRingAddressPairing(rows.len()));
        }
        Ok(Self(rows))
    }

    pub fn rows(&self) -> &[PairingRow] {
        &self.0
    }

    pub fn is_off(&self) -> bool {
        self.0.is_empty()
    }

    pub fn admits(&self, mint: &Address, amount: u64) -> bool {
        self.0.iter().any(|row| row.admits(mint, amount))
    }
}

impl Default for Pairing {
    fn default() -> Self {
        Self(vec![PairingRow::ANY])
    }
}

/// Shared off chain, never published, `recipient.viewing_pubkey` keys the inbox stream.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingAddress {
    pub recipient: ShieldedAddress,
    pub ring_program_id: Address,
    pub pairing: Pairing,
}

impl RingAddress {
    /// `version ‖ recipient ‖ ring_program_id ‖ count ‖ rows ‖ checksum`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MAX_RING_ADDRESS_PAYLOAD_LEN);
        bytes.push(RING_ADDRESS_VERSION);
        bytes.extend_from_slice(&self.recipient.to_bytes());
        bytes.extend_from_slice(self.ring_program_id.as_array());
        // `Pairing::new` bounds the count by `MAX_PAIRING_ROWS`.
        bytes.push(self.pairing.0.len() as u8);
        for row in &self.pairing.0 {
            bytes.extend_from_slice(row.mint.as_array());
            bytes.extend_from_slice(&row.min_amount.to_be_bytes());
        }
        let checksum = checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeypairError> {
        let (body, checksum_bytes) = bytes
            .split_last_chunk::<CHECKSUM_LEN>()
            .ok_or(KeypairError::InvalidRingAddressLength)?;
        let (header, rows) = body
            .split_at_checked(HEADER_LEN)
            .ok_or(KeypairError::InvalidRingAddressLength)?;
        let (&version, header) = header
            .split_first()
            .ok_or(KeypairError::InvalidRingAddressLength)?;
        if version != RING_ADDRESS_VERSION {
            return Err(KeypairError::UnknownRingAddressVersion(version));
        }
        let (recipient, header) = header
            .split_first_chunk::<SHIELDED_ADDRESS_LEN>()
            .ok_or(KeypairError::InvalidRingAddressLength)?;
        let (program, count) = header
            .split_first_chunk::<32>()
            .ok_or(KeypairError::InvalidRingAddressLength)?;
        let count = usize::from(count[0]);
        if count > MAX_PAIRING_ROWS {
            return Err(KeypairError::InvalidRingAddressPairing(count));
        }
        if rows.len() != count * PAIRING_ROW_LEN {
            return Err(KeypairError::InvalidRingAddressLength);
        }
        if *checksum_bytes != checksum(body) {
            return Err(KeypairError::InvalidRingAddressChecksum);
        }
        let rows = rows
            .as_chunks::<PAIRING_ROW_LEN>()
            .0
            .iter()
            .map(|row| {
                let (mint, min_amount) = row.split_at(32);
                PairingRow {
                    mint: Address::new_from_array(core::array::from_fn(|i| mint[i])),
                    min_amount: u64::from_be_bytes(core::array::from_fn(|i| min_amount[i])),
                }
            })
            .collect();
        Ok(Self {
            recipient: ShieldedAddress::from_bytes(recipient)?,
            ring_program_id: Address::new_from_array(*program),
            pairing: Pairing(rows),
        })
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    pub fn from_base58(text: &str) -> Result<Self, KeypairError> {
        let mut bytes = [0u8; MAX_RING_ADDRESS_PAYLOAD_LEN];
        let len = bs58::decode(text)
            .onto(&mut bytes)
            .map_err(|error| match error {
                bs58::decode::Error::BufferTooSmall => KeypairError::InvalidRingAddressLength,
                _ => KeypairError::InvalidRingAddressBase58,
            })?;
        Self::from_bytes(&bytes[..len])
    }
}

/// The first 4 bytes of `SHA256(domain ‖ body)`.
fn checksum(body: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::new()
        .chain_update(RING_ADDRESS_CHECKSUM_DOMAIN)
        .chain_update(body)
        .finalize();
    core::array::from_fn(|i| digest[i])
}

/// `zolana:<address>?amount=&mint=&label=`, the query part is unauthenticated.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingPaymentRequest {
    pub address: RingAddress,
    pub amount: Option<u64>,
    pub mint: Option<Address>,
    pub label: Option<String>,
}

impl RingPaymentRequest {
    pub fn new(address: RingAddress) -> Self {
        Self {
            address,
            amount: None,
            mint: None,
            label: None,
        }
    }
}

impl fmt::Display for RingPaymentRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(RING_PAYMENT_SCHEME)?;
        formatter.write_str(&self.address.to_base58())?;
        let mut separator = '?';
        let mut write = |key: &str, value: fmt::Arguments<'_>| -> fmt::Result {
            write!(formatter, "{separator}{key}={value}")?;
            separator = '&';
            Ok(())
        };
        if let Some(amount) = self.amount {
            write("amount", format_args!("{amount}"))?;
        }
        if let Some(mint) = &self.mint {
            write("mint", format_args!("{mint}"))?;
        }
        if let Some(label) = &self.label {
            write(
                "label",
                format_args!("{}", utf8_percent_encode(label, LABEL_ENCODE_SET)),
            )?;
        }
        Ok(())
    }
}

impl FromStr for RingPaymentRequest {
    type Err = KeypairError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let rest = text
            .trim()
            .strip_prefix(RING_PAYMENT_SCHEME)
            .ok_or(KeypairError::InvalidRingAddressScheme)?;
        let (address, query) = match rest.split_once('?') {
            Some((address, query)) => (address, Some(query)),
            None => (rest, None),
        };
        let mut request = Self::new(RingAddress::from_base58(address)?);
        for part in query.into_iter().flat_map(|query| query.split('&')) {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            match key {
                "amount" => replace_once(&mut request.amount, parse_amount(value)?)?,
                "mint" => replace_once(&mut request.mint, parse_mint(value)?)?,
                "label" => replace_once(&mut request.label, parse_label(value)?)?,
                _ => return Err(KeypairError::UnknownRingPaymentKey),
            }
        }
        Ok(request)
    }
}

fn replace_once<T>(slot: &mut Option<T>, value: T) -> Result<(), KeypairError> {
    if slot.replace(value).is_some() {
        return Err(KeypairError::DuplicateRingPaymentKey);
    }
    Ok(())
}

fn parse_amount(value: &str) -> Result<u64, KeypairError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(KeypairError::InvalidRingPaymentAmount);
    }
    value
        .parse()
        .map_err(|_| KeypairError::InvalidRingPaymentAmount)
}

fn parse_mint(value: &str) -> Result<Address, KeypairError> {
    value
        .parse()
        .map_err(|_| KeypairError::InvalidRingPaymentMint)
}

/// `percent_decode_str` keeps a bare `%`, every escape must be two hex digits.
fn parse_label(value: &str) -> Result<String, KeypairError> {
    let escapes_complete = value.split('%').skip(1).all(|after| {
        after.len() >= 2 && after.bytes().take(2).all(|byte| byte.is_ascii_hexdigit())
    });
    if !escapes_complete {
        return Err(KeypairError::InvalidRingPaymentLabel);
    }
    percent_decode_str(value)
        .decode_utf8()
        .map(|label| label.into_owned())
        .map_err(|_| KeypairError::InvalidRingPaymentLabel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_escapes_everything_outside_the_unreserved_set() {
        let encoded = utf8_percent_encode("a b&c=d/é-._~!*'()", LABEL_ENCODE_SET).to_string();
        assert_eq!(encoded, "a%20b%26c%3Dd%2F%C3%A9-._~%21%2A%27%28%29");
        assert_eq!(parse_label(&encoded).unwrap(), "a b&c=d/é-._~!*'()");
    }

    #[test]
    fn label_rejects_incomplete_or_non_utf8_escapes() {
        for value in ["%", "%2", "%zz", "a%2", "%80"] {
            assert_eq!(
                parse_label(value).unwrap_err(),
                KeypairError::InvalidRingPaymentLabel
            );
        }
    }

    #[test]
    fn amount_rejects_signs_blanks_and_overflow() {
        for value in ["", "+1", "-1", " 1", "1.0", "18446744073709551616"] {
            assert_eq!(
                parse_amount(value).unwrap_err(),
                KeypairError::InvalidRingPaymentAmount
            );
        }
        assert_eq!(parse_amount("18446744073709551615").unwrap(), u64::MAX);
    }

    /// The zero mint is SOL's address too, so a SOL-only row cannot be written.
    #[test]
    fn a_row_admits_its_mint_at_or_above_its_minimum_and_the_zero_mint_every_asset() {
        let usdc = Address::new_from_array([7; 32]);
        let other = Address::new_from_array([8; 32]);
        let pairing = Pairing::new(vec![PairingRow {
            mint: usdc,
            min_amount: 100,
        }])
        .unwrap();
        assert!(pairing.admits(&usdc, 100));
        assert!(!pairing.admits(&usdc, 99));
        assert!(!pairing.admits(&other, 1_000));
        assert!(Pairing::default().admits(&other, 0));
        assert!(!Pairing::off().admits(&usdc, u64::MAX));
    }
}
