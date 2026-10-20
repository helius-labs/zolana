//! Off chain address of an anonymous ring member and its `zolana:` payment request form.

use std::{fmt, str::FromStr};

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};
use solana_address::Address;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    derivation,
    error::KeypairError,
    shielded::{ShieldedAddress, SHIELDED_ADDRESS_LEN},
    viewing_key::ViewTag,
};

pub const RING_ADDRESS_VERSION: u8 = 1;

pub const RING_ADDRESS_CHECKSUM_DOMAIN: &[u8] = b"zolana/ring-addr/v1";

pub const RING_PAYMENT_SCHEME: &str = "zolana:";

const CHECKSUM_LEN: usize = 4;

/// `version || recipient || ring_program_id || inbox_secret || checksum`.
pub const RING_ADDRESS_PAYLOAD_LEN: usize = 1 + SHIELDED_ADDRESS_LEN + 32 + 32 + CHECKSUM_LEN;

/// RFC 3986 unreserved characters stay literal, everything else is percent-encoded.
const LABEL_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Holding it lets a payer derive the recipient's inbox tags.
#[derive(Clone)]
pub struct InboxSecret(Zeroizing<[u8; 32]>);

impl PartialEq for InboxSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&*other.0).into()
    }
}

impl Eq for InboxSecret {}

impl InboxSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Tag of the `j`th first payment to the address.
    pub fn view_tag(&self, j: u64) -> Result<ViewTag, KeypairError> {
        derivation::inbox_view_tag(&self.0, j)
    }
}

impl fmt::Debug for InboxSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InboxSecret(..)")
    }
}

/// Shared off chain, never published.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingAddress {
    pub recipient: ShieldedAddress,
    pub ring_program_id: Address,
    pub inbox_secret: InboxSecret,
}

impl RingAddress {
    pub fn to_bytes(&self) -> [u8; RING_ADDRESS_PAYLOAD_LEN] {
        let mut bytes = [0u8; RING_ADDRESS_PAYLOAD_LEN];
        let (body, checksum) = bytes.split_at_mut(RING_ADDRESS_PAYLOAD_LEN - CHECKSUM_LEN);
        let (version, rest) = body.split_at_mut(1);
        let (recipient, rest) = rest.split_at_mut(SHIELDED_ADDRESS_LEN);
        let (program, inbox) = rest.split_at_mut(32);
        version[0] = RING_ADDRESS_VERSION;
        recipient.copy_from_slice(&self.recipient.to_bytes());
        program.copy_from_slice(self.ring_program_id.as_array());
        inbox.copy_from_slice(self.inbox_secret.as_bytes());
        checksum.copy_from_slice(&Self::checksum(body));
        bytes
    }

    pub fn from_bytes(bytes: &[u8; RING_ADDRESS_PAYLOAD_LEN]) -> Result<Self, KeypairError> {
        let (body, checksum) = bytes.split_at(RING_ADDRESS_PAYLOAD_LEN - CHECKSUM_LEN);
        let (version, rest) = body.split_at(1);
        let (recipient, rest) = rest.split_at(SHIELDED_ADDRESS_LEN);
        let (program, inbox) = rest.split_at(32);
        if version[0] != RING_ADDRESS_VERSION {
            return Err(KeypairError::UnknownRingAddressVersion(version[0]));
        }
        if checksum != Self::checksum(body) {
            return Err(KeypairError::InvalidRingAddressChecksum);
        }
        let recipient: &[u8; SHIELDED_ADDRESS_LEN] = recipient
            .try_into()
            .map_err(|_| KeypairError::InvalidRingAddressLength)?;
        let program: [u8; 32] = program
            .try_into()
            .map_err(|_| KeypairError::InvalidRingAddressLength)?;
        let inbox: [u8; 32] = inbox
            .try_into()
            .map_err(|_| KeypairError::InvalidRingAddressLength)?;
        Ok(Self {
            recipient: ShieldedAddress::from_bytes(recipient)?,
            ring_program_id: Address::new_from_array(program),
            inbox_secret: InboxSecret::from_bytes(inbox),
        })
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    pub fn from_base58(text: &str) -> Result<Self, KeypairError> {
        let mut bytes = [0u8; RING_ADDRESS_PAYLOAD_LEN];
        let len = bs58::decode(text)
            .onto(&mut bytes)
            .map_err(|error| match error {
                bs58::decode::Error::BufferTooSmall => KeypairError::InvalidRingAddressLength,
                _ => KeypairError::InvalidRingAddressBase58,
            })?;
        if len != RING_ADDRESS_PAYLOAD_LEN {
            return Err(KeypairError::InvalidRingAddressLength);
        }
        Self::from_bytes(&bytes)
    }

    fn checksum(body: &[u8]) -> [u8; CHECKSUM_LEN] {
        let digest = Sha256::new()
            .chain_update(RING_ADDRESS_CHECKSUM_DOMAIN)
            .chain_update(body)
            .finalize();
        let mut checksum = [0u8; CHECKSUM_LEN];
        checksum.copy_from_slice(&digest[..CHECKSUM_LEN]);
        checksum
    }
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
}
