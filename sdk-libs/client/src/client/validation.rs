use solana_address::Address;
use solana_pubkey::Pubkey;
use url::Url;

use crate::{error::ClientError, prover::endpoint::is_loopback};

/// Reject a service URL that would carry shielded material in plaintext:
/// anything but https, or http to loopback (`localhost` or a name under it,
/// `127.0.0.0/8`, `[::1]`). [`SprClient::from_urls`] runs it; a caller
/// building its own indexer and prover clients runs it itself.
///
/// [`SprClient::from_urls`]: super::SprClient::from_urls
pub fn check_service_url(url: &str, field: &'static str) -> Result<(), ClientError> {
    let secure = Url::parse(url).is_ok_and(|parsed| match parsed.scheme() {
        "https" => true,
        "http" => is_loopback(&parsed),
        _ => false,
    });
    if secure {
        Ok(())
    } else {
        Err(ClientError::InsecureServiceUrl {
            field,
            url: url.to_string(),
        })
    }
}

pub(super) fn validate_fee_payer_pubkey(
    expected_payer: &Address,
    fee_payer: Pubkey,
) -> Result<(), ClientError> {
    if expected_payer.to_bytes() != fee_payer.to_bytes() {
        return Err(ClientError::FeePayerMismatch);
    }
    Ok(())
}
