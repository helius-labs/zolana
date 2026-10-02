use solana_address::Address;
use solana_pubkey::Pubkey;

use crate::error::ClientError;

/// Reject a service URL that would carry shielded material in plaintext.
pub(super) fn check_service_url(url: &str, field: &'static str) -> Result<(), ClientError> {
    let insecure = || ClientError::InsecureServiceUrl {
        field,
        url: url.to_string(),
    };

    if url.starts_with("https://") {
        return Ok(());
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return Err(insecure());
    };
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit_once(':')
        .map_or(
            rest.split(['/', '?', '#']).next().unwrap_or_default(),
            |(host, _)| host,
        );
    let host = host.trim_end_matches('.');

    let loopback = host == "localhost"
        || host.ends_with(".localhost")
        || host == "[::1]"
        || host
            .strip_prefix("127.")
            .is_some_and(|tail| tail.split('.').count() == 3);
    if loopback {
        Ok(())
    } else {
        Err(insecure())
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
