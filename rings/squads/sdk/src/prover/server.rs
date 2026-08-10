//! Prove requests for the Squads circuits.
//!
//! The HTTP transport, its retry loop, and API-key resolution belong to
//! [`ProverClient`]. This module adds only the encodings the Squads request
//! bodies use and the transport policy the Squads inputs need.

use std::net::IpAddr;

use zolana_client::prover::{InputSensitivity, ProverClient};

use crate::prover::error::SquadsProverError;

/// A field element as the prover server reads it: `0x` plus the minimal
/// big-endian hex of the value.
pub(crate) fn fe_hex(bytes: &[u8; 32]) -> String {
    format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_be(bytes).to_str_radix(16)
    )
}

/// Every Squads prove request carries wallet secrets, so only a loopback prover
/// may see one. This is stricter than the shared client's remote-over-HTTPS
/// allowance, and it is asserted here rather than inherited.
fn validate_prover_transport(server_address: &str) -> Result<(), SquadsProverError> {
    let url =
        reqwest::Url::parse(server_address).map_err(|_| SquadsProverError::InvalidProverUrl {
            server_address: server_address.to_string(),
        })?;
    let loopback = url.host_str().is_some_and(|host| {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if !loopback {
        return Err(SquadsProverError::RequiresLocalProver {
            server_address: server_address.to_string(),
        });
    }
    Ok(())
}

/// POST `body` to `<server_address>/prove` and return the gnark proof JSON
/// object as a string.
pub(crate) fn send_prove_request(
    server_address: &str,
    body: &str,
) -> Result<String, SquadsProverError> {
    validate_prover_transport(server_address)?;
    ProverClient::new(server_address.to_string())
        .send_raw(body.to_string(), InputSensitivity::WalletSecrets)
        .map_err(|error| SquadsProverError::ProverServer(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{validate_prover_transport, SquadsProverError};

    #[test]
    fn wallet_secret_requests_require_loopback() {
        assert!(validate_prover_transport("http://127.0.0.1:3001").is_ok());
        assert!(validate_prover_transport("http://localhost:3001").is_ok());
        assert!(validate_prover_transport("http://[::1]:3001").is_ok());

        let error = validate_prover_transport("https://prover.example")
            .expect_err("Squads proof secrets must not leave the wallet device");
        assert!(matches!(
            error,
            SquadsProverError::RequiresLocalProver { .. }
        ));
    }

    #[test]
    fn malformed_prover_url_is_named() {
        let error = validate_prover_transport("not a url")
            .expect_err("a malformed prover URL must be rejected");
        assert!(matches!(error, SquadsProverError::InvalidProverUrl { .. }));
    }
}
