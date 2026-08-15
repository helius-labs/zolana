//! Reassembling a 64-byte signature from Turnkey's `{r, s}` response.
//!
//! The two rails need opposite rules, which is the whole reason this lives in
//! one place:
//!
//! - **P-256.** `r` and `s` are big-endian scalars. A big-endian integer may
//!   arrive with leading zeros stripped, so a short component is *left*-padded.
//! - **Ed25519.** `r` is a little-endian compressed point and `s` a
//!   little-endian scalar. Neither is an integer this code may re-pad: padding
//!   on either end produces a different, still well-formed 64 bytes. On the
//!   derivation path those bytes are the seed for the nullifier and viewing
//!   keys, so the result would be a valid wallet that is not the user's wallet,
//!   with no signature check anywhere able to notice. Short components are
//!   therefore rejected outright.

use p256::ecdsa::Signature as EcdsaSignature;

use crate::{activities::RawSignature, error::TurnkeyKeypairError};

const COMPONENT_LEN: usize = 32;

/// Joins `r || s` for an RFC 8032 signature, requiring both components to be
/// exactly 32 bytes. See the module docs for why nothing is padded here.
pub(crate) fn ed25519_signature(signature: &RawSignature) -> Result<[u8; 64], TurnkeyKeypairError> {
    let r = exact_component("ed25519 signature R", &signature.r)?;
    let s = exact_component("ed25519 signature S", &signature.s)?;
    Ok(join(&r, &s))
}

/// Joins `r || s` for an ECDSA signature and normalizes it to low-S.
///
/// Both the SPP proof and Solana's secp256r1 precompile reject high-S, and
/// Turnkey makes no low-S guarantee, so normalization happens here rather than
/// at each call site.
pub(crate) fn p256_signature(signature: &RawSignature) -> Result<[u8; 64], TurnkeyKeypairError> {
    let r = big_endian_scalar("P-256 signature r", &signature.r)?;
    let s = big_endian_scalar("P-256 signature s", &signature.s)?;
    let parsed = EcdsaSignature::from_slice(&join(&r, &s))
        .map_err(|error| TurnkeyKeypairError::malformed("P-256 signature", error.to_string()))?;
    Ok(parsed.normalize_s().unwrap_or(parsed).to_bytes().into())
}

fn join(r: &[u8; COMPONENT_LEN], s: &[u8; COMPONENT_LEN]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..COMPONENT_LEN].copy_from_slice(r);
    out[COMPONENT_LEN..].copy_from_slice(s);
    out
}

fn exact_component(
    field: &'static str,
    bytes: &[u8],
) -> Result<[u8; COMPONENT_LEN], TurnkeyKeypairError> {
    bytes.try_into().map_err(|_| {
        TurnkeyKeypairError::malformed(
            field,
            format!(
                "{} bytes, expected exactly {COMPONENT_LEN}; this component is little-endian and \
                 must not be re-padded",
                bytes.len()
            ),
        )
    })
}

fn big_endian_scalar(
    field: &'static str,
    bytes: &[u8],
) -> Result<[u8; COMPONENT_LEN], TurnkeyKeypairError> {
    if bytes.is_empty() || bytes.len() > COMPONENT_LEN {
        return Err(TurnkeyKeypairError::malformed(
            field,
            format!("{} bytes, expected 1..={COMPONENT_LEN}", bytes.len()),
        ));
    }
    let mut scalar = [0u8; COMPONENT_LEN];
    let offset = COMPONENT_LEN - bytes.len();
    scalar
        .get_mut(offset..)
        .ok_or_else(|| TurnkeyKeypairError::malformed(field, "scalar does not fit"))?
        .copy_from_slice(bytes);
    Ok(scalar)
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

    use super::*;

    fn raw(r: Vec<u8>, s: Vec<u8>) -> RawSignature {
        RawSignature { r, s }
    }

    /// Exactly-32-byte components pass through untouched, in `r || s` order.
    #[test]
    fn ed25519_components_are_joined_verbatim() {
        let signature = ed25519_signature(&raw(vec![1u8; 32], vec![2u8; 32])).unwrap();

        let mut expected = [0u8; 64];
        expected[..32].copy_from_slice(&[1u8; 32]);
        expected[32..].copy_from_slice(&[2u8; 32]);
        assert_eq!(signature, expected);
    }

    /// A short ed25519 component is a hard error, never a pad. Guarding this is
    /// the point of the type: a padded seed derives a different wallet.
    #[test]
    fn ed25519_rejects_components_that_are_not_exactly_32_bytes() {
        for signature in [
            raw(vec![1u8; 31], vec![2u8; 32]),
            raw(vec![1u8; 32], vec![2u8; 31]),
            raw(vec![1u8; 33], vec![2u8; 32]),
            raw(Vec::new(), vec![2u8; 32]),
        ] {
            assert!(matches!(
                ed25519_signature(&signature),
                Err(TurnkeyKeypairError::MalformedResponse { .. })
            ));
        }
    }

    /// A P-256 scalar with stripped leading zeros is left-padded back to width,
    /// the opposite of the ed25519 rule above.
    #[test]
    fn p256_left_pads_stripped_scalars() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let digest = [9u8; 32];
        let reference: p256::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
        let reference = reference.normalize_s().unwrap_or(reference);
        let bytes: [u8; 64] = reference.to_bytes().into();

        let (r, s) = bytes.split_at(32);
        let stripped = raw(
            r.iter().copied().skip_while(|byte| *byte == 0).collect(),
            s.to_vec(),
        );

        assert_eq!(p256_signature(&stripped).unwrap(), bytes);
    }

    /// High-S in, low-S out: the caller never has to normalize.
    #[test]
    fn p256_normalizes_high_s() {
        use p256::elliptic_curve::scalar::IsHigh;

        let key = SigningKey::from_slice(&[11u8; 32]).unwrap();
        let digest = [13u8; 32];
        let low: p256::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
        let low = low.normalize_s().unwrap_or(low);

        let s = *low.s();
        let flipped = if s.is_high().into() { s } else { -s };
        let high = p256::ecdsa::Signature::from_scalars(*low.r(), flipped).unwrap();
        let high_bytes: [u8; 64] = high.to_bytes().into();
        assert!(high.normalize_s().is_some(), "test needs a high-S input");

        let normalized =
            p256_signature(&raw(high_bytes[..32].to_vec(), high_bytes[32..].to_vec())).unwrap();

        assert_eq!(normalized, <[u8; 64]>::from(low.to_bytes()));
    }

    #[test]
    fn p256_rejects_oversized_scalars() {
        assert!(matches!(
            p256_signature(&raw(vec![1u8; 33], vec![2u8; 32])),
            Err(TurnkeyKeypairError::MalformedResponse { .. })
        ));
    }
}
