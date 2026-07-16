//! The wallet seed — the root every SLIP-0010-derived shielded key grows from —
//! and the derivation paths under the TSPP coin type.

use zeroize::Zeroizing;

use crate::{
    constants::{INFO_WALLET_SEED, TSPP_COIN_TYPE, WALLET_SEED_LEN},
    error::KeypairError,
    slip10::HARDENED,
    viewing_key::hkdf_expand,
};

/// `wallet_seed` for a Solana-only owner: `HKDF-SHA256(salt=∅, IKM=ed25519_sk,
/// info="TSPP/wallet_seed", L=64)`. One-way, so the derived shielded keys never
/// expose the Solana secret; anchored to the secret itself, so a raw keypair
/// file recovers the wallet without the original mnemonic.
pub fn wallet_seed_from_ed25519(
    signing_secret: &[u8; 32],
) -> Result<Zeroizing<[u8; WALLET_SEED_LEN]>, KeypairError> {
    let mut seed = Zeroizing::new([0u8; WALLET_SEED_LEN]);
    hkdf_expand(
        None,
        signing_secret,
        &[INFO_WALLET_SEED],
        seed.as_mut_slice(),
    )?;
    Ok(seed)
}

/// `m/44'/TSPP_COIN_TYPE'/account'/0'/0'` — the signing-key path.
pub(crate) fn signing_path(account: u32) -> Result<[u32; 5], KeypairError> {
    derivation_path(account, 0)
}

/// `m/44'/TSPP_COIN_TYPE'/account'/1'/0'` — the viewing-key path, the signing
/// path's sibling under change index `1'`.
pub(crate) fn viewing_path(account: u32) -> Result<[u32; 5], KeypairError> {
    derivation_path(account, 1)
}

fn derivation_path(account: u32, change: u32) -> Result<[u32; 5], KeypairError> {
    if account >= HARDENED {
        return Err(KeypairError::InvalidDerivationAccount(account));
    }
    Ok([
        44 | HARDENED,
        TSPP_COIN_TYPE | HARDENED,
        account | HARDENED,
        change | HARDENED,
        HARDENED,
    ])
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    /// `TSPP_COIN_TYPE` is pinned; this test enforces the derivation formula
    /// the constant claims (`SHA-256("luminous.TSPP.v1")[0..4]` big-endian,
    /// masked to 31 bits) so constant and formula cannot drift apart.
    #[test]
    fn tspp_coin_type_matches_its_derivation_formula() {
        let digest = Sha256::digest(b"luminous.TSPP.v1");
        let prefix: [u8; 4] = digest
            .get(..4)
            .expect("SHA-256 digest is 32 bytes")
            .try_into()
            .expect("4-byte prefix");
        assert_eq!(u32::from_be_bytes(prefix) & 0x7FFF_FFFF, TSPP_COIN_TYPE);
    }

    #[test]
    fn wallet_seed_is_deterministic_and_key_separated() {
        let first = wallet_seed_from_ed25519(&[7u8; 32]).unwrap();
        let again = wallet_seed_from_ed25519(&[7u8; 32]).unwrap();
        let other = wallet_seed_from_ed25519(&[8u8; 32]).unwrap();

        assert_eq!(first.as_slice(), again.as_slice());
        assert_ne!(first.as_slice(), other.as_slice());
    }

    #[test]
    fn account_must_stay_below_the_hardened_bit() {
        assert_eq!(
            derivation_path(HARDENED, 0).unwrap_err(),
            KeypairError::InvalidDerivationAccount(HARDENED)
        );
    }
}
