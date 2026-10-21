use solana_address::Address;
use solana_keypair::Keypair;
use zeroize::Zeroizing;
use zolana_keypair::{KeypairError, X25519Keypair};
use zolana_ring_client::rpc::auditor_keypair;

use crate::{config::RootSecret, error::RingRpcError};

/// The auditor and service domains must stay distinct.
const DERIVATION_INFO: &[u8] = b"zolana/ring-auditor/v1";
const SERVICE_KEY_INFO: &[u8] = b"zolana/ring-rpc-service/v1";
/// Part of the pinned derivation info of every registered auditor key.
const DERIVATION_SUFFIX: &[u8] = &[0];

pub(crate) enum KeySource {
    Local {
        ring: Address,
        auditor: X25519Keypair,
    },
    Derived(RootSecret),
}

/// The cluster and ring bind each auditor key.
#[must_use]
pub(crate) struct AuditorKeyDerivation<'a> {
    pub root: &'a RootSecret,
    pub genesis_hash: &'a [u8; 32],
    pub ring: Address,
}

impl AuditorKeyDerivation<'_> {
    pub fn derive(self) -> Result<X25519Keypair, RingRpcError> {
        let mut secret = Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(None, self.root.as_bytes())
            .expand_multi_info(
                &[
                    DERIVATION_INFO,
                    self.genesis_hash,
                    self.ring.as_ref(),
                    DERIVATION_SUFFIX,
                ],
                secret.as_mut_slice(),
            )
            .map_err(|_| KeypairError::Hkdf)?;
        Ok(auditor_keypair(&secret)?)
    }
}

pub(crate) fn service_keypair(secret: &[u8]) -> Result<Keypair, RingRpcError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret)
        .expand(SERVICE_KEY_INFO, seed.as_mut_slice())
        .map_err(|_| KeypairError::Hkdf)?;
    Ok(Keypair::new_from_array(*seed))
}

#[cfg(test)]
mod tests {
    use solana_signer::Signer;

    use super::*;

    /// The ring config pins its auditor key forever, so a new derivation domain orphans every ring.
    #[test]
    fn derived_keys_are_pinned_to_their_derivation_domain() {
        let root = RootSecret::from_bytes([7; 32]).expect("root secret");
        let auditor = AuditorKeyDerivation {
            root: &root,
            genesis_hash: &[9; 32],
            ring: Address::new_from_array([5; 32]),
        }
        .derive()
        .expect("auditor key");

        assert_eq!(
            hex::encode(auditor.pubkey().as_bytes()),
            "04269a2c3596d0b1d0d5971be8132ee7f641f5948c2d8cb98b9896a9a8363dda42"
        );
        assert_eq!(
            service_keypair(root.as_bytes())
                .expect("service key")
                .pubkey()
                .to_string(),
            "FQ7ZZ4DEkoubT5Ca9BzzbgXDTmjKdRh6a3snGfPjpEZT"
        );
    }
}
