use solana_address::Address;
use solana_keypair::Keypair;
use zeroize::Zeroizing;
use zolana_keypair::{KeypairError, X25519Secret};

use crate::{config::RootSecret, error::RingRpcError};

/// The auditor and service domains must stay distinct.
const DERIVATION_INFO: &[u8] = b"zolana/ring-auditor/v1";
const SERVICE_KEY_INFO: &[u8] = b"zolana/ring-rpc-service/v1";

pub(crate) enum KeySource {
    Local {
        ring: Address,
        auditor: X25519Secret,
    },
    Derived(RootSecret),
}

/// The cluster and ring bind each key, the trailing zero byte keeps the first derivation's info.
pub(crate) fn derive_auditor_key(
    root: &RootSecret,
    genesis_hash: &[u8; 32],
    ring: Address,
) -> Result<X25519Secret, RingRpcError> {
    let info = [DERIVATION_INFO, genesis_hash, ring.as_ref(), &[0]].concat();
    let mut secret = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, root.as_bytes())
        .expand(&info, secret.as_mut_slice())
        .map_err(|_| KeypairError::Hkdf)?;
    Ok(X25519Secret::from_bytes(&secret)?)
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
        let auditor = derive_auditor_key(&root, &[9; 32], Address::new_from_array([5; 32]))
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
