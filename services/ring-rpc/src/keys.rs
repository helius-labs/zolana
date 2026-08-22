use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_keypair::Keypair;
use zeroize::Zeroizing;
use zolana_keypair::ViewingKey;

use crate::{config::RootSecret, error::RingRpcError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyMode {
    Local,
    Derived,
}

/// The auditor and service domains must stay distinct.
const DERIVATION_INFO: &[u8] = b"zolana/ring-auditor/v1";
const SERVICE_KEY_INFO: &[u8] = b"zolana/ring-rpc-service/v1";

/// The cluster and ring bind each auditor key.
#[must_use]
pub(crate) struct AuditorKeyDerivation<'a> {
    pub root: &'a RootSecret,
    pub genesis_hash: &'a [u8; 32],
    pub ring: Address,
}

impl AuditorKeyDerivation<'_> {
    pub fn derive(self) -> Result<ViewingKey, RingRpcError> {
        let mut info = Vec::with_capacity(
            DERIVATION_INFO.len() + self.genesis_hash.len() + self.ring.as_ref().len() + 1,
        );
        info.extend_from_slice(DERIVATION_INFO);
        info.extend_from_slice(self.genesis_hash);
        info.extend_from_slice(self.ring.as_ref());
        info.push(0);
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, self.root.as_bytes());
        for counter in 0..=u8::MAX {
            *info.last_mut().ok_or(zolana_keypair::KeypairError::Hkdf)? = counter;
            let mut secret = Zeroizing::new([0u8; 32]);
            hkdf.expand(&info, secret.as_mut_slice())
                .map_err(|_| zolana_keypair::KeypairError::Hkdf)?;
            if let Ok(key) = ViewingKey::from_bytes(&secret) {
                return Ok(key);
            }
        }
        Err(zolana_keypair::KeypairError::ZeroScalar.into())
    }
}

pub(crate) fn service_keypair(secret: &[u8]) -> Result<Keypair, RingRpcError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret)
        .expand(SERVICE_KEY_INFO, seed.as_mut_slice())
        .map_err(|_| zolana_keypair::KeypairError::Hkdf)?;
    Ok(Keypair::new_from_array(*seed))
}

pub(crate) enum KeySource {
    Local {
        ring: Address,
        auditor: ViewingKey,
    },
    Derived {
        root: RootSecret,
        genesis_hash: [u8; 32],
    },
}
