use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::error::GlobalSharedViewKeyError;
use crate::ffi;
use crate::share::EncryptedKeyShare;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InnerPolicy {
    pub t: u8,
    pub m: u8,
}

impl InnerPolicy {
    pub fn new(t: u8, m: u8) -> Self {
        Self { t, m }
    }
}

#[derive(Debug, Clone)]
pub struct SharedViewKeySetup {
    pub data_pubkey: PublicKey,
    pub outer_threshold: u8,
    pub policies: Vec<InnerPolicy>,
    pub entities: Vec<Vec<EncryptedKeyShare>>,
}

pub struct GlobalSharedViewKey {
    auth_key: SecretKey,
    signing_key: SigningKey,
}

impl GlobalSharedViewKey {
    pub fn new() -> Self {
        Self {
            auth_key: SecretKey::random(&mut OsRng),
            signing_key: SigningKey::random(&mut OsRng),
        }
    }

    pub fn setup(
        &self,
        data_key: SecretKey,
        outer_threshold: u8,
        policies: Vec<InnerPolicy>,
    ) -> Result<SharedViewKeySetup, GlobalSharedViewKeyError> {
        validate(outer_threshold, &policies)?;

        let outer_parts = policies.len() as u8;
        let data_pubkey = data_key.public_key();
        let data_secret = Zeroizing::new(data_key.to_bytes());
        let outer_shares = ffi::split(data_secret.as_slice(), outer_parts, outer_threshold)?;

        let auth_pubkey = self.auth_key.public_key();
        let mut entities: Vec<Vec<EncryptedKeyShare>> = Vec::with_capacity(policies.len());
        for (outer_share, policy) in outer_shares.iter().zip(policies.iter()) {
            let sub_shares: Vec<Zeroizing<Vec<u8>>> = if policy.t == 1 {
                (0..policy.m)
                    .map(|_| Zeroizing::new(outer_share.to_vec()))
                    .collect()
            } else {
                ffi::split(outer_share.as_slice(), policy.m, policy.t)?
            };

            let mut encrypted: Vec<EncryptedKeyShare> = Vec::with_capacity(sub_shares.len());
            for sub_share in &sub_shares {
                encrypted.push(EncryptedKeyShare::encrypt(
                    &auth_pubkey,
                    &self.signing_key,
                    sub_share.as_slice(),
                )?);
            }
            entities.push(encrypted);
        }

        Ok(SharedViewKeySetup {
            data_pubkey,
            outer_threshold,
            policies,
            entities,
        })
    }

    pub fn reconstruct(
        &self,
        setup: &SharedViewKeySetup,
        returned: &[Vec<EncryptedKeyShare>],
    ) -> Result<SecretKey, GlobalSharedViewKeyError> {
        let verifying_key = VerifyingKey::from(&self.signing_key);
        let mut outer_shares: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        for (entity_index, policy) in setup.policies.iter().enumerate() {
            let entity_shares = match returned.get(entity_index) {
                Some(shares) => shares,
                None => continue,
            };
            if entity_shares.len() < policy.t as usize {
                continue;
            }

            let mut decrypted: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(policy.t as usize);
            for share in entity_shares.iter().take(policy.t as usize) {
                decrypted.push(share.decrypt(&self.auth_key, &verifying_key)?);
            }

            let outer_share = if policy.t == 1 {
                decrypted
                    .into_iter()
                    .next()
                    .ok_or(GlobalSharedViewKeyError::ShortBlob)?
            } else {
                let inner: Vec<&[u8]> = decrypted.iter().map(|share| share.as_slice()).collect();
                ffi::combine(&inner)?
            };
            outer_shares.push(outer_share);
        }

        let needed = setup.outer_threshold as usize;
        if outer_shares.len() < needed {
            return Err(GlobalSharedViewKeyError::QuorumNotMet {
                needed,
                got: outer_shares.len(),
            });
        }

        let quorum: Vec<&[u8]> = outer_shares
            .iter()
            .take(needed)
            .map(|share| share.as_slice())
            .collect();
        let secret = ffi::combine(&quorum)?;
        let data_key = SecretKey::from_slice(secret.as_slice())
            .map_err(|_| GlobalSharedViewKeyError::InvalidReconstructedKey)?;
        if data_key.public_key() != setup.data_pubkey {
            return Err(GlobalSharedViewKeyError::InvalidReconstructedKey);
        }
        Ok(data_key)
    }
}

impl Default for GlobalSharedViewKey {
    fn default() -> Self {
        Self::new()
    }
}

fn validate(outer_threshold: u8, policies: &[InnerPolicy]) -> Result<(), GlobalSharedViewKeyError> {
    let entity_count = policies.len();
    if !(2..=255).contains(&entity_count) {
        return Err(GlobalSharedViewKeyError::InvalidConfig(
            "entity count must be in 2..=255",
        ));
    }
    if outer_threshold < 2 || outer_threshold as usize > entity_count {
        return Err(GlobalSharedViewKeyError::InvalidConfig(
            "outer threshold must be in 2..=entity count",
        ));
    }
    for policy in policies {
        if policy.m < 1 || policy.t < 1 || policy.t > policy.m {
            return Err(GlobalSharedViewKeyError::InvalidConfig(
                "inner policy must satisfy 1 <= t <= m",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policies(specs: &[(u8, u8)]) -> Vec<InnerPolicy> {
        specs
            .iter()
            .map(|(t, m)| InnerPolicy::new(*t, *m))
            .collect()
    }

    fn quorum(setup: &SharedViewKeySetup, per_entity: &[usize]) -> Vec<Vec<EncryptedKeyShare>> {
        setup
            .entities
            .iter()
            .zip(per_entity.iter())
            .map(|(shares, take)| shares.iter().take(*take).cloned().collect())
            .collect()
    }

    #[test]
    fn three_of_three_outer_two_of_five_inner_round_trips() {
        let authority = GlobalSharedViewKey::new();
        let setup = authority
            .setup(
                SecretKey::random(&mut OsRng),
                3,
                policies(&[(2, 5), (2, 5), (2, 5)]),
            )
            .expect("setup");

        let returned = quorum(&setup, &[2, 2, 2]);
        let recovered = authority
            .reconstruct(&setup, &returned)
            .expect("reconstruct");
        assert_eq!(recovered.public_key(), setup.data_pubkey);
    }

    #[test]
    fn one_entity_below_inner_threshold_fails() {
        let authority = GlobalSharedViewKey::new();
        let setup = authority
            .setup(
                SecretKey::random(&mut OsRng),
                3,
                policies(&[(2, 5), (2, 5), (2, 5)]),
            )
            .expect("setup");

        let returned = quorum(&setup, &[1, 2, 2]);
        assert!(matches!(
            authority.reconstruct(&setup, &returned),
            Err(GlobalSharedViewKeyError::QuorumNotMet { needed: 3, got: 2 })
        ));
    }

    #[test]
    fn mixed_inner_policies_round_trip() {
        let authority = GlobalSharedViewKey::new();
        let setup = authority
            .setup(
                SecretKey::random(&mut OsRng),
                3,
                policies(&[(2, 5), (1, 3), (2, 5)]),
            )
            .expect("setup");

        let returned = quorum(&setup, &[2, 1, 2]);
        let recovered = authority
            .reconstruct(&setup, &returned)
            .expect("reconstruct");
        assert_eq!(recovered.public_key(), setup.data_pubkey);
    }

    #[test]
    fn outer_two_of_three_tolerates_one_missing_entity() {
        let authority = GlobalSharedViewKey::new();
        let setup = authority
            .setup(
                SecretKey::random(&mut OsRng),
                2,
                policies(&[(2, 5), (2, 5), (2, 5)]),
            )
            .expect("setup");

        let returned = quorum(&setup, &[2, 2, 0]);
        let recovered = authority
            .reconstruct(&setup, &returned)
            .expect("reconstruct");
        assert_eq!(recovered.public_key(), setup.data_pubkey);
    }

    #[test]
    fn tampered_returned_share_fails_reconstruct() {
        let authority = GlobalSharedViewKey::new();
        let setup = authority
            .setup(
                SecretKey::random(&mut OsRng),
                3,
                policies(&[(2, 5), (2, 5), (2, 5)]),
            )
            .expect("setup");

        let mut returned = quorum(&setup, &[2, 2, 2]);
        if let Some(entity) = returned.get_mut(0) {
            if let Some(share) = entity.get_mut(0) {
                share.signature = [0u8; 64];
            }
        }

        assert!(matches!(
            authority.reconstruct(&setup, &returned),
            Err(GlobalSharedViewKeyError::BadSignature)
        ));
    }

    #[test]
    fn invalid_configurations_are_rejected() {
        let authority = GlobalSharedViewKey::new();

        let outer_threshold_too_low = authority.setup(
            SecretKey::random(&mut OsRng),
            1,
            policies(&[(2, 5), (2, 5)]),
        );
        assert!(matches!(
            outer_threshold_too_low,
            Err(GlobalSharedViewKeyError::InvalidConfig(_))
        ));

        let inner_threshold_above_m = authority.setup(
            SecretKey::random(&mut OsRng),
            2,
            policies(&[(6, 5), (2, 5)]),
        );
        assert!(matches!(
            inner_threshold_above_m,
            Err(GlobalSharedViewKeyError::InvalidConfig(_))
        ));
    }

    #[test]
    fn payload_round_trips_across_two_independent_reconstructions() {
        use crate::share::EciesCiphertext;

        let authority = GlobalSharedViewKey::new();
        let setup = authority
            .setup(
                SecretKey::random(&mut OsRng),
                3,
                policies(&[(2, 5), (2, 5), (2, 5)]),
            )
            .expect("setup");
        let returned = quorum(&setup, &[2, 2, 2]);

        let key1 = authority
            .reconstruct(&setup, &returned)
            .expect("reconstruct 1");
        let payload = b"independent payload";
        let ciphertext =
            EciesCiphertext::encrypt(&key1.public_key(), payload).expect("encrypt to key1");

        let key2 = authority
            .reconstruct(&setup, &returned)
            .expect("reconstruct 2");
        let decrypted = ciphertext.decrypt(&key2).expect("decrypt with key2");

        assert_eq!(key1.public_key(), key2.public_key());
        assert_eq!(decrypted.as_slice(), payload.as_slice());
    }
}
