use custom_ring_interface::{
    RingDepositAuditCapsule, MAX_RING_DEPOSIT_AUDIT_SLOTS, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN,
    RING_DEPOSIT_AUDIT_INFO,
};
use zeroize::Zeroizing;
use zolana_keypair::{symmetric_apply, P256Pubkey, ViewingKey};

use crate::encryption::{AuditEncryptionError, AuditSharedSecret};

/// Owner commitment preimage disclosed to the ring auditor.
pub struct DepositOpening {
    pub owner_hash: [u8; 32],
    pub blinding: Zeroizing<[u8; 32]>,
}

/// Batch ciphertexts and the ephemeral secret needed by the disclosure proof.
pub struct DepositEncryption {
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    pub ephemeral_pk: P256Pubkey,
    pub ciphertexts: Vec<[u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]>,
}

/// Encrypts deposit openings under the ring's pinned auditor key.
pub struct DepositSeal<'a> {
    pub openings: &'a [DepositOpening],
    pub auditor_pk: &'a P256Pubkey,
}

impl DepositSeal<'_> {
    pub fn seal(self) -> Result<DepositEncryption, AuditEncryptionError> {
        self.seal_with_key(ViewingKey::new())
    }

    fn seal_with_key(
        self,
        ephemeral: ViewingKey,
    ) -> Result<DepositEncryption, AuditEncryptionError> {
        if self.openings.is_empty() || self.openings.len() > MAX_RING_DEPOSIT_AUDIT_SLOTS {
            return Err(AuditEncryptionError::DepositCount(self.openings.len()));
        }
        let ephemeral_sk = ephemeral.secret_bytes();
        let ephemeral_pk = ephemeral.pubkey();
        // 1. CR_S binds the shared secret to both P256 public keys.
        let dh = Zeroizing::new(ephemeral.ecdh(self.auditor_pk)?);
        let shared_secret = AuditSharedSecret {
            diffie_hellman_x: &dh,
            ephemeral_key: &ephemeral_pk,
            auditor_key: self.auditor_pk,
        }
        .derive()?;
        let mut plaintext =
            Zeroizing::new([0u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN * MAX_RING_DEPOSIT_AUDIT_SLOTS]);
        for (slot, opening) in plaintext
            .as_chunks_mut::<RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN>()
            .0
            .iter_mut()
            .zip(self.openings)
        {
            slot[..32].copy_from_slice(&opening.owner_hash);
            slot[32..].copy_from_slice(opening.blinding.as_slice());
        }
        // 2. CRING/dep1 separates the padded deposit stream from transaction
        // disclosures.
        symmetric_apply(
            &shared_secret,
            RING_DEPOSIT_AUDIT_INFO,
            plaintext.as_mut_slice(),
        )?;
        let ciphertexts = plaintext
            .as_chunks::<RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN>()
            .0
            .iter()
            .take(self.openings.len())
            .copied()
            .collect();
        Ok(DepositEncryption {
            ephemeral_sk,
            ephemeral_pk,
            ciphertexts,
        })
    }
}

/// Authenticates an auditor opening against the deposited owner commitment.
pub struct DepositOpen<'a> {
    pub capsule: RingDepositAuditCapsule<'a>,
    pub auditor: &'a ViewingKey,
    pub owner_utxo_hash: &'a [u8; 32],
}

impl DepositOpen<'_> {
    pub fn open(self) -> Result<DepositOpening, AuditEncryptionError> {
        let slot_index = usize::from(self.capsule.slot_index);
        if slot_index >= MAX_RING_DEPOSIT_AUDIT_SLOTS {
            return Err(AuditEncryptionError::DepositSlot(slot_index));
        }
        let ephemeral_pk = P256Pubkey::from_bytes(*self.capsule.eph_pk)?;
        let auditor_pk = self.auditor.pubkey();
        let dh = Zeroizing::new(self.auditor.ecdh(&ephemeral_pk)?);
        let shared_secret = AuditSharedSecret {
            diffie_hellman_x: &dh,
            ephemeral_key: &ephemeral_pk,
            auditor_key: &auditor_pk,
        }
        .derive()?;
        let mut plaintext =
            Zeroizing::new([0u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN * MAX_RING_DEPOSIT_AUDIT_SLOTS]);
        let offset = slot_index * RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN;
        plaintext[offset..offset + RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]
            .copy_from_slice(self.capsule.ciphertext);
        // 1. Each slot retains its offset in the shared batch stream.
        symmetric_apply(
            &shared_secret,
            RING_DEPOSIT_AUDIT_INFO,
            plaintext.as_mut_slice(),
        )?;
        let mut owner_hash = [0u8; 32];
        owner_hash.copy_from_slice(&plaintext[offset..offset + 32]);
        let mut blinding = Zeroizing::new([0u8; 32]);
        blinding
            .copy_from_slice(&plaintext[offset + 32..offset + RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]);
        // 2. The owner commitment authenticates the decrypted opening.
        if zolana_keypair::hash::poseidon(&[&owner_hash, &*blinding])? != *self.owner_utxo_hash {
            return Err(AuditEncryptionError::DepositOpeningMismatch);
        }
        Ok(DepositOpening {
            owner_hash,
            blinding,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_encryption_and_public_hash_match_the_typescript_vector() {
        let auditor = ViewingKey::from_bytes(&[0x11; 32]).unwrap();
        let ephemeral = ViewingKey::from_bytes(&[0x22; 32]).unwrap();
        let word = |value| {
            let mut bytes = [0; 32];
            bytes[31] = value;
            bytes
        };
        let openings = [
            DepositOpening {
                owner_hash: word(1),
                blinding: Zeroizing::new(word(3)),
            },
            DepositOpening {
                owner_hash: word(2),
                blinding: Zeroizing::new(word(4)),
            },
        ];
        let sealed = DepositSeal {
            openings: &openings,
            auditor_pk: &auditor.pubkey(),
        }
        .seal_with_key(ephemeral)
        .unwrap();
        assert_eq!(
            hex::encode(auditor.pubkey().as_bytes()),
            "020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed"
        );
        assert_eq!(
            hex::encode(sealed.ephemeral_pk.as_bytes()),
            "03d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf3"
        );
        assert_eq!(hex::encode(sealed.ciphertexts[0]), "146b393f9c81cad9bc22887e500644f69ea8293e2253f55869e88127e5483e9b12a46abadf0068bd73c83584a8e47a550e88a35558642ba87646ff0765c5e3b5");
        assert_eq!(hex::encode(sealed.ciphertexts[1]), "74e42b590ba76cfee5c6d8e3e05e03a460e0c02c7330fd977dc4eb71e34645616f616fb39595f1ecadfdd87feffd48fb4177741341dd2d507c474094e252f89c");
        let context_hash = custom_ring_interface::DepositContext {
            program_id: &[0x33; 32],
            tree: &[0x44; 32],
            spp_data: &[18, 1, 0, 2],
        }
        .hash()
        .unwrap();
        assert_eq!(
            hex::encode(context_hash),
            "2cc6b9a5a2cb550702b5387ade744abee5e6eeb7c266415e59502e6f8acce56b"
        );
        let owners = openings.each_ref().map(|opening| {
            zolana_transaction::owner_utxo_hash(&opening.owner_hash, &opening.blinding).unwrap()
        });
        let public_hash = custom_ring_interface::DepositPublicInput {
            context_hash: &context_hash,
            owner_utxo_hashes: &owners,
            ciphertexts: &sealed.ciphertexts,
            auditor_pk: auditor.pubkey().as_bytes(),
            eph_pk: sealed.ephemeral_pk.as_bytes(),
            key_registry_root: None,
        }
        .hash()
        .unwrap();
        assert_eq!(
            hex::encode(public_hash),
            "0bc3f76e72b6d6bd1a557447da49e445dafb11e6d9168005742013130b45e030"
        );
    }

    #[test]
    fn every_slot_uses_its_batch_stream_offset() {
        let auditor = ViewingKey::new();
        let openings: Vec<_> = (0..MAX_RING_DEPOSIT_AUDIT_SLOTS)
            .map(|index| DepositOpening {
                owner_hash: [index as u8; 32],
                blinding: Zeroizing::new([index as u8 + 1; 32]),
            })
            .collect();
        let sealed = DepositSeal {
            openings: &openings,
            auditor_pk: &auditor.pubkey(),
        }
        .seal()
        .unwrap();
        for (index, ciphertext) in sealed.ciphertexts.iter().enumerate() {
            let opened = DepositOpen {
                capsule: RingDepositAuditCapsule {
                    slot_index: index as u8,
                    eph_pk: sealed.ephemeral_pk.as_bytes(),
                    ciphertext,
                    recipient_ciphertext: &[],
                },
                auditor: &auditor,
                owner_utxo_hash: &zolana_transaction::owner_utxo_hash(
                    &openings[index].owner_hash,
                    &openings[index].blinding,
                )
                .unwrap(),
            }
            .open()
            .unwrap();
            assert_eq!(opened.owner_hash, openings[index].owner_hash);
            assert_eq!(*opened.blinding, *openings[index].blinding);
        }
    }

    #[test]
    fn empty_and_oversized_batches_are_rejected() {
        let auditor = ViewingKey::new().pubkey();
        assert!(matches!(
            DepositSeal {
                openings: &[],
                auditor_pk: &auditor
            }
            .seal(),
            Err(AuditEncryptionError::DepositCount(0))
        ));
        let openings: Vec<_> = (0..=MAX_RING_DEPOSIT_AUDIT_SLOTS)
            .map(|_| DepositOpening {
                owner_hash: [0; 32],
                blinding: Zeroizing::new([0; 32]),
            })
            .collect();
        assert!(matches!(
            DepositSeal {
                openings: &openings,
                auditor_pk: &auditor
            }
            .seal(),
            Err(AuditEncryptionError::DepositCount(9))
        ));
    }
}
