use custom_ring_interface::{
    RingDepositAuditCapsule, MAX_RING_DEPOSIT_AUDIT_SLOTS, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN,
    RING_DEPOSIT_AUDIT_INFO, RING_DEPOSIT_AUDIT_OWNER_KEY_OFFSET,
};
use zeroize::Zeroizing;
use zolana_keypair::{symmetric_apply, X25519Keypair, X25519Pubkey};

use crate::encryption::{AuditEncryptionError, AuditSharedSecret};

/// Owner commitment preimage disclosed to the ring auditor.
pub struct DepositOpening {
    pub owner_hash: [u8; 32],
    pub blinding: Zeroizing<[u8; 32]>,
    /// The Ed25519 owner key an anonymous ring discloses, `None` otherwise.
    /// The disclosure proof binds it to `owner_hash`.
    pub owner_key: Option<[u8; 32]>,
}

/// Batch ciphertexts and the ephemeral secret needed by the disclosure proof.
pub struct DepositEncryption {
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    pub ephemeral_pk: X25519Pubkey,
    pub ciphertexts: Vec<[u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]>,
}

/// Encrypts deposit openings under the ring's pinned auditor key.
pub struct DepositSeal<'a> {
    pub openings: &'a [DepositOpening],
    pub auditor_pk: &'a X25519Pubkey,
}

impl DepositSeal<'_> {
    pub fn seal(self) -> Result<DepositEncryption, AuditEncryptionError> {
        self.seal_with_key(X25519Keypair::new())
    }

    fn seal_with_key(
        self,
        ephemeral: X25519Keypair,
    ) -> Result<DepositEncryption, AuditEncryptionError> {
        if self.openings.is_empty() || self.openings.len() > MAX_RING_DEPOSIT_AUDIT_SLOTS {
            return Err(AuditEncryptionError::DepositCount(self.openings.len()));
        }
        let ephemeral_sk = ephemeral.secret_bytes();
        let ephemeral_pk = ephemeral.pubkey();
        // 1. CR_S binds the shared secret to both tagged X25519 public keys.
        let dh = ephemeral.ecdh(self.auditor_pk)?;
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
            slot[32..RING_DEPOSIT_AUDIT_OWNER_KEY_OFFSET]
                .copy_from_slice(opening.blinding.as_slice());
            slot[RING_DEPOSIT_AUDIT_OWNER_KEY_OFFSET..]
                .copy_from_slice(&opening.owner_key.unwrap_or_default());
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
    pub auditor: &'a X25519Keypair,
    pub owner_utxo_hash: &'a [u8; 32],
    /// Fetched independently of the indexed capsule from its confirmed event.
    pub confirmed: &'a crate::ConfirmedDeposit,
}

impl DepositOpen<'_> {
    pub fn open(self) -> Result<DepositOpening, AuditEncryptionError> {
        // The owner commitment omits the disclosed key, so authenticate every
        // ciphertext byte against the executed proof before decrypting it.
        if !self.confirmed.matches(self.capsule, self.owner_utxo_hash) {
            return Err(AuditEncryptionError::DepositOpeningMismatch);
        }
        let slot_index = usize::from(self.capsule.slot_index);
        if slot_index >= MAX_RING_DEPOSIT_AUDIT_SLOTS {
            return Err(AuditEncryptionError::DepositSlot(slot_index));
        }
        let ephemeral_pk = X25519Pubkey::from_bytes(*self.capsule.eph_pk)?;
        let auditor_pk = self.auditor.pubkey();
        let dh = self.auditor.ecdh(&ephemeral_pk)?;
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
            .copy_from_slice(&plaintext[offset + 32..offset + RING_DEPOSIT_AUDIT_OWNER_KEY_OFFSET]);
        let mut owner_key = [0u8; 32];
        owner_key.copy_from_slice(
            &plaintext[offset + RING_DEPOSIT_AUDIT_OWNER_KEY_OFFSET
                ..offset + RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN],
        );
        // 2. The owner commitment authenticates the decrypted opening.
        if zolana_keypair::hash::poseidon(&[&owner_hash, &*blinding])? != *self.owner_utxo_hash {
            return Err(AuditEncryptionError::DepositOpeningMismatch);
        }
        Ok(DepositOpening {
            owner_hash,
            blinding,
            owner_key: (owner_key != [0; 32]).then_some(owner_key),
        })
    }
}

#[cfg(test)]
#[path = "../tests/common/deposit.rs"]
mod deposit_fixture;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_encryption_and_public_hash_match_the_typescript_vector() {
        let auditor = X25519Keypair::from_bytes(&[0x11; 32]);
        let ephemeral = X25519Keypair::from_bytes(&[0x22; 32]);
        let word = |value| {
            let mut bytes = [0; 32];
            bytes[31] = value;
            bytes
        };
        let openings = [
            DepositOpening {
                owner_hash: word(1),
                blinding: Zeroizing::new(word(3)),
                owner_key: None,
            },
            DepositOpening {
                owner_hash: word(2),
                blinding: Zeroizing::new(word(4)),
                owner_key: None,
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
            "047b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
        );
        assert_eq!(
            hex::encode(sealed.ephemeral_pk.as_bytes()),
            "040faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"
        );
        assert_eq!(hex::encode(sealed.ciphertexts[0]), "006d5d4d188464de0e852c806b11ef3850cd683b977fea9bd1b9278b6461669f631350fa47a91f10cceb37738a4fefe7f88ded2f36b08fa08cb0ebba0268414424ab3ee9887da5fa32d2074fbd7155bc72723a28dacb3fd92f045649bba3cdf6");
        assert_eq!(hex::encode(sealed.ciphertexts[1]), "588ca73e11d9094a68cc5e7c26aadac08f1bc0f41c3580bf9ddc70518b26a826aaeab0368c456598c7641706ce6de7dcdbafa8c64f3eba9526b5012da75c1a4c4fb93b88049bc84e8589460c06610c931447f57d2d4a9955f6ec638727886729");
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
            anonymous: false,
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
            "0313e323a3870bacb7042d78648a0d01d5f5b4ddfa56ee3024bcd26207ebe4f3"
        );
    }

    #[test]
    fn every_slot_uses_its_batch_stream_offset() {
        let auditor = X25519Keypair::new();
        let openings: Vec<_> = (0..MAX_RING_DEPOSIT_AUDIT_SLOTS)
            .map(|index| DepositOpening {
                owner_hash: [index as u8; 32],
                blinding: Zeroizing::new([index as u8 + 1; 32]),
                // Odd slots disclose an owner key like an anonymous ring.
                owner_key: (index % 2 == 1).then_some([index as u8 + 2; 32]),
            })
            .collect();
        let sealed = DepositSeal {
            openings: &openings,
            auditor_pk: &auditor.pubkey(),
        }
        .seal()
        .unwrap();
        let deposits: Vec<_> = sealed
            .ciphertexts
            .iter()
            .enumerate()
            .map(|(index, ciphertext)| {
                let commitment = zolana_transaction::owner_utxo_hash(
                    &openings[index].owner_hash,
                    &openings[index].blinding,
                )
                .unwrap();
                let capsule = RingDepositAuditCapsule {
                    slot_index: index as u8,
                    eph_pk: sealed.ephemeral_pk.as_bytes(),
                    ciphertext,
                    recipient_ciphertext: &[1, 2, 3],
                }
                .encode();
                (commitment, capsule)
            })
            .collect();
        let ring = solana_address::Address::new_from_array([9; 32]);
        let groups = [deposit_fixture::group(ring, true, deposits.clone())];
        let origin = crate::ring_event_origin_in(&groups, 0, ring).unwrap();
        for (index, (commitment, bytes)) in deposits.iter().enumerate() {
            let open = |bytes: &[u8], confirmed: &crate::ConfirmedDeposit| {
                DepositOpen {
                    capsule: RingDepositAuditCapsule::parse(bytes).unwrap().unwrap(),
                    auditor: &auditor,
                    owner_utxo_hash: commitment,
                    confirmed,
                }
                .open()
            };
            let opened = open(bytes, &origin.deposits[index]).unwrap();
            assert_eq!(opened.owner_hash, openings[index].owner_hash);
            assert_eq!(*opened.blinding, *openings[index].blinding);
            assert_eq!(opened.owner_key, openings[index].owner_key);
            // The previously unauthenticated key occupies ciphertext bytes 64..96.
            for offset in [8, 9, 42 + 64, bytes.len() - 1] {
                let mut changed = bytes.clone();
                changed[offset] ^= 1;
                assert!(matches!(
                    open(&changed, &origin.deposits[index]),
                    Err(AuditEncryptionError::DepositOpeningMismatch)
                ));
            }
            assert!(open(bytes, &origin.deposits[(index + 1) % deposits.len()]).is_err());
        }
        assert!(DepositOpen {
            capsule: RingDepositAuditCapsule::parse(&deposits[0].1)
                .unwrap()
                .unwrap(),
            auditor: &auditor,
            owner_utxo_hash: &[0; 32],
            confirmed: &origin.deposits[0],
        }
        .open()
        .is_err());
        // The same opening in a different event has an independent capsule binding.
        let mut other = deposits.clone();
        other[0].1[42 + 64] ^= 1;
        let groups = [groups[0].clone(), deposit_fixture::group(ring, true, other)];
        let other_origin = crate::ring_event_origin_in(&groups, 1, ring).unwrap();
        assert!(DepositOpen {
            capsule: RingDepositAuditCapsule::parse(&deposits[0].1)
                .unwrap()
                .unwrap(),
            auditor: &auditor,
            owner_utxo_hash: &deposits[0].0,
            confirmed: &other_origin.deposits[0],
        }
        .open()
        .is_err());
        let plain = [deposit_fixture::group(ring, false, deposits)];
        assert!(crate::ring_event_origin_in(&plain, 0, ring)
            .unwrap()
            .deposits
            .is_empty());
    }

    #[test]
    fn empty_and_oversized_batches_are_rejected() {
        let auditor = X25519Keypair::new().pubkey();
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
                owner_key: None,
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
