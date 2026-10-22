//! Mirrors `custom_rings/circuits/base`, streams keyed by `Poseidon(CR_S, dh, eph_pk, auditor_pk)`.

use custom_ring_interface::{
    RingDepositAuditCapsule, AUDIT_CIPHERTEXT_LEN, AUDIT_STREAM_INFO, MAX_RING_DEPOSIT_AUDIT_SLOTS,
    RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN, RING_DEPOSIT_AUDIT_INFO,
    RING_DEPOSIT_AUDIT_OWNER_KEY_OFFSET,
};
use zeroize::Zeroizing;
use zolana_hasher::{
    primitives::{pack_be, right_align},
    Hasher, Poseidon,
};
use zolana_keypair::{
    symmetric_apply, symmetric_apply_audit, NullifierKey, X25519Keypair, X25519Pubkey,
};

use crate::AuditError;

type Result<T> = core::result::Result<T, AuditError>;

const NF_KEY_ENC_INFO: &[u8; 10] = b"CRING/nfk1";
/// ASCII "CR_S", the Go `DomSepCRShared`.
const DOM_SEP_CR_SHARED: u32 = 0x4352_5f53;

#[path = "encryption/merge_disclosure.rs"]
mod merge_disclosure;
#[cfg(test)]
pub(crate) use merge_disclosure::tests::Vector as MergeVector;
pub use merge_disclosure::{open_merge_disclosure, MergeDisclosureEncryption, MergeOpening};

/// The auditor key's u-coordinate, the tag the auditor scans for.
pub fn auditor_view_tag(pk: &X25519Pubkey) -> [u8; 32] {
    pk.u()
}

/// The key schedule of a sealed stream, the envelope and every delivered body share `Audit`.
#[derive(Clone, Copy)]
pub(crate) enum StreamSchedule {
    Audit,
    Labelled(&'static [u8; 10]),
}

/// Binds the X25519 output to both keys that produced it, in the order `seal.go` hashes.
pub(crate) fn shared_secret(
    dh: &[u8; 32],
    ephemeral: &X25519Pubkey,
    auditor: &X25519Pubkey,
) -> Result<Zeroizing<[u8; 32]>> {
    let [dh0, dh1] = pack_be(dh);
    let [eph0, eph1] = pack_be(ephemeral.as_bytes());
    let [aud0, aud1] = pack_be(auditor.as_bytes());
    Ok(Zeroizing::new(Poseidon::hashv(&[
        &right_align(&DOM_SEP_CR_SHARED.to_be_bytes()),
        &dh0,
        &dh1,
        &eph0,
        &eph1,
        &aud0,
        &aud1,
    ])?))
}

/// Seals `data` from an ephemeral key to the auditor.
pub(crate) fn seal_stream(
    ephemeral: &X25519Keypair,
    auditor: &X25519Pubkey,
    schedule: StreamSchedule,
    data: &mut [u8],
) -> Result<()> {
    let secret = shared_secret(&*ephemeral.ecdh(auditor)?, &ephemeral.pubkey(), auditor)?;
    apply_stream(&secret, schedule, data)
}

pub(crate) fn open_stream(
    auditor: &X25519Keypair,
    ephemeral: &X25519Pubkey,
    schedule: StreamSchedule,
    data: &mut [u8],
) -> Result<()> {
    let secret = shared_secret(&*auditor.ecdh(ephemeral)?, ephemeral, &auditor.pubkey())?;
    apply_stream(&secret, schedule, data)
}

fn apply_stream(secret: &[u8; 32], schedule: StreamSchedule, data: &mut [u8]) -> Result<()> {
    match schedule {
        StreamSchedule::Audit => symmetric_apply_audit(secret, AUDIT_STREAM_INFO, data),
        StreamSchedule::Labelled(info) => symmetric_apply(secret, info, data),
    }
    .map_err(Into::into)
}

/// A nullifier key sealed to the ring auditor, plaintext byte zero is the pad the circuit pins.
pub struct NullifierKeyEnvelope {
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    pub sealed: SealedNullifierKey,
    pub nullifier_pk: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedNullifierKey {
    pub eph_pk: X25519Pubkey,
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
}

impl NullifierKeyEnvelope {
    pub fn new(nullifier_key: &NullifierKey, auditor_pk: &X25519Pubkey) -> Result<Self> {
        Self::seal(nullifier_key, auditor_pk, X25519Keypair::new())
    }

    fn seal(
        nullifier_key: &NullifierKey,
        auditor_pk: &X25519Pubkey,
        ephemeral: X25519Keypair,
    ) -> Result<Self> {
        let mut ciphertext = Zeroizing::new(right_align(&nullifier_key.secret()));
        seal_stream(
            &ephemeral,
            auditor_pk,
            StreamSchedule::Labelled(NF_KEY_ENC_INFO),
            &mut *ciphertext,
        )?;
        Ok(Self {
            ephemeral_sk: ephemeral.secret_bytes(),
            sealed: SealedNullifierKey {
                eph_pk: ephemeral.pubkey(),
                ciphertext: *ciphertext,
            },
            nullifier_pk: nullifier_key.pubkey()?,
        })
    }
}

impl SealedNullifierKey {
    /// The pad alone does not authenticate the key against its registry record.
    pub fn open(&self, auditor: &X25519Keypair) -> Result<NullifierKey> {
        let mut plaintext = Zeroizing::new(self.ciphertext);
        open_stream(
            auditor,
            &self.eph_pk,
            StreamSchedule::Labelled(NF_KEY_ENC_INFO),
            &mut *plaintext,
        )?;
        let [pad, secret @ ..] = &*plaintext;
        if *pad != 0 {
            return Err(AuditError::NullifierPad);
        }
        Ok(NullifierKey::from_secret(*secret))
    }
}

/// The owner commitment preimage a deposit discloses to the auditor.
pub struct DepositOpening {
    pub owner_hash: [u8; 32],
    pub blinding: Zeroizing<[u8; 32]>,
    /// The Ed25519 owner key an anonymous ring discloses, the proof binds it to `owner_hash`.
    pub owner_key: Option<[u8; 32]>,
}

/// Batch ciphertexts and the ephemeral secret the disclosure proof witnesses.
pub struct DepositEncryption {
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    pub ephemeral_pk: X25519Pubkey,
    pub ciphertexts: Vec<[u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]>,
}

const DEPOSIT_STREAM_LEN: usize = RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN * MAX_RING_DEPOSIT_AUDIT_SLOTS;
const DEPOSIT_SCHEDULE: StreamSchedule = StreamSchedule::Labelled(RING_DEPOSIT_AUDIT_INFO);

/// Seals deposit openings to the ring's pinned auditor key.
pub fn seal_deposits(
    openings: &[DepositOpening],
    auditor_pk: &X25519Pubkey,
) -> Result<DepositEncryption> {
    seal_deposits_with(openings, auditor_pk, X25519Keypair::new())
}

fn seal_deposits_with(
    openings: &[DepositOpening],
    auditor_pk: &X25519Pubkey,
    ephemeral: X25519Keypair,
) -> Result<DepositEncryption> {
    if openings.is_empty() || openings.len() > MAX_RING_DEPOSIT_AUDIT_SLOTS {
        return Err(AuditError::DepositCount(openings.len()));
    }
    let mut plaintext = Zeroizing::new([0u8; DEPOSIT_STREAM_LEN]);
    let (slots, _) = plaintext.as_chunks_mut::<RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN>();
    for (slot, opening) in slots.iter_mut().zip(openings) {
        slot[..32].copy_from_slice(&opening.owner_hash);
        slot[32..RING_DEPOSIT_AUDIT_OWNER_KEY_OFFSET].copy_from_slice(opening.blinding.as_slice());
        slot[RING_DEPOSIT_AUDIT_OWNER_KEY_OFFSET..]
            .copy_from_slice(&opening.owner_key.unwrap_or_default());
    }
    seal_stream(&ephemeral, auditor_pk, DEPOSIT_SCHEDULE, &mut *plaintext)?;
    Ok(DepositEncryption {
        ephemeral_sk: ephemeral.secret_bytes(),
        ephemeral_pk: ephemeral.pubkey(),
        ciphertexts: plaintext.as_chunks().0[..openings.len()].to_vec(),
    })
}

/// Opens a capsule only after binding every ciphertext byte to its confirmed deposit proof.
pub fn open_deposit(
    capsule: &RingDepositAuditCapsule<'_>,
    auditor: &X25519Keypair,
    owner_utxo_hash: &[u8; 32],
    confirmed: &crate::ConfirmedDeposit,
) -> Result<DepositOpening> {
    if !confirmed.matches(*capsule, owner_utxo_hash) {
        return Err(AuditError::DepositOpeningMismatch);
    }
    let slot = usize::from(capsule.slot_index);
    if slot >= MAX_RING_DEPOSIT_AUDIT_SLOTS {
        return Err(AuditError::DepositSlot(slot));
    }
    let mut plaintext = Zeroizing::new([0u8; DEPOSIT_STREAM_LEN]);
    let offset = slot * RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN;
    let opened = offset..offset + RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN;
    plaintext[opened.clone()].copy_from_slice(capsule.ciphertext);
    open_stream(
        auditor,
        &X25519Pubkey::from_bytes(*capsule.eph_pk)?,
        DEPOSIT_SCHEDULE,
        &mut *plaintext,
    )?;
    let mut opening = DepositOpening {
        owner_hash: [0; 32],
        blinding: Zeroizing::new([0; 32]),
        owner_key: None,
    };
    let key_offset = offset + RING_DEPOSIT_AUDIT_OWNER_KEY_OFFSET;
    opening
        .owner_hash
        .copy_from_slice(&plaintext[offset..offset + 32]);
    opening
        .blinding
        .copy_from_slice(&plaintext[offset + 32..key_offset]);
    let mut owner_key = [0u8; 32];
    owner_key.copy_from_slice(&plaintext[key_offset..opened.end]);
    opening.owner_key = (owner_key != [0; 32]).then_some(owner_key);
    if Poseidon::hashv(&[&opening.owner_hash, opening.blinding.as_slice()])? != *owner_utxo_hash {
        return Err(AuditError::DepositOpeningMismatch);
    }
    Ok(opening)
}

#[cfg(test)]
mod tests {
    use custom_ring_interface::EscrowKey;

    use super::*;
    mod deposit_fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/common/deposit.rs"
        ));
    }

    fn bytes<const N: usize>(value: &str) -> [u8; N] {
        let decoded = hex::decode(value).expect("hex");
        decoded.try_into().expect("byte length")
    }

    #[test]
    fn shared_secret_matches_the_circuit_vector() {
        let diffie_hellman_x =
            bytes("464b33b122dc1346a6012199742d7e14b2ee6436589c454a579fdda24feec92c");
        let ephemeral_key = X25519Pubkey::from_bytes(bytes(
            "048ea960e4e1b72cdec9a6e7d86ae28cd04edb4b5c07266d3c32d9133c8ebaa966",
        ))
        .expect("ephemeral key");
        let auditor_key = X25519Pubkey::from_bytes(bytes(
            "04708c2645c705baaf44f2ab947574174f9280df58be6fc2f6f2e8881b78a3115a",
        ))
        .expect("auditor key");
        let secret =
            shared_secret(&diffie_hellman_x, &ephemeral_key, &auditor_key).expect("shared secret");
        assert_eq!(
            *secret,
            bytes("2590b2b949a2f87b9201e4d065167ea9282c4bd06a32e888e24e33c5bddae54f")
        );
    }

    #[test]
    fn shared_secret_binds_both_keys_and_the_ecdh_value() {
        let auditor_key = X25519Keypair::new().pubkey();
        let other_auditor_key = X25519Keypair::new().pubkey();
        let ephemeral_key = X25519Keypair::new().pubkey();
        let other_ephemeral_key = X25519Keypair::new().pubkey();
        let derive = |dh, eph, auditor| shared_secret(dh, eph, auditor).expect("shared secret");
        let secret = derive(&[7u8; 32], &ephemeral_key, &auditor_key);
        assert_ne!(secret, derive(&[8u8; 32], &ephemeral_key, &auditor_key));
        assert_ne!(
            secret,
            derive(&[7u8; 32], &other_ephemeral_key, &auditor_key)
        );
        assert_ne!(
            secret,
            derive(&[7u8; 32], &ephemeral_key, &other_auditor_key)
        );
    }

    #[test]
    fn nullifier_key_envelope_round_trips_through_the_auditor() {
        let auditor = X25519Keypair::new();
        let nullifier_key = NullifierKey::from_secret([7u8; 31]);
        let envelope =
            NullifierKeyEnvelope::new(&nullifier_key, &auditor.pubkey()).expect("encrypt");
        let recovered = envelope.sealed.open(&auditor).expect("decrypt");
        assert_eq!(
            recovered.secret().as_slice(),
            nullifier_key.secret().as_slice()
        );
        assert_eq!(
            envelope.nullifier_pk,
            nullifier_key.pubkey().expect("pubkey")
        );
    }

    #[test]
    fn a_stranger_auditor_cannot_recover_the_nullifier_key() {
        let auditor = X25519Keypair::new();
        let stranger = X25519Keypair::new();
        let nullifier_key = NullifierKey::from_secret([9u8; 31]);
        let envelope =
            NullifierKeyEnvelope::new(&nullifier_key, &auditor.pubkey()).expect("encrypt");
        match envelope.sealed.open(&stranger) {
            Err(AuditError::NullifierPad) => {}
            Ok(recovered) => {
                assert_ne!(
                    recovered.secret().as_slice(),
                    nullifier_key.secret().as_slice()
                )
            }
            Err(other) => panic!("unexpected error {other}"),
        }
    }

    /// The `go_vectors.rs` auditor scalar, the TypeScript mirror pins the same values.
    const AUDITOR_SK: &str = "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c";
    const EPHEMERAL_SK: &str = "011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e";
    const NULLIFIER_SECRET: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const NULLIFIER_PK: &str = "2d1faf6cf358763421511eb637adf7b6609443d38edc4ed2b042dfbf834b03f5";
    const EPH_PK: &str = "043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0eb63";
    const CIPHERTEXT: &str = "2c2a1650e3a2a0d012a0d438341ff610ad99bd3c1cde0dd169179174880e755d";
    const KEY_HASH: &str = "1c73c14786dd7354525c98368bca8dbc5f836e957c45f552f377c84e266546c4";

    #[test]
    fn the_sealed_key_and_its_escrow_key_match_the_pinned_vector() {
        let auditor = X25519Keypair::from_bytes(&bytes(AUDITOR_SK));
        let nullifier_key = NullifierKey::from_secret(bytes(NULLIFIER_SECRET));
        let ephemeral = X25519Keypair::from_bytes(&bytes(EPHEMERAL_SK));
        let envelope =
            NullifierKeyEnvelope::seal(&nullifier_key, &auditor.pubkey(), ephemeral).expect("seal");
        assert_eq!(envelope.nullifier_pk, bytes(NULLIFIER_PK));
        assert_eq!(envelope.sealed.eph_pk.as_bytes(), &bytes::<33>(EPH_PK));
        assert_eq!(envelope.sealed.ciphertext, bytes(CIPHERTEXT));
        assert_eq!(
            envelope
                .sealed
                .open(&auditor)
                .expect("open")
                .secret()
                .as_slice(),
            &bytes::<31>(NULLIFIER_SECRET)
        );
        let key = EscrowKey {
            nullifier_pk: &envelope.nullifier_pk,
            ciphertext: &envelope.sealed.ciphertext,
        }
        .hash()
        .expect("key hash");
        assert_eq!(key, bytes(KEY_HASH));
    }

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
        let sealed = seal_deposits_with(&openings, &auditor.pubkey(), ephemeral).unwrap();
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
            member_registry_root: None,
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
        let sealed = seal_deposits(&openings, &auditor.pubkey()).unwrap();
        for (index, ciphertext) in sealed.ciphertexts.iter().enumerate() {
            let capsule = RingDepositAuditCapsule {
                slot_index: index as u8,
                eph_pk: sealed.ephemeral_pk.as_bytes(),
                ciphertext,
                recipient_ciphertext: &[],
            };
            let owner = zolana_transaction::owner_utxo_hash(
                &openings[index].owner_hash,
                &openings[index].blinding,
            )
            .unwrap();
            let ring = solana_address::Address::new_from_array([9; 32]);
            let deposits = (0..=index)
                .map(|slot| {
                    let capsule = RingDepositAuditCapsule {
                        slot_index: slot as u8,
                        ..capsule
                    };
                    (owner, capsule.encode())
                })
                .collect();
            let group = deposit_fixture::group(ring, true, deposits);
            let origin = crate::ring_event_origin_in(&[group], 0, ring).unwrap();
            let binding = &origin.deposits[index];
            let opened = open_deposit(&capsule, &auditor, &owner, binding).unwrap();
            let mut corrupted = *capsule.ciphertext;
            corrupted[RING_DEPOSIT_AUDIT_OWNER_KEY_OFFSET] ^= 1;
            let altered = RingDepositAuditCapsule {
                ciphertext: &corrupted,
                ..capsule
            };
            assert!(matches!(
                open_deposit(&altered, &auditor, &owner, binding),
                Err(AuditError::DepositOpeningMismatch)
            ));
            assert_eq!(opened.owner_hash, openings[index].owner_hash);
            assert_eq!(*opened.blinding, *openings[index].blinding);
            assert_eq!(opened.owner_key, openings[index].owner_key);
        }
    }

    #[test]
    fn empty_and_oversized_batches_are_rejected() {
        let auditor = X25519Keypair::new().pubkey();
        assert!(matches!(
            seal_deposits(&[], &auditor),
            Err(AuditError::DepositCount(0))
        ));
        let openings: Vec<_> = (0..=MAX_RING_DEPOSIT_AUDIT_SLOTS)
            .map(|_| DepositOpening {
                owner_hash: [0; 32],
                blinding: Zeroizing::new([0; 32]),
                owner_key: None,
            })
            .collect();
        assert!(matches!(
            seal_deposits(&openings, &auditor),
            Err(AuditError::DepositCount(9))
        ));
    }
}
