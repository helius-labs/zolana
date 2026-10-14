//! Host mirror of the ring circuits' auditor crypto (`prover/server/custom_rings/circuits/base`).
//! Every stream is keyed by `Poseidon(CR_S, dh, eph_pk, auditor_pk)` over the packed values.

use custom_ring_interface::{
    pack_2fe, FieldPair, RingDepositAuditCapsule, AUDITOR_MESSAGE_LEN, AUDIT_CIPHERTEXT_LEN,
    AUDIT_DISCLOSURE_FIELD_COUNT, AUDIT_OUTPUT_FIELD_COUNT, AUDIT_OUTPUT_SLOTS,
    COMPRESSED_P256_KEY_LEN, MAX_RING_DEPOSIT_AUDIT_SLOTS, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN,
    RING_DEPOSIT_AUDIT_INFO,
};
use num_bigint::BigUint;
use zeroize::Zeroizing;
use zolana_client::ProofInputUtxo;
use zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE;
use zolana_interface::instruction::MessageData;
use zolana_keypair::{
    hash::{poseidon, right_align},
    symmetric_apply, NullifierKey, P256Pubkey, ViewingKey,
};

use crate::AuditError;

/// Equals the Go `auditEncInfo`.
pub(crate) const AUDIT_ENC_INFO: &[u8; 10] = b"CRING/adt1";
const NF_KEY_ENC_INFO: &[u8; 10] = b"CRING/nfk1";
/// ASCII "CR_S", the Go `DomSepCRShared`.
const DOM_SEP_CR_SHARED: u32 = 0x4352_5f53;
/// ASCII "CR_OD", the output disclosure stream domain.
const DISCLOSURE_DOMAIN: u64 = 0x4352_5f4f44;

type Result<T> = core::result::Result<T, AuditError>;

/// The auditor key's x-coordinate, the tag the auditor scans for.
pub fn auditor_view_tag(pk: &P256Pubkey) -> [u8; 32] {
    pk.x()
}

/// Binds the ECDH x-coordinate to both keys that produced it, in the order `pack.go` hashes.
pub(crate) fn shared_secret(
    dh: &[u8; 32],
    ephemeral: &P256Pubkey,
    auditor: &P256Pubkey,
) -> Result<Zeroizing<[u8; 32]>> {
    let [dh, ephemeral, auditor] = [
        pack_2fe(dh),
        pack_2fe(ephemeral.as_bytes()),
        pack_2fe(auditor.as_bytes()),
    ];
    Ok(Zeroizing::new(poseidon(&[
        &right_align(&DOM_SEP_CR_SHARED.to_be_bytes()),
        &dh.lo,
        &dh.hi,
        &ephemeral.lo,
        &ephemeral.hi,
        &auditor.lo,
        &auditor.hi,
    ])?))
}

/// Seals `data` from an ephemeral key to the auditor.
pub(crate) fn seal_stream(
    ephemeral: &ViewingKey,
    auditor: &P256Pubkey,
    info: &[u8; 10],
    data: &mut [u8],
) -> Result<()> {
    auditor_stream(ephemeral, auditor, true, info, data)
}

fn open_stream(
    auditor: &ViewingKey,
    ephemeral: &P256Pubkey,
    info: &[u8; 10],
    data: &mut [u8],
) -> Result<()> {
    auditor_stream(auditor, ephemeral, false, info, data)
}

/// `local` is the ephemeral key when sealing and the auditor key when opening.
fn auditor_stream(
    local: &ViewingKey,
    remote: &P256Pubkey,
    sealing: bool,
    info: &[u8; 10],
    data: &mut [u8],
) -> Result<()> {
    let dh = Zeroizing::new(local.ecdh(remote)?);
    let local_pk = local.pubkey();
    let (ephemeral, auditor) = match sealing {
        true => (&local_pk, remote),
        false => (remote, &local_pk),
    };
    Ok(symmetric_apply(
        &*shared_secret(&dh, ephemeral, auditor)?,
        info,
        data,
    )?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditorMessage {
    eph_pk: P256Pubkey,
    /// AES-256-CTR ciphertext of the transaction viewing secret key.
    ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
    disclosure: [[u8; 32]; AUDIT_DISCLOSURE_FIELD_COUNT],
}

/// The only way to a message is a fresh ephemeral scalar, so a CTR keystream is never reused.
pub struct AuditorEncryption {
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    pub message: AuditorMessage,
}

impl AuditorMessage {
    pub fn new(eph_pk: P256Pubkey, ciphertext: [u8; AUDIT_CIPHERTEXT_LEN]) -> Self {
        Self {
            eph_pk,
            ciphertext,
            disclosure: [[0u8; 32]; AUDIT_DISCLOSURE_FIELD_COUNT],
        }
    }

    /// The transaction viewing secret, unchecked as a scalar.
    pub fn decrypt(&self, auditor: &ViewingKey) -> Result<Zeroizing<[u8; 32]>> {
        let mut plaintext = Zeroizing::new(self.ciphertext);
        open_stream(auditor, &self.eph_pk, AUDIT_ENC_INFO, &mut *plaintext)?;
        Ok(plaintext)
    }

    pub fn to_message_data(&self, auditor_pk: &P256Pubkey) -> MessageData {
        let mut data = Vec::with_capacity(AUDITOR_MESSAGE_LEN);
        data.extend_from_slice(self.eph_pk.as_bytes());
        data.extend_from_slice(&self.ciphertext);
        data.extend(self.disclosure.iter().flatten());
        MessageData {
            view_tag: auditor_view_tag(auditor_pk),
            data,
        }
    }

    pub fn parse(message: &MessageData, auditor_pk: &P256Pubkey) -> Result<Self> {
        if message.view_tag != auditor_view_tag(auditor_pk) {
            return Err(AuditError::ViewTagMismatch);
        }
        let Ok(data) = <&[u8; AUDITOR_MESSAGE_LEN]>::try_from(message.data.as_slice()) else {
            return Err(AuditError::MessageLength(message.data.len()));
        };
        let (eph_pk, body) = data.split_at(COMPRESSED_P256_KEY_LEN);
        let (ciphertext, disclosure) = body.split_at(AUDIT_CIPHERTEXT_LEN);
        let mut fields = [[0u8; 32]; AUDIT_DISCLOSURE_FIELD_COUNT];
        for (field, bytes) in fields.iter_mut().zip(disclosure.as_chunks::<32>().0) {
            if *bytes >= BN254_SCALAR_MODULUS_BE {
                return Err(AuditError::DisclosureField);
            }
            *field = *bytes;
        }
        let mut key = [0u8; COMPRESSED_P256_KEY_LEN];
        key.copy_from_slice(eph_pk);
        let mut message = Self::new(P256Pubkey::from_bytes(key)?, [0; AUDIT_CIPHERTEXT_LEN]);
        message.ciphertext.copy_from_slice(ciphertext);
        message.disclosure = fields;
        Ok(message)
    }

    pub fn ephemeral_pubkey(&self) -> P256Pubkey {
        self.eph_pk
    }

    pub fn ephemeral_pubkey_bytes(&self) -> &[u8; COMPRESSED_P256_KEY_LEN] {
        self.eph_pk.as_bytes()
    }

    pub fn ciphertext(&self) -> &[u8; AUDIT_CIPHERTEXT_LEN] {
        &self.ciphertext
    }

    pub fn disclosure(&self) -> &[[u8; 32]; AUDIT_DISCLOSURE_FIELD_COUNT] {
        &self.disclosure
    }

    pub fn open_outputs(
        &self,
        tx_viewing_key: &ViewingKey,
        salt: [u8; 16],
    ) -> Result<[ProofInputUtxo; AUDIT_OUTPUT_SLOTS]> {
        let fields = disclosure_stream(tx_viewing_key, salt, self.disclosure, false)?;
        Ok(core::array::from_fn(|slot| {
            let field = |index: usize| fields[slot * AUDIT_OUTPUT_FIELD_COUNT + index];
            ProofInputUtxo {
                domain: field(0),
                tree_id: field(1),
                owner_hash: field(2),
                asset: field(3),
                amount: field(4),
                blinding: field(5),
                data_hash: field(6),
                ring_data_hash: field(7),
                ring_program_id: field(8),
            }
        }))
    }
}

impl AuditorEncryption {
    pub fn new(tx_viewing_key: &ViewingKey, auditor_pk: &P256Pubkey) -> Result<Self> {
        let ephemeral = ViewingKey::new();
        let mut ciphertext = tx_viewing_key.secret_bytes();
        seal_stream(&ephemeral, auditor_pk, AUDIT_ENC_INFO, &mut *ciphertext)?;
        Ok(Self {
            ephemeral_sk: ephemeral.secret_bytes(),
            message: AuditorMessage::new(ephemeral.pubkey(), *ciphertext),
        })
    }

    pub fn new_with_outputs(
        tx_viewing_key: &ViewingKey,
        auditor_pk: &P256Pubkey,
        salt: [u8; 16],
        outputs: &[ProofInputUtxo],
    ) -> Result<Self> {
        if outputs.is_empty() || outputs.len() > AUDIT_OUTPUT_SLOTS {
            return Err(AuditError::OutputCount(outputs.len()));
        }
        let mut sealed = Self::new(tx_viewing_key, auditor_pk)?;
        let mut plaintext = [[0u8; 32]; AUDIT_DISCLOSURE_FIELD_COUNT];
        let (slots, _) = plaintext.as_chunks_mut::<AUDIT_OUTPUT_FIELD_COUNT>();
        for (slot, output) in slots.iter_mut().zip(outputs) {
            *slot = [
                output.domain,
                output.tree_id,
                output.owner_hash,
                output.asset,
                output.amount,
                output.blinding,
                output.data_hash,
                output.ring_data_hash,
                output.ring_program_id,
            ];
        }
        sealed.message.disclosure = disclosure_stream(tx_viewing_key, salt, plaintext, true)?;
        Ok(sealed)
    }
}

/// Adds or removes the Poseidon mask of each disclosure field modulo the BN254 order.
fn disclosure_stream(
    tx_viewing_key: &ViewingKey,
    salt: [u8; 16],
    fields: [[u8; 32]; AUDIT_DISCLOSURE_FIELD_COUNT],
    encrypt: bool,
) -> Result<[[u8; 32]; AUDIT_DISCLOSURE_FIELD_COUNT]> {
    let FieldPair { lo, hi } = pack_2fe(&tx_viewing_key.secret_bytes());
    let modulus = BigUint::from_bytes_be(&BN254_SCALAR_MODULUS_BE);
    let mut out = [[0u8; 32]; AUDIT_DISCLOSURE_FIELD_COUNT];
    for (index, (field, result)) in fields.into_iter().zip(out.iter_mut()).enumerate() {
        let mask = BigUint::from_bytes_be(&poseidon(&[
            &right_align(&DISCLOSURE_DOMAIN.to_be_bytes()),
            &lo,
            &hi,
            &right_align(&salt),
            &right_align(&(index as u64).to_be_bytes()),
        ])?);
        let value = BigUint::from_bytes_be(&field);
        let masked = match encrypt {
            true => (value + mask) % &modulus,
            false => (value + &modulus - mask) % &modulus,
        };
        let bytes = masked.to_bytes_be();
        result[32 - bytes.len()..].copy_from_slice(&bytes);
    }
    Ok(out)
}

/// A nullifier key sealed to the ring auditor, plaintext byte zero is the pad the circuit pins.
pub struct NullifierKeyEnvelope {
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    pub sealed: SealedNullifierKey,
    pub nullifier_pk: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedNullifierKey {
    pub eph_pk: P256Pubkey,
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
}

impl NullifierKeyEnvelope {
    pub fn new(nullifier_key: &NullifierKey, auditor_pk: &P256Pubkey) -> Result<Self> {
        Self::seal(nullifier_key, auditor_pk, ViewingKey::new())
    }

    fn seal(
        nullifier_key: &NullifierKey,
        auditor_pk: &P256Pubkey,
        ephemeral: ViewingKey,
    ) -> Result<Self> {
        let mut ciphertext = Zeroizing::new(right_align(&nullifier_key.secret()));
        seal_stream(&ephemeral, auditor_pk, NF_KEY_ENC_INFO, &mut *ciphertext)?;
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
    /// The pad alone does not authenticate the key against its registry leaf.
    pub fn open(&self, auditor: &ViewingKey) -> Result<NullifierKey> {
        let mut plaintext = Zeroizing::new(self.ciphertext);
        open_stream(auditor, &self.eph_pk, NF_KEY_ENC_INFO, &mut *plaintext)?;
        if plaintext[0] != 0 {
            return Err(AuditError::NullifierPad);
        }
        let mut key = Zeroizing::new([0u8; 31]);
        key.copy_from_slice(&plaintext[1..]);
        Ok(NullifierKey::from_secret(*key))
    }
}

/// The owner commitment preimage a deposit discloses to the auditor.
pub struct DepositOpening {
    pub owner_hash: [u8; 32],
    pub blinding: Zeroizing<[u8; 32]>,
}

/// Batch ciphertexts and the ephemeral secret the disclosure proof witnesses.
pub struct DepositEncryption {
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    pub ephemeral_pk: P256Pubkey,
    pub ciphertexts: Vec<[u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]>,
}

const DEPOSIT_STREAM_LEN: usize = RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN * MAX_RING_DEPOSIT_AUDIT_SLOTS;

/// Seals deposit openings to the ring's pinned auditor key.
pub fn seal_deposits(
    openings: &[DepositOpening],
    auditor_pk: &P256Pubkey,
) -> Result<DepositEncryption> {
    seal_deposits_with(openings, auditor_pk, ViewingKey::new())
}

fn seal_deposits_with(
    openings: &[DepositOpening],
    auditor_pk: &P256Pubkey,
    ephemeral: ViewingKey,
) -> Result<DepositEncryption> {
    if openings.is_empty() || openings.len() > MAX_RING_DEPOSIT_AUDIT_SLOTS {
        return Err(AuditError::DepositCount(openings.len()));
    }
    let mut plaintext = Zeroizing::new([0u8; DEPOSIT_STREAM_LEN]);
    let (slots, _) = plaintext.as_chunks_mut::<RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN>();
    for (slot, opening) in slots.iter_mut().zip(openings) {
        slot[..32].copy_from_slice(&opening.owner_hash);
        slot[32..].copy_from_slice(opening.blinding.as_slice());
    }
    seal_stream(
        &ephemeral,
        auditor_pk,
        RING_DEPOSIT_AUDIT_INFO,
        &mut *plaintext,
    )?;
    Ok(DepositEncryption {
        ephemeral_sk: ephemeral.secret_bytes(),
        ephemeral_pk: ephemeral.pubkey(),
        ciphertexts: plaintext.as_chunks().0[..openings.len()].to_vec(),
    })
}

/// Opens one capsule at its offset in the batch stream, authenticated by the owner commitment.
pub fn open_deposit(
    capsule: &RingDepositAuditCapsule<'_>,
    auditor: &ViewingKey,
    owner_utxo_hash: &[u8; 32],
) -> Result<DepositOpening> {
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
        &P256Pubkey::from_bytes(*capsule.eph_pk)?,
        RING_DEPOSIT_AUDIT_INFO,
        &mut *plaintext,
    )?;
    let mut opening = DepositOpening {
        owner_hash: [0; 32],
        blinding: Zeroizing::new([0; 32]),
    };
    opening
        .owner_hash
        .copy_from_slice(&plaintext[offset..offset + 32]);
    opening
        .blinding
        .copy_from_slice(&plaintext[offset + 32..opened.end]);
    if poseidon(&[&opening.owner_hash, opening.blinding.as_slice()])? != *owner_utxo_hash {
        return Err(AuditError::DepositOpeningMismatch);
    }
    Ok(opening)
}

#[cfg(test)]
mod tests {
    use custom_ring_interface::{RegisterKeyPublicInput, RegisteredKey, KEY_REGISTRY_EMPTY_ROOT};
    use zolana_ring_key_registry::{KeyRegistryTree, Registration};
    use zolana_ring_policy::Member;

    use super::*;

    fn bytes<const N: usize>(value: &str) -> [u8; N] {
        let decoded = hex::decode(value).expect("hex");
        decoded.try_into().expect("byte length")
    }

    #[test]
    fn shared_secret_matches_the_circuit_vector() {
        let diffie_hellman_x =
            bytes("0adc4a9b4fc9112518acab2c346559372e9a5c2a9d8b93fb1b7650ea1edd4823");
        let ephemeral_key = P256Pubkey::from_bytes(bytes(
            "038bd43dcdaea72a1db879b1ca6faac09593fd17893d22eeef926b5c1c245a133c",
        ))
        .expect("ephemeral key");
        let auditor_key = P256Pubkey::from_bytes(bytes(
            "039dc51b59006b13f143944d4e432db7c032241ceb3698a6cc0cdabadf29b71dec",
        ))
        .expect("auditor key");
        let secret =
            shared_secret(&diffie_hellman_x, &ephemeral_key, &auditor_key).expect("shared secret");
        assert_eq!(
            *secret,
            bytes("009926f6e6fefd31699816632ef553197a3695424ddd9589e3d074518c40d605")
        );
    }

    #[test]
    fn shared_secret_binds_both_keys_and_the_ecdh_value() {
        let auditor_key = ViewingKey::new().pubkey();
        let other_auditor_key = ViewingKey::new().pubkey();
        let ephemeral_key = ViewingKey::new().pubkey();
        let other_ephemeral_key = ViewingKey::new().pubkey();
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
        let auditor = ViewingKey::new();
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
        let auditor = ViewingKey::new();
        let stranger = ViewingKey::new();
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
    const MEMBER_TAG: [u8; 32] = [9u8; 32];
    const NULLIFIER_PK: &str = "2d1faf6cf358763421511eb637adf7b6609443d38edc4ed2b042dfbf834b03f5";
    const EPH_PK: &str = "0268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955c5d5";
    const CIPHERTEXT: &str = "f329a32e36717753ba70f955e2102b53fa3a1bfd7389ebda109030ea70602d40";
    const KEY_HASH: &str = "095939aeb6e0dc92dd4455bab6058c5c5f639b52a610932c22e517fc87d64a94";
    const REGISTRY_NEW_ROOT: &str =
        "01c9026ae3349a610ca0d39793c06c924e3ad8e2dcacb64c120c800185372618";
    const PUBLIC_INPUT_HASH: &str =
        "2f3163cf5ea64c46bcf1a4b97b0aabccc674aa6056daa42cb63007bb1d9534a9";

    #[test]
    fn the_sealed_key_and_its_registration_statement_match_the_pinned_vector() {
        let auditor = ViewingKey::from_bytes(&bytes(AUDITOR_SK)).expect("auditor");
        let nullifier_key = NullifierKey::from_secret(bytes(NULLIFIER_SECRET));
        let ephemeral = ViewingKey::from_bytes(&bytes(EPHEMERAL_SK)).expect("ephemeral");
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

        let key = RegisteredKey {
            nullifier_pk: &envelope.nullifier_pk,
            ciphertext: &envelope.sealed.ciphertext,
        }
        .hash()
        .expect("key hash");
        assert_eq!(key, bytes(KEY_HASH));

        let member = Member::owner_tag(&MEMBER_TAG).expect("member");
        let inserted = KeyRegistryTree::new()
            .expect("empty registry")
            .register(Registration {
                member: *member.as_bytes(),
                key,
            })
            .expect("first registration");
        assert_eq!(inserted.old_root, KEY_REGISTRY_EMPTY_ROOT);
        assert_eq!(inserted.new_root, bytes(REGISTRY_NEW_ROOT));
        assert_eq!(inserted.new_index, 1);

        let public_input = RegisterKeyPublicInput {
            registry_old_root: &inserted.old_root,
            registry_new_root: &inserted.new_root,
            member: member.as_bytes(),
            nullifier_pk: &envelope.nullifier_pk,
            auditor_pk: auditor.pubkey().as_bytes(),
            eph_pk: envelope.sealed.eph_pk.as_bytes(),
            ciphertext: &envelope.sealed.ciphertext,
            new_index: inserted.new_index,
        }
        .hash()
        .expect("public input");
        assert_eq!(public_input, bytes(PUBLIC_INPUT_HASH));
    }

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
        let sealed = seal_deposits_with(&openings, &auditor.pubkey(), ephemeral).unwrap();
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
            let opened = open_deposit(&capsule, &auditor, &owner).unwrap();
            assert_eq!(opened.owner_hash, openings[index].owner_hash);
            assert_eq!(*opened.blinding, *openings[index].blinding);
        }
    }

    #[test]
    fn empty_and_oversized_batches_are_rejected() {
        let auditor = ViewingKey::new().pubkey();
        assert!(matches!(
            seal_deposits(&[], &auditor),
            Err(AuditError::DepositCount(0))
        ));
        let openings: Vec<_> = (0..=MAX_RING_DEPOSIT_AUDIT_SLOTS)
            .map(|_| DepositOpening {
                owner_hash: [0; 32],
                blinding: Zeroizing::new([0; 32]),
            })
            .collect();
        assert!(matches!(
            seal_deposits(&openings, &auditor),
            Err(AuditError::DepositCount(9))
        ));
    }
}
