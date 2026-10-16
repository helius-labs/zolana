//! Host mirror of the ring circuits' auditor crypto (`prover/server/custom_rings/circuits/base`).
//! Every stream is keyed by `Poseidon(CR_S, dh, eph_pk, auditor_pk)` over the packed X25519 values.

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
    symmetric_apply, NullifierKey, ViewingKey, X25519Pubkey, X25519Secret,
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

/// The auditor key's u-coordinate, the tag the auditor scans for.
pub fn auditor_view_tag(pk: &X25519Pubkey) -> [u8; 32] {
    pk.u()
}

/// Binds the X25519 output to both keys that produced it, in the order `pack.go` hashes.
pub(crate) fn shared_secret(
    dh: &[u8; 32],
    ephemeral: &X25519Pubkey,
    auditor: &X25519Pubkey,
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
    ephemeral: &X25519Secret,
    auditor: &X25519Pubkey,
    info: &[u8; 10],
    data: &mut [u8],
) -> Result<()> {
    auditor_stream(ephemeral, auditor, true, info, data)
}

fn open_stream(
    auditor: &X25519Secret,
    ephemeral: &X25519Pubkey,
    info: &[u8; 10],
    data: &mut [u8],
) -> Result<()> {
    auditor_stream(auditor, ephemeral, false, info, data)
}

/// `local` is the ephemeral key when sealing and the auditor key when opening.
fn auditor_stream(
    local: &X25519Secret,
    remote: &X25519Pubkey,
    sealing: bool,
    info: &[u8; 10],
    data: &mut [u8],
) -> Result<()> {
    let dh = local.ecdh(remote)?;
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
    eph_pk: X25519Pubkey,
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
    pub fn new(eph_pk: X25519Pubkey, ciphertext: [u8; AUDIT_CIPHERTEXT_LEN]) -> Self {
        Self {
            eph_pk,
            ciphertext,
            disclosure: [[0u8; 32]; AUDIT_DISCLOSURE_FIELD_COUNT],
        }
    }

    /// The transaction viewing secret, unchecked as a scalar.
    pub fn decrypt(&self, auditor: &X25519Secret) -> Result<Zeroizing<[u8; 32]>> {
        let mut plaintext = Zeroizing::new(self.ciphertext);
        open_stream(auditor, &self.eph_pk, AUDIT_ENC_INFO, &mut *plaintext)?;
        Ok(plaintext)
    }

    pub fn to_message_data(&self, auditor_pk: &X25519Pubkey) -> MessageData {
        let mut data = Vec::with_capacity(AUDITOR_MESSAGE_LEN);
        data.extend_from_slice(self.eph_pk.as_bytes());
        data.extend_from_slice(&self.ciphertext);
        data.extend(self.disclosure.iter().flatten());
        MessageData {
            view_tag: auditor_view_tag(auditor_pk),
            data,
        }
    }

    pub fn parse(message: &MessageData, auditor_pk: &X25519Pubkey) -> Result<Self> {
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
        let mut message = Self::new(X25519Pubkey::from_bytes(key)?, [0; AUDIT_CIPHERTEXT_LEN]);
        message.ciphertext.copy_from_slice(ciphertext);
        message.disclosure = fields;
        Ok(message)
    }

    pub fn ephemeral_pubkey(&self) -> X25519Pubkey {
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
    pub fn new(tx_viewing_key: &ViewingKey, auditor_pk: &X25519Pubkey) -> Result<Self> {
        let ephemeral = X25519Secret::new();
        let mut ciphertext = tx_viewing_key.secret_bytes();
        seal_stream(&ephemeral, auditor_pk, AUDIT_ENC_INFO, &mut *ciphertext)?;
        Ok(Self {
            ephemeral_sk: ephemeral.secret_bytes(),
            message: AuditorMessage::new(ephemeral.pubkey(), *ciphertext),
        })
    }

    pub fn new_with_outputs(
        tx_viewing_key: &ViewingKey,
        auditor_pk: &X25519Pubkey,
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
    pub eph_pk: X25519Pubkey,
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
}

impl NullifierKeyEnvelope {
    pub fn new(nullifier_key: &NullifierKey, auditor_pk: &X25519Pubkey) -> Result<Self> {
        Self::seal(nullifier_key, auditor_pk, X25519Secret::new())
    }

    fn seal(
        nullifier_key: &NullifierKey,
        auditor_pk: &X25519Pubkey,
        ephemeral: X25519Secret,
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
    pub fn open(&self, auditor: &X25519Secret) -> Result<NullifierKey> {
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
    pub ephemeral_pk: X25519Pubkey,
    pub ciphertexts: Vec<[u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]>,
}

const DEPOSIT_STREAM_LEN: usize = RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN * MAX_RING_DEPOSIT_AUDIT_SLOTS;

/// Seals deposit openings to the ring's pinned auditor key.
pub fn seal_deposits(
    openings: &[DepositOpening],
    auditor_pk: &X25519Pubkey,
) -> Result<DepositEncryption> {
    seal_deposits_with(openings, auditor_pk, X25519Secret::new())
}

fn seal_deposits_with(
    openings: &[DepositOpening],
    auditor_pk: &X25519Pubkey,
    ephemeral: X25519Secret,
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
    auditor: &X25519Secret,
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
        &X25519Pubkey::from_bytes(*capsule.eph_pk)?,
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
    use custom_ring_interface::{EscrowKey, RegisterKeyPublicInput, MEMBER_REGISTRY_EMPTY_ROOT};
    use zolana_ring_member_registry::MemberRegistryTree;
    use zolana_ring_policy::Member;

    use super::*;

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
        let auditor_key = X25519Secret::new().pubkey();
        let other_auditor_key = X25519Secret::new().pubkey();
        let ephemeral_key = X25519Secret::new().pubkey();
        let other_ephemeral_key = X25519Secret::new().pubkey();
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
        let auditor = X25519Secret::new();
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
        let auditor = X25519Secret::new();
        let stranger = X25519Secret::new();
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
    const EPH_PK: &str = "043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0eb63";
    const CIPHERTEXT: &str = "2c2a1650e3a2a0d012a0d438341ff610ad99bd3c1cde0dd169179174880e755d";
    const KEY_HASH: &str = "1c73c14786dd7354525c98368bca8dbc5f836e957c45f552f377c84e266546c4";

    #[test]
    fn the_sealed_key_and_its_registration_statement_match_the_pinned_vector() {
        let auditor = X25519Secret::from_bytes(&bytes(AUDITOR_SK)).expect("auditor");
        let nullifier_key = NullifierKey::from_secret(bytes(NULLIFIER_SECRET));
        let ephemeral = X25519Secret::from_bytes(&bytes(EPHEMERAL_SK)).expect("ephemeral");
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

        let member = Member::owner_tag(&MEMBER_TAG).expect("member");
        // The first registration inserts the record at index 1 above the sentinel.
        let mut registry = MemberRegistryTree::new().expect("empty registry");
        let item = registry
            .register_item(member.as_bytes(), key)
            .expect("registration item");
        assert_eq!(registry.root(), MEMBER_REGISTRY_EMPTY_ROOT);
        assert_eq!(item.index, 1);
        assert_eq!(item.escrow_key, key);
        registry.apply(&[item]).expect("first registration");
        assert_ne!(registry.root(), MEMBER_REGISTRY_EMPTY_ROOT);

        let public_input = RegisterKeyPublicInput {
            registry_old_root: &MEMBER_REGISTRY_EMPTY_ROOT,
            registry_new_root: &registry.root(),
            member: member.as_bytes(),
            nullifier_pk: &envelope.nullifier_pk,
            auditor_pk: auditor.pubkey().as_bytes(),
            eph_pk: envelope.sealed.eph_pk.as_bytes(),
            ciphertext: &envelope.sealed.ciphertext,
            index: item.index,
        }
        .hash()
        .expect("public input");
        assert_ne!(public_input, [0; 32]);
    }

    #[test]
    fn deposit_encryption_and_public_hash_match_the_typescript_vector() {
        let auditor = X25519Secret::from_bytes(&[0x11; 32]).unwrap();
        let ephemeral = X25519Secret::from_bytes(&[0x22; 32]).unwrap();
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
            "047b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
        );
        assert_eq!(
            hex::encode(sealed.ephemeral_pk.as_bytes()),
            "040faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"
        );
        assert_eq!(hex::encode(sealed.ciphertexts[0]), "006d5d4d188464de0e852c806b11ef3850cd683b977fea9bd1b9278b6461669f631350fa47a91f10cceb37738a4fefe7f88ded2f36b08fa08cb0ebba02684144");
        assert_eq!(hex::encode(sealed.ciphertexts[1]), "24ab3ee9887da5fa32d2074fbd7155bc72723a28dacb3fd92f045649bba3cdf4588ca73e11d9094a68cc5e7c26aadac08f1bc0f41c3580bf9ddc70518b26a820");
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
            member_registry_root: None,
        }
        .hash()
        .unwrap();
        assert_eq!(
            hex::encode(public_hash),
            "0b0b034e07cb9b13f86c4e840d388aaeeb37cf3f6966f94bbc2f70646f056fef"
        );
    }

    #[test]
    fn every_slot_uses_its_batch_stream_offset() {
        let auditor = X25519Secret::new();
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
        let auditor = X25519Secret::new().pubkey();
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
