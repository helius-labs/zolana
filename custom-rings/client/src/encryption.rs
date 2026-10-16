//! Host mirror of the custom-ring circuit's crypto
//! (`prover/server/custom_rings/circuits/base/{circuit.go,pack.go}`).
//!
//! The circuit proves that the transaction viewing secret key was encrypted to
//! the ring's auditor key, so every value below has an in-circuit counterpart
//! that must agree bit for bit:
//!
//! ```text
//! dh            = X25519(eph_sk, auditor_pk)                -- x25519.ECDH
//! shared_secret = Poseidon(DOM_SEP_CR_SHARED,
//!                          dh_lo, dh_hi,
//!                          eph_pk_lo, eph_pk_hi,
//!                          auditor_pk_lo, auditor_pk_hi)     -- DeriveAuditSharedSecret
//! ciphertext    = AES-256-CTR(KeySchedule(shared_secret, AUDIT_ENC_INFO),
//!                             tx_viewing_sk)                 -- ve.KeySchedule + aes.CTREncrypt
//! ```
//!
//! `pack.go` is the source of truth for the packing of `dh` and of the 33-byte
//! compressed keys into pairs of field elements. [`pack32_to_2fe`] and
//! [`pack33_to_2fe`] mirror it. The key schedule and the CTR keystream come from
//! [`zolana_keypair::symmetric_apply`], whose Poseidon silo/key/nonce separators
//! are the ones `ve.KeySchedule` uses.

use custom_ring_interface::{
    pack32_to_2fe, pack33_to_2fe, pack_disclosure, unpack_disclosure, DisclosureShape, FieldPair,
    AUDITOR_MESSAGE_LEN, AUDIT_CIPHERTEXT_LEN, AUDIT_DISCLOSURE_FIELD_COUNT,
    AUDIT_OUTPUT_FIELD_COUNT, AUDIT_OUTPUT_SLOTS, COMPRESSED_P256_KEY_LEN, DISCLOSURE_INPUT_LEN,
    DISCLOSURE_OUTPUT_LEN, DISCLOSURE_SENDER_LEN,
};
use num_bigint::BigUint;
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_client::ProofInputUtxo;
use zolana_hasher::primitives::BN254_SCALAR_MODULUS_BE;
use zolana_interface::instruction::MessageData;
use zolana_keypair::{
    hash::{poseidon, right_align},
    symmetric_apply, KeypairError, NullifierKey, ViewingKey, X25519Pubkey, X25519Secret,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuditEncryptionError {
    #[error("message view tag is not the auditor view tag")]
    ViewTagMismatch,
    #[error("auditor message data must be {AUDITOR_MESSAGE_LEN} bytes, got {0}")]
    MessageLength(usize),
    #[error("nullifier ciphertext did not decrypt to a zero-padded secret")]
    NullifierPad,
    #[error("deposit count must be between one and eight, got {0}")]
    DepositCount(usize),
    #[error("deposit slot must be below eight, got {0}")]
    DepositSlot(usize),
    #[error("deposit opening does not match the owner commitment")]
    DepositOpeningMismatch,
    #[error("output disclosure contains a non-canonical field element")]
    DisclosureField,
    #[error("output count must be between one and four, got {0}")]
    OutputCount(usize),
    #[error("disclosure shape does not match the transaction")]
    DisclosureShape,
    #[error("disclosure padding is not zero")]
    DisclosurePadding,
    #[error(transparent)]
    Keypair(#[from] KeypairError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditorMessage {
    /// Tagged X25519 ephemeral public key.
    eph_pk: X25519Pubkey,
    /// AES-256-CTR ciphertext of the transaction viewing secret key.
    ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
    disclosure: Vec<[u8; 32]>,
}

/// One spent note opening in an anonymous ring. The leaf index is not in the
/// circuit disclosure, so the indexer must resolve it separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditInputOpening {
    pub tree_id: u16,
    pub amount: u64,
    pub asset: [u8; 32],
    pub blinding: [u8; 32],
}

/// The owner identity and note data disclosed for one anonymous output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AnonymousOutputOpening {
    pub identity_tag: u8,
    pub identity_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub amount: u64,
    pub asset: [u8; 32],
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub ring_note: u8,
}

/// The hidden sender, spent notes and recipients bound by an anonymous proof.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnonymousDisclosure {
    pub sender: [u8; 32],
    pub inputs: Vec<AuditInputOpening>,
    pub outputs: Vec<AnonymousOutputOpening>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditOutputOpening {
    pub domain: [u8; 32],
    pub tree_id: [u8; 32],
    pub owner_hash: [u8; 32],
    pub asset: [u8; 32],
    pub amount: [u8; 32],
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub ring_program_id: [u8; 32],
}

/// A fresh ephemeral key and the auditor message it produced.
///
/// Generating the key here is what keeps the AES-CTR keystream single-use: the
/// only way to obtain a message is to obtain a new ephemeral scalar with it. The
/// scalar is kept because the circuit witnesses it.
pub struct AuditorEncryption {
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    pub message: AuditorMessage,
}

impl AuditorMessage {
    pub fn new(eph_pk: X25519Pubkey, ciphertext: [u8; AUDIT_CIPHERTEXT_LEN]) -> Self {
        Self {
            eph_pk,
            ciphertext,
            disclosure: vec![[0u8; 32]; AUDIT_DISCLOSURE_FIELD_COUNT],
        }
    }

    /// Recovers the transaction viewing secret key with the auditor's viewing key.
    ///
    /// ECDH is symmetric, so `auditor.ecdh(eph_pk)` is the same x-coordinate the
    /// sender derived, and the CTR keystream application is its own inverse.
    pub fn decrypt(&self, auditor: &X25519Secret) -> Result<Zeroizing<[u8; 32]>> {
        AuditDecryption {
            auditor,
            message: self,
        }
        .decrypt()
    }

    pub fn to_message_data(&self, auditor_pk: &X25519Pubkey) -> MessageData {
        let mut data = Vec::with_capacity(
            COMPRESSED_P256_KEY_LEN + AUDIT_CIPHERTEXT_LEN + 32 * self.disclosure.len(),
        );
        data.extend_from_slice(self.eph_pk.as_bytes());
        data.extend_from_slice(&self.ciphertext);
        for field in &self.disclosure {
            data.extend_from_slice(field);
        }
        MessageData {
            view_tag: auditor_view_tag(auditor_pk),
            data,
        }
    }

    pub fn parse(message: &MessageData, auditor_pk: &X25519Pubkey) -> Result<Self> {
        Self::parse_with_fields(message, auditor_pk, AUDIT_DISCLOSURE_FIELD_COUNT)
    }

    /// The ring mode and published slot count fix the accepted disclosure size.
    pub fn parse_with_shape(
        message: &MessageData,
        auditor_pk: &X25519Pubkey,
        shape: DisclosureShape,
    ) -> Result<Self> {
        let fields = shape
            .field_count()
            .ok_or(AuditEncryptionError::DisclosureShape)?;
        Self::parse_with_fields(message, auditor_pk, fields)
    }

    fn parse_with_fields(
        message: &MessageData,
        auditor_pk: &X25519Pubkey,
        count: usize,
    ) -> Result<Self> {
        if message.view_tag != auditor_view_tag(auditor_pk) {
            return Err(AuditEncryptionError::ViewTagMismatch);
        }
        let (eph_pk, body) = message
            .data
            .split_at_checked(COMPRESSED_P256_KEY_LEN)
            .filter(|(_, body)| body.len() == AUDIT_CIPHERTEXT_LEN + 32 * count)
            .ok_or(AuditEncryptionError::MessageLength(message.data.len()))?;
        let (ciphertext, disclosure_bytes) = body.split_at(AUDIT_CIPHERTEXT_LEN);
        let eph_pk: [u8; COMPRESSED_P256_KEY_LEN] = eph_pk
            .try_into()
            .map_err(|_| AuditEncryptionError::MessageLength(message.data.len()))?;
        let ciphertext: [u8; AUDIT_CIPHERTEXT_LEN] = ciphertext
            .try_into()
            .map_err(|_| AuditEncryptionError::MessageLength(message.data.len()))?;
        let mut disclosure = vec![[0u8; 32]; count];
        let (fields, remainder) = disclosure_bytes.as_chunks::<32>();
        debug_assert!(remainder.is_empty());
        for (field, bytes) in disclosure.iter_mut().zip(fields) {
            *field = *bytes;
            if *field >= BN254_SCALAR_MODULUS_BE {
                return Err(AuditEncryptionError::DisclosureField);
            }
        }
        Ok(Self {
            eph_pk: X25519Pubkey::from_bytes(eph_pk)?,
            ciphertext,
            disclosure,
        })
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

    pub fn disclosure(&self) -> &[[u8; 32]] {
        &self.disclosure
    }

    pub fn open_outputs(
        &self,
        tx_viewing_key: &ViewingKey,
        salt: [u8; 16],
    ) -> Result<[AuditOutputOpening; AUDIT_OUTPUT_SLOTS]> {
        if self.disclosure.len() != AUDIT_DISCLOSURE_FIELD_COUNT {
            return Err(AuditEncryptionError::DisclosureShape);
        }
        let fields = apply_disclosure_stream(tx_viewing_key, salt, &self.disclosure, false)?;
        Ok(core::array::from_fn(|slot| {
            let start = slot * AUDIT_OUTPUT_FIELD_COUNT;
            AuditOutputOpening::from_fields(
                fields[start..start + AUDIT_OUTPUT_FIELD_COUNT]
                    .try_into()
                    .expect("fixed disclosure field count"),
            )
        }))
    }

    /// Unmasks the slot-padded chunks that the anonymous circuit binds to its
    /// hidden sender, inputs and outputs.
    pub fn open_anonymous(
        &self,
        tx_viewing_key: &ViewingKey,
        salt: [u8; 16],
        shape: DisclosureShape,
    ) -> Result<AnonymousDisclosure> {
        if !shape.anonymous || Some(self.disclosure.len()) != shape.field_count() {
            return Err(AuditEncryptionError::DisclosureShape);
        }
        let fields = apply_disclosure_stream(tx_viewing_key, salt, &self.disclosure, false)?;
        let plaintext = Zeroizing::new(
            unpack_disclosure(
                &fields,
                shape
                    .plaintext_len()
                    .ok_or(AuditEncryptionError::DisclosureShape)?,
            )
            .ok_or(AuditEncryptionError::DisclosurePadding)?,
        );
        AnonymousDisclosure::decode(&plaintext, shape)
    }
}

impl AuditorEncryption {
    pub fn new(tx_viewing_key: &ViewingKey, auditor_pk: &X25519Pubkey) -> Result<Self> {
        let ephemeral = X25519Secret::new();
        let ephemeral_sk = ephemeral.secret_bytes();
        let eph_pk = ephemeral.pubkey();
        let dh = ephemeral.ecdh(auditor_pk)?;
        let shared_secret = AuditSharedSecret {
            diffie_hellman_x: &dh,
            ephemeral_key: &eph_pk,
            auditor_key: auditor_pk,
        }
        .derive()?;
        let mut ciphertext = tx_viewing_key.secret_bytes();
        symmetric_apply(&shared_secret, AUDIT_ENC_INFO, ciphertext.as_mut_slice())?;
        Ok(Self {
            ephemeral_sk,
            message: AuditorMessage::new(eph_pk, *ciphertext),
        })
    }

    pub fn new_with_outputs(
        tx_viewing_key: &ViewingKey,
        auditor_pk: &X25519Pubkey,
        salt: [u8; 16],
        outputs: &[ProofInputUtxo],
    ) -> Result<Self> {
        if outputs.is_empty() || outputs.len() > AUDIT_OUTPUT_SLOTS {
            return Err(AuditEncryptionError::OutputCount(outputs.len()));
        }
        let mut sealed = Self::new(tx_viewing_key, auditor_pk)?;
        let mut plaintext = [[0u8; 32]; AUDIT_DISCLOSURE_FIELD_COUNT];
        for (slot, output) in outputs.iter().enumerate() {
            let start = slot * AUDIT_OUTPUT_FIELD_COUNT;
            plaintext[start..start + AUDIT_OUTPUT_FIELD_COUNT]
                .copy_from_slice(&AuditOutputOpening::from(output).fields());
        }
        sealed.message.disclosure =
            apply_disclosure_stream(tx_viewing_key, salt, &plaintext, true)?;
        Ok(sealed)
    }

    /// Seals the anonymous opening using the same fresh capsule and disclosure
    /// stream as the circuit.
    pub fn new_with_anonymous(
        tx_viewing_key: &ViewingKey,
        auditor_pk: &X25519Pubkey,
        salt: [u8; 16],
        disclosure: &AnonymousDisclosure,
    ) -> Result<Self> {
        let plaintext = Zeroizing::new(disclosure.encode()?);
        let mut sealed = Self::new(tx_viewing_key, auditor_pk)?;
        sealed.message.disclosure =
            apply_disclosure_stream(tx_viewing_key, salt, &pack_disclosure(&plaintext), true)?;
        Ok(sealed)
    }
}

impl AnonymousDisclosure {
    pub fn shape(&self) -> DisclosureShape {
        DisclosureShape {
            anonymous: true,
            inputs: self.inputs.len(),
            outputs: self.outputs.len(),
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let len = self
            .shape()
            .plaintext_len()
            .ok_or(AuditEncryptionError::DisclosureShape)?;
        let mut bytes = Vec::with_capacity(len);
        bytes.push(zolana_hasher::primitives::SOLANA_OWNER_TAG);
        bytes.extend_from_slice(&self.sender);
        bytes.resize(DISCLOSURE_SENDER_LEN, 0);
        for input in &self.inputs {
            let end = bytes.len() + DISCLOSURE_INPUT_LEN;
            bytes.extend_from_slice(&input.tree_id.to_be_bytes());
            bytes.extend_from_slice(&input.amount.to_be_bytes());
            bytes.extend_from_slice(&input.asset);
            bytes.extend_from_slice(&input.blinding);
            bytes.resize(end, 0);
        }
        for output in &self.outputs {
            let end = bytes.len() + DISCLOSURE_OUTPUT_LEN;
            bytes.push(output.identity_tag);
            bytes.extend_from_slice(&output.identity_key);
            bytes.extend_from_slice(&output.nullifier_pk);
            bytes.extend_from_slice(&output.amount.to_be_bytes());
            bytes.extend_from_slice(&output.asset);
            bytes.extend_from_slice(&output.blinding);
            bytes.extend_from_slice(&output.data_hash);
            bytes.extend_from_slice(&output.ring_data_hash);
            bytes.push(output.ring_note);
            bytes.resize(end, 0);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8], shape: DisclosureShape) -> Result<Self> {
        let (header, mut rest) = bytes
            .split_at_checked(DISCLOSURE_SENDER_LEN)
            .ok_or(AuditEncryptionError::DisclosureShape)?;
        if header[0] != zolana_hasher::primitives::SOLANA_OWNER_TAG
            || header[33..].iter().any(|b| *b != 0)
        {
            return Err(AuditEncryptionError::DisclosurePadding);
        }
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&header[1..33]);
        let mut inputs = Vec::with_capacity(shape.inputs);
        for _ in 0..shape.inputs {
            let (slot, tail) = rest
                .split_at_checked(DISCLOSURE_INPUT_LEN)
                .ok_or(AuditEncryptionError::DisclosureShape)?;
            rest = tail;
            if slot[74..].iter().any(|b| *b != 0) {
                return Err(AuditEncryptionError::DisclosurePadding);
            }
            inputs.push(AuditInputOpening {
                tree_id: u16::from_be_bytes(slot[0..2].try_into().expect("fixed input slot")),
                amount: u64::from_be_bytes(slot[2..10].try_into().expect("fixed input slot")),
                asset: slot[10..42].try_into().expect("fixed input slot"),
                blinding: slot[42..74].try_into().expect("fixed input slot"),
            });
        }
        let mut outputs = Vec::with_capacity(shape.outputs);
        for _ in 0..shape.outputs {
            let (slot, tail) = rest
                .split_at_checked(DISCLOSURE_OUTPUT_LEN)
                .ok_or(AuditEncryptionError::DisclosureShape)?;
            rest = tail;
            if slot[202..].iter().any(|b| *b != 0) || slot[201] > 1 {
                return Err(AuditEncryptionError::DisclosurePadding);
            }
            outputs.push(AnonymousOutputOpening {
                identity_tag: slot[0],
                identity_key: slot[1..33].try_into().expect("fixed output slot"),
                nullifier_pk: slot[33..65].try_into().expect("fixed output slot"),
                amount: u64::from_be_bytes(slot[65..73].try_into().expect("fixed output slot")),
                asset: slot[73..105].try_into().expect("fixed output slot"),
                blinding: slot[105..137].try_into().expect("fixed output slot"),
                data_hash: slot[137..169].try_into().expect("fixed output slot"),
                ring_data_hash: slot[169..201].try_into().expect("fixed output slot"),
                ring_note: slot[201],
            });
        }
        if !rest.is_empty() {
            return Err(AuditEncryptionError::DisclosureShape);
        }
        Ok(Self {
            sender,
            inputs,
            outputs,
        })
    }
}

impl AuditOutputOpening {
    fn fields(self) -> [[u8; 32]; AUDIT_OUTPUT_FIELD_COUNT] {
        [
            self.domain,
            self.tree_id,
            self.owner_hash,
            self.asset,
            self.amount,
            self.blinding,
            self.data_hash,
            self.ring_data_hash,
            self.ring_program_id,
        ]
    }

    fn from_fields(fields: [[u8; 32]; AUDIT_OUTPUT_FIELD_COUNT]) -> Self {
        Self {
            domain: fields[0],
            tree_id: fields[1],
            owner_hash: fields[2],
            asset: fields[3],
            amount: fields[4],
            blinding: fields[5],
            data_hash: fields[6],
            ring_data_hash: fields[7],
            ring_program_id: fields[8],
        }
    }
}

impl From<&ProofInputUtxo> for AuditOutputOpening {
    fn from(output: &ProofInputUtxo) -> Self {
        Self {
            domain: output.domain,
            tree_id: output.tree_id,
            owner_hash: output.owner_hash,
            asset: output.asset,
            amount: output.amount,
            blinding: output.blinding,
            data_hash: output.data_hash,
            ring_data_hash: output.ring_data_hash,
            ring_program_id: output.ring_program_id,
        }
    }
}

fn apply_disclosure_stream(
    tx_viewing_key: &ViewingKey,
    salt: [u8; 16],
    fields: &[[u8; 32]],
    encrypt: bool,
) -> Result<Vec<[u8; 32]>> {
    const DOMAIN: u64 = 0x4352_5f4f44;
    let FieldPair { lo, hi } = pack32_to_2fe(&tx_viewing_key.secret_bytes());
    let modulus = BigUint::from_bytes_be(&BN254_SCALAR_MODULUS_BE);
    let mut out = vec![[0u8; 32]; fields.len()];
    for (index, (field, result)) in fields.iter().zip(out.iter_mut()).enumerate() {
        let stream = poseidon(&[
            &right_align(&DOMAIN.to_be_bytes()),
            &lo,
            &hi,
            &right_align(&salt),
            &right_align(&(index as u64).to_be_bytes()),
        ])?;
        let value = BigUint::from_bytes_be(field);
        let mask = BigUint::from_bytes_be(&stream);
        let transformed = if encrypt {
            (value + mask) % &modulus
        } else {
            (value + &modulus - mask) % &modulus
        };
        let bytes = transformed.to_bytes_be();
        result[32 - bytes.len()..].copy_from_slice(&bytes);
    }
    Ok(out)
}

/// Info string separating the nullifier key stream from the audit key stream.
pub(crate) const NF_KEY_ENC_INFO: &[u8; 10] = b"CRING/nfk1";

/// Nullifier key sealed to the ring auditor, plaintext byte zero is the pad the circuit pins.
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

#[must_use]
struct NullifierKeySeal<'a> {
    nullifier_key: &'a NullifierKey,
    auditor_pk: &'a X25519Pubkey,
    ephemeral: X25519Secret,
}

impl NullifierKeyEnvelope {
    pub fn new(nullifier_key: &NullifierKey, auditor_pk: &X25519Pubkey) -> Result<Self> {
        NullifierKeySeal {
            nullifier_key,
            auditor_pk,
            ephemeral: X25519Secret::new(),
        }
        .seal()
    }
}

impl NullifierKeySeal<'_> {
    fn seal(self) -> Result<NullifierKeyEnvelope> {
        let ephemeral_sk = self.ephemeral.secret_bytes();
        let eph_pk = self.ephemeral.pubkey();
        let dh = self.ephemeral.ecdh(self.auditor_pk)?;
        let shared_secret = AuditSharedSecret {
            diffie_hellman_x: &dh,
            ephemeral_key: &eph_pk,
            auditor_key: self.auditor_pk,
        }
        .derive()?;
        let secret = self.nullifier_key.secret();
        let mut ciphertext = Zeroizing::new(right_align(&secret));
        symmetric_apply(&shared_secret, NF_KEY_ENC_INFO, ciphertext.as_mut_slice())?;
        Ok(NullifierKeyEnvelope {
            ephemeral_sk,
            sealed: SealedNullifierKey {
                eph_pk,
                ciphertext: *ciphertext,
            },
            nullifier_pk: self.nullifier_key.pubkey()?,
        })
    }
}

impl SealedNullifierKey {
    /// Padding alone does not authenticate the recovered key against its
    /// registry leaf.
    pub fn open(&self, auditor: &X25519Secret) -> Result<NullifierKey> {
        let dh = auditor.ecdh(&self.eph_pk)?;
        let auditor_key = auditor.pubkey();
        let shared_secret = AuditSharedSecret {
            diffie_hellman_x: &dh,
            ephemeral_key: &self.eph_pk,
            auditor_key: &auditor_key,
        }
        .derive()?;
        let mut plaintext = Zeroizing::new(self.ciphertext);
        symmetric_apply(&shared_secret, NF_KEY_ENC_INFO, plaintext.as_mut_slice())?;
        if plaintext[0] != 0 {
            return Err(AuditEncryptionError::NullifierPad);
        }
        let mut secret = Zeroizing::new([0u8; 31]);
        secret.copy_from_slice(&plaintext[1..]);
        Ok(NullifierKey::from_secret(*secret))
    }
}

/// The view tag the auditor scans for: the auditor key's x-coordinate, i.e. the
/// little-endian coordinate without its tag.
pub fn auditor_view_tag(pk: &X25519Pubkey) -> [u8; 32] {
    pk.u()
}

type Result<T> = core::result::Result<T, AuditEncryptionError>;

/// Key-schedule info string matching the Go `auditEncInfo`.
pub(crate) const AUDIT_ENC_INFO: &[u8; 10] = b"CRING/adt1";

/// Shared-secret domain separator, ASCII "CR_S" read as a big-endian u32.
/// It matches the Go `DomSepCRShared`.
const DOM_SEP_CR_SHARED: u32 = 0x4352_5f53;

/// Mirrors `DeriveAuditSharedSecret`: binds the raw ECDH x-coordinate to both
/// public keys that produced it, so the key schedule input cannot be replayed
/// under a different key pair. Input order is pinned by `pack.go`.
#[must_use]
pub(crate) struct AuditSharedSecret<'a> {
    pub diffie_hellman_x: &'a [u8; 32],
    pub ephemeral_key: &'a X25519Pubkey,
    pub auditor_key: &'a X25519Pubkey,
}

#[must_use]
struct AuditDecryption<'a> {
    auditor: &'a X25519Secret,
    message: &'a AuditorMessage,
}

impl AuditSharedSecret<'_> {
    pub fn derive(self) -> Result<Zeroizing<[u8; 32]>> {
        let FieldPair {
            lo: dh_lo,
            hi: dh_hi,
        } = pack32_to_2fe(self.diffie_hellman_x);
        let FieldPair {
            lo: eph_lo,
            hi: eph_hi,
        } = pack33_to_2fe(self.ephemeral_key.as_bytes());
        let FieldPair {
            lo: auditor_lo,
            hi: auditor_hi,
        } = pack33_to_2fe(self.auditor_key.as_bytes());
        Ok(Zeroizing::new(poseidon(&[
            &right_align(&DOM_SEP_CR_SHARED.to_be_bytes()),
            &dh_lo,
            &dh_hi,
            &eph_lo,
            &eph_hi,
            &auditor_lo,
            &auditor_hi,
        ])?))
    }
}

impl AuditDecryption<'_> {
    pub fn decrypt(self) -> Result<Zeroizing<[u8; 32]>> {
        let ephemeral_key = self.message.ephemeral_pubkey();
        let dh = self.auditor.ecdh(&ephemeral_key)?;
        let auditor_key = self.auditor.pubkey();
        let shared_secret = AuditSharedSecret {
            diffie_hellman_x: &dh,
            ephemeral_key: &ephemeral_key,
            auditor_key: &auditor_key,
        }
        .derive()?;
        let mut plaintext = Zeroizing::new(self.message.ciphertext);
        symmetric_apply(&shared_secret, AUDIT_ENC_INFO, plaintext.as_mut_slice())?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use custom_ring_interface::{RegisterKeyPublicInput, RegisteredKey, KEY_REGISTRY_EMPTY_ROOT};
    use zolana_ring_key_registry::{KeyRegistryTree, Registration};
    use zolana_ring_policy::Member;

    use super::*;

    #[test]
    fn anonymous_disclosure_round_trips_even_when_its_count_equals_legacy() {
        let auditor = X25519Secret::new();
        let tx = ViewingKey::new();
        let disclosure = AnonymousDisclosure {
            sender: [7; 32],
            inputs: vec![
                AuditInputOpening {
                    tree_id: 4,
                    amount: 9,
                    asset: [3; 32],
                    blinding: [5; 32],
                },
                AuditInputOpening::default(),
            ],
            outputs: vec![
                AnonymousOutputOpening {
                    identity_tag: zolana_hasher::primitives::SOLANA_OWNER_TAG,
                    identity_key: [8; 32],
                    nullifier_pk: [9; 32],
                    amount: 12,
                    asset: [3; 32],
                    blinding: [4; 32],
                    ring_note: 1,
                    ..Default::default()
                };
                4
            ],
        };
        let shape = disclosure.shape();
        assert_eq!(shape.field_count(), Some(AUDIT_DISCLOSURE_FIELD_COUNT));
        let sealed =
            AuditorEncryption::new_with_anonymous(&tx, &auditor.pubkey(), [2; 16], &disclosure)
                .expect("seal");
        let parsed = AuditorMessage::parse_with_shape(
            &sealed.message.to_message_data(&auditor.pubkey()),
            &auditor.pubkey(),
            shape,
        )
        .expect("parse");
        assert_eq!(
            parsed.open_anonymous(&tx, [2; 16], shape).unwrap(),
            disclosure
        );
        let mut plaintext = disclosure.encode().unwrap();
        plaintext[33] = 1;
        assert_eq!(
            AnonymousDisclosure::decode(&plaintext, shape),
            Err(AuditEncryptionError::DisclosurePadding)
        );
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
        let secret = AuditSharedSecret {
            diffie_hellman_x: &diffie_hellman_x,
            ephemeral_key: &ephemeral_key,
            auditor_key: &auditor_key,
        }
        .derive()
        .expect("shared secret");
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
        let derive = |dh, eph, auditor| {
            AuditSharedSecret {
                diffie_hellman_x: dh,
                ephemeral_key: eph,
                auditor_key: auditor,
            }
            .derive()
            .expect("shared secret")
        };
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
            Err(AuditEncryptionError::NullifierPad) => {}
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
    const REGISTRY_NEW_ROOT: &str =
        "2ec354929355675625614fc9fd05405e3538fd0de45f028690d20e3c6a4e3b76";
    const PUBLIC_INPUT_HASH: &str =
        "27640a4aef274e2bd8e4fcc761ca86b1e70a4f203857cc2728dad0bc5b6a6085";

    #[test]
    fn the_sealed_key_and_its_registration_statement_match_the_pinned_vector() {
        let auditor = X25519Secret::from_bytes(&bytes(AUDITOR_SK)).expect("auditor");
        let nullifier_key = NullifierKey::from_secret(bytes(NULLIFIER_SECRET));
        let envelope = NullifierKeySeal {
            nullifier_key: &nullifier_key,
            auditor_pk: &auditor.pubkey(),
            ephemeral: X25519Secret::from_bytes(&bytes(EPHEMERAL_SK)).expect("ephemeral"),
        }
        .seal()
        .expect("seal");
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
}
