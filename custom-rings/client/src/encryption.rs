//! Host mirror of the custom-ring circuit's crypto
//! (`prover/server/circuits/custom_ring/{circuit.go,pack.go}`).
//!
//! The circuit proves that the transaction viewing secret key was encrypted to
//! the ring's auditor key, so every value below has an in-circuit counterpart
//! that must agree bit for bit:
//!
//! ```text
//! dh            = ECDH(eph_sk, auditor_pk).x                 -- p256.ECDH
//! shared_secret = Poseidon(DOM_SEP_CR_SHARED,
//!                          dh_lo, dh_hi,
//!                          eph_pk_lo, eph_pk_hi,
//!                          auditor_pk_lo, auditor_pk_hi)     -- DeriveAuditSharedSecret
//! ciphertext    = AES-256-CTR(KeySchedule(shared_secret, AUDIT_ENC_INFO),
//!                             tx_viewing_sk)                 -- ve.KeySchedule + aes.CTREncrypt
//! ```
//!
//! `pack.go` is the source of truth for the packing of `dh` and of the 33-byte
//! compressed keys into pairs of field elements; [`pack32_to_2fe`] and
//! [`pack33_to_2fe`] mirror it. The key schedule and the CTR keystream come from
//! [`zolana_keypair::symmetric_apply`], whose Poseidon silo/key/nonce separators
//! are the ones `ve.KeySchedule` uses.

use custom_ring_interface::{pack32_to_2fe, pack33_to_2fe, FieldPair, AUDITOR_MESSAGE_LEN};
use custom_ring_interface::{AUDIT_CIPHERTEXT_LEN, COMPRESSED_P256_KEY_LEN};
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_interface::instruction::MessageData;
use zolana_keypair::{
    hash::{poseidon, right_align},
    symmetric_apply, KeypairError, NullifierKey, P256Pubkey, ViewingKey,
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
    #[error(transparent)]
    Keypair(#[from] KeypairError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditorMessage {
    /// SEC1-compressed ephemeral public key.
    eph_pk: P256Pubkey,
    /// AES-256-CTR ciphertext of the transaction viewing secret key.
    ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
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
    pub fn new(eph_pk: P256Pubkey, ciphertext: [u8; AUDIT_CIPHERTEXT_LEN]) -> Self {
        Self { eph_pk, ciphertext }
    }

    /// Recovers the transaction viewing secret key with the auditor's viewing key.
    ///
    /// ECDH is symmetric, so `auditor.ecdh(eph_pk)` is the same x-coordinate the
    /// sender derived, and the CTR keystream application is its own inverse.
    pub fn decrypt(&self, auditor: &ViewingKey) -> Result<Zeroizing<[u8; 32]>> {
        AuditDecryption {
            auditor,
            message: self,
        }
        .decrypt()
    }

    pub fn to_message_data(&self, auditor_pk: &P256Pubkey) -> MessageData {
        let mut data = Vec::with_capacity(AUDITOR_MESSAGE_LEN);
        data.extend_from_slice(self.eph_pk.as_bytes());
        data.extend_from_slice(&self.ciphertext);
        MessageData {
            view_tag: auditor_view_tag(auditor_pk),
            data,
        }
    }

    pub fn parse(message: &MessageData, auditor_pk: &P256Pubkey) -> Result<Self> {
        if message.view_tag != auditor_view_tag(auditor_pk) {
            return Err(AuditEncryptionError::ViewTagMismatch);
        }
        let (eph_pk, ciphertext) = message
            .data
            .split_at_checked(COMPRESSED_P256_KEY_LEN)
            .filter(|(_, ciphertext)| ciphertext.len() == AUDIT_CIPHERTEXT_LEN)
            .ok_or(AuditEncryptionError::MessageLength(message.data.len()))?;
        let eph_pk: [u8; COMPRESSED_P256_KEY_LEN] = eph_pk
            .try_into()
            .map_err(|_| AuditEncryptionError::MessageLength(message.data.len()))?;
        let ciphertext: [u8; AUDIT_CIPHERTEXT_LEN] = ciphertext
            .try_into()
            .map_err(|_| AuditEncryptionError::MessageLength(message.data.len()))?;
        Ok(Self::new(P256Pubkey::from_bytes(eph_pk)?, ciphertext))
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
}

impl AuditorEncryption {
    pub fn new(tx_viewing_key: &ViewingKey, auditor_pk: &P256Pubkey) -> Result<Self> {
        let ephemeral = ViewingKey::new();
        let ephemeral_sk = ephemeral.secret_bytes();
        let eph_pk = ephemeral.pubkey();
        let dh = Zeroizing::new(ephemeral.ecdh(auditor_pk)?);
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
    pub eph_pk: P256Pubkey,
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
}

#[must_use]
struct NullifierKeySeal<'a> {
    nullifier_key: &'a NullifierKey,
    auditor_pk: &'a P256Pubkey,
    ephemeral: ViewingKey,
}

impl NullifierKeyEnvelope {
    pub fn new(nullifier_key: &NullifierKey, auditor_pk: &P256Pubkey) -> Result<Self> {
        NullifierKeySeal {
            nullifier_key,
            auditor_pk,
            ephemeral: ViewingKey::new(),
        }
        .seal()
    }
}

impl NullifierKeySeal<'_> {
    fn seal(self) -> Result<NullifierKeyEnvelope> {
        let ephemeral_sk = self.ephemeral.secret_bytes();
        let eph_pk = self.ephemeral.pubkey();
        let dh = Zeroizing::new(self.ephemeral.ecdh(self.auditor_pk)?);
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
    pub fn open(&self, auditor: &ViewingKey) -> Result<NullifierKey> {
        let dh = Zeroizing::new(auditor.ecdh(&self.eph_pk)?);
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
/// compressed key without its SEC1 prefix.
pub fn auditor_view_tag(pk: &P256Pubkey) -> [u8; 32] {
    pk.x()
}

type Result<T> = core::result::Result<T, AuditEncryptionError>;

/// Key-schedule info string; equals the Go `auditEncInfo`.
pub(crate) const AUDIT_ENC_INFO: &[u8; 10] = b"CRING/adt1";

/// Shared-secret domain separator, ASCII "CR_S" read as a big-endian u32; equals
/// the Go `DomSepCRShared`.
const DOM_SEP_CR_SHARED: u32 = 0x4352_5f53;

/// Mirrors `DeriveAuditSharedSecret`: binds the raw ECDH x-coordinate to both
/// public keys that produced it, so the key schedule input cannot be replayed
/// under a different key pair. Input order is pinned by `pack.go`.
#[must_use]
pub(crate) struct AuditSharedSecret<'a> {
    pub diffie_hellman_x: &'a [u8; 32],
    pub ephemeral_key: &'a P256Pubkey,
    pub auditor_key: &'a P256Pubkey,
}

#[must_use]
struct AuditDecryption<'a> {
    auditor: &'a ViewingKey,
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
        let dh = Zeroizing::new(self.auditor.ecdh(&ephemeral_key)?);
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
    use custom_ring_interface::{RegisterKeyPublicInput, RegisteredKey, HEAD_MAP_EMPTY_ROOT};
    use zolana_ring_head_map::{HeadMap, Registration};
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
        let secret = AuditSharedSecret {
            diffie_hellman_x: &diffie_hellman_x,
            ephemeral_key: &ephemeral_key,
            auditor_key: &auditor_key,
        }
        .derive()
        .expect("shared secret");
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
    const EPH_PK: &str = "0268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955c5d5";
    const CIPHERTEXT: &str = "f329a32e36717753ba70f955e2102b53fa3a1bfd7389ebda109030ea70602d40";
    const GENESIS: &str = "095939aeb6e0dc92dd4455bab6058c5c5f639b52a610932c22e517fc87d64a94";
    const REGISTRY_NEW_ROOT: &str =
        "01c9026ae3349a610ca0d39793c06c924e3ad8e2dcacb64c120c800185372618";
    const PUBLIC_INPUT_HASH: &str =
        "2f3163cf5ea64c46bcf1a4b97b0aabccc674aa6056daa42cb63007bb1d9534a9";

    #[test]
    fn the_sealed_key_and_its_registration_statement_match_the_pinned_vector() {
        let auditor = ViewingKey::from_bytes(&bytes(AUDITOR_SK)).expect("auditor");
        let nullifier_key = NullifierKey::from_secret(bytes(NULLIFIER_SECRET));
        let envelope = NullifierKeySeal {
            nullifier_key: &nullifier_key,
            auditor_pk: &auditor.pubkey(),
            ephemeral: ViewingKey::from_bytes(&bytes(EPHEMERAL_SK)).expect("ephemeral"),
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

        let genesis = RegisteredKey {
            nullifier_pk: &envelope.nullifier_pk,
            ciphertext: &envelope.sealed.ciphertext,
        }
        .commitment()
        .expect("genesis");
        assert_eq!(genesis, bytes(GENESIS));

        let member = Member::owner_tag(&MEMBER_TAG).expect("member");
        let inserted = HeadMap::new()
            .expect("empty registry")
            .register(Registration {
                member: *member.as_bytes(),
                genesis,
            })
            .expect("first registration");
        assert_eq!(inserted.old_root, HEAD_MAP_EMPTY_ROOT);
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
