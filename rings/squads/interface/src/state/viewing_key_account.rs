//! Per-owner viewing key account: the shared viewing key, the ciphertexts that
//! let recovery keys and the auditor recover the shared private key, and the
//! encrypted nullifier secret.

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_hasher::{Hasher, HasherError, Poseidon};

use super::discriminator;
use crate::{
    constants::{OWNER_KIND_KEYPAIR, OWNER_KIND_SMART_ACCOUNT},
    error::SquadsZoneError,
    types::{Address, EncryptedNullifierSecret, P256Pubkey, SharedKeyCiphertext},
    VIEWING_KEY_ACCOUNT_PDA_SEED,
};

/// The settlement rail a viewing key account's owner spends through. The wire
/// form is a byte, so every consumer parses it once and branches on the enum. An
/// unrecognized byte has no variant, which keeps a rail from falling open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerKind {
    /// P256 keypair owner. The owner's signature inside the SPP proof
    /// authorizes the spend.
    Keypair,
    /// Squads vault owner with no signing key. Spends are signatureless and the
    /// vault authorizes them as a signer account.
    SmartAccount,
}

impl TryFrom<u8> for OwnerKind {
    type Error = SquadsZoneError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            OWNER_KIND_KEYPAIR => Ok(Self::Keypair),
            OWNER_KIND_SMART_ACCOUNT => Ok(Self::SmartAccount),
            _ => Err(SquadsZoneError::InvalidOwnerKind),
        }
    }
}

impl From<OwnerKind> for u8 {
    fn from(kind: OwnerKind) -> Self {
        match kind {
            OwnerKind::Keypair => OWNER_KIND_KEYPAIR,
            OwnerKind::SmartAccount => OWNER_KIND_SMART_ACCOUNT,
        }
    }
}

/// Per-owner viewing key record, derived at `[b"viewing_key_account", owner]`.
/// Variable-length (recovery/auditor key vectors), so it (de)serializes with
/// wincode rather than a zero-copy `bytemuck` cast.
#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct ViewingKeyAccount {
    pub discriminator: u8,
    pub owner: Address,
    pub state: u8,
    pub encryption_scheme: u8,
    /// `OWNER_KIND_KEYPAIR` (P256 rail) or `OWNER_KIND_SMART_ACCOUNT` (signatureless
    /// zone-authority rail). Selects the SPP settlement rail for spends of this
    /// account's UTXOs. It is not bound by any proof.
    pub owner_kind: u8,
    pub shared_viewing_key: P256Pubkey,
    pub shared_viewing_key_commitment: [u8; 32],
    pub key_nonce: u64,
    pub nullifier_pubkey: [u8; 32],
    pub key_ciphertext_ephemeral: P256Pubkey,
    pub encrypted_nullifier_secret: EncryptedNullifierSecret,
    #[wincode(with = "containers::Vec<[u8; 33], FixIntLen<u8>>")]
    pub recovery_keys: Vec<P256Pubkey>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub recovery_key_ciphertexts: Vec<SharedKeyCiphertext>,
    #[wincode(with = "containers::Vec<[u8; 33], FixIntLen<u8>>")]
    pub auditor_keys: Vec<P256Pubkey>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub auditor_key_ciphertexts: Vec<SharedKeyCiphertext>,
}

impl ViewingKeyAccount {
    pub const DISCRIMINATOR: u8 = discriminator::VIEWING_KEY_ACCOUNT;
    pub const SEED: &'static [u8] = VIEWING_KEY_ACCOUNT_PDA_SEED;

    /// Parse the stored `owner_kind` byte. The loader calls this so a later
    /// branch can never see a byte outside the known set.
    pub fn kind(&self) -> Result<OwnerKind, SquadsZoneError> {
        OwnerKind::try_from(self.owner_kind)
    }

    /// The index tag every output this account can decrypt carries: the X
    /// coordinate of its SEC1-compressed shared viewing key.
    pub fn view_tag(&self) -> [u8; 32] {
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&self.shared_viewing_key[1..33]);
        tag
    }

    /// Allocation size for `recovery` recovery entries and `auditor` auditor
    /// entries. Each entry is a 33-byte key plus a 32-byte ciphertext (65 bytes).
    /// The fixed part (209) covers the scalar fields (including the 1-byte
    /// `owner_kind`) and the four 1-byte wincode length prefixes.
    pub fn account_size(recovery: usize, auditor: usize) -> usize {
        209 + 65 * (recovery + auditor)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }

    /// Commit to the account fields that a key-rotation proof must precede.
    /// The nonce makes a proof for one rotation unusable after that rotation is
    /// applied, even if every other policy field is unchanged.
    pub fn key_rotation_commitment(&self) -> Result<[u8; 32], HasherError> {
        const DOMAIN: &[u8; 26] = b"ZOLANA/SQUADS/VKA_STATE/V1";

        let domain = right_aligned(DOMAIN);
        let owner_bytes = self.owner.to_bytes();
        let owner = split_32(&owner_bytes);
        let shared_commitment = split_32(&self.shared_viewing_key_commitment);
        let nullifier_pubkey = split_32(&self.nullifier_pubkey);

        // These fixed positions make the scalar policy fields and nonce one
        // injective value below 2^88, safely inside the BN254 scalar field.
        let mut policy = [0u8; 32];
        policy[21] = self.state;
        policy[22] = self.owner_kind;
        policy[23] = self.encryption_scheme;
        policy[24..].copy_from_slice(&self.key_nonce.to_be_bytes());

        Poseidon::hashv(&[
            &domain,
            &owner[0],
            &owner[1],
            &shared_commitment[0],
            &shared_commitment[1],
            &nullifier_pubkey[0],
            &nullifier_pubkey[1],
            &policy,
        ])
    }
}

/// Encode `N` bytes as a big-endian BN254 scalar. `N <= 31` keeps the value
/// below the field modulus and is checked at compile time.
fn right_aligned<const N: usize>(bytes: &[u8; N]) -> [u8; 32] {
    const { assert!(N <= 31, "a domain tag must fit a BN254 scalar") };
    let mut field = [0u8; 32];
    field[32 - N..].copy_from_slice(bytes);
    field
}

/// Preserve all 256 bits as two ordered 128-bit BN254 scalars.
fn split_32(bytes: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut prefix = [0u8; 32];
    prefix[16..].copy_from_slice(&bytes[..16]);
    let mut suffix = [0u8; 32];
    suffix[16..].copy_from_slice(&bytes[16..]);
    [prefix, suffix]
}
