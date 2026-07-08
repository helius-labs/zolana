//! Per-user P256 owner keypairs for the Squads zone P256 (keypair-rail) lifecycle
//! suite, plus the backend auditor key.
//!
//! Unlike the earlier genesis-seeded design, no `ViewingKeyAccount` is written at
//! genesis: every user's VKA is created at runtime through the backend's
//! `requestCreateViewingKeyAccount`, which mints a FRESH shared viewing key and
//! nullifier secret held only by the backend (recoverable via the auditor key). So
//! the only per-user secret the client keeps is the deterministic P256 owner
//! (signing) key -- the key the P256 keypair rail signs `sha256(private_tx_hash)`
//! with. Everything else (balances, the deposit view tag, the recipient's public
//! fields) is read from on-chain VKA data or recovered by the backend auditor.
//!
//! A user's VKA lives at the canonical PDA
//! `find_program_address([VIEWING_KEY_ACCOUNT_PDA_SEED, owner_pk_field], squads)`,
//! where `owner_pk_field = hash_field(owner_pubkey)` is the on-chain `owner`.

use p256::SecretKey;
use solana_pubkey::Pubkey;
use zolana_keypair::{P256Pubkey, PublicKey, SigningKey};
use zolana_squads_interface::{SQUADS_ZONE_PROGRAM_ID, VIEWING_KEY_ACCOUNT_PDA_SEED};

/// A field element derived from `name` and `domain`: SHA256 with the top byte
/// cleared so it is `< 2^248 < BN254 modulus < P-256 order` (a valid Poseidon
/// input and P-256 scalar).
fn field_element(name: &str, domain: &[u8]) -> [u8; 32] {
    let mut input = domain.to_vec();
    input.extend_from_slice(name.as_bytes());
    let mut out = zolana_keypair::hash::sha256_be(&input);
    out[0] = 0;
    out
}

fn squads_program_id() -> Pubkey {
    Pubkey::new_from_array(SQUADS_ZONE_PROGRAM_ID)
}

/// The deterministic P256 owner (signing) identity for `name`. The client holds
/// only this key; the viewing / nullifier secrets are backend-random.
#[derive(Clone)]
pub(crate) struct OwnerKeypair {
    /// The raw P256 owner scalar (32 bytes).
    pub(crate) owner_secret: [u8; 32],
}

impl OwnerKeypair {
    fn p256_secret(&self) -> SecretKey {
        SecretKey::from_slice(&self.owner_secret).expect("valid p256 owner scalar")
    }

    /// The compressed 33-byte P256 owner public key the backend's P256 rail needs
    /// (`RequestTransactRequest::sender_owner_pubkey`).
    pub(crate) fn owner_pubkey_bytes(&self) -> [u8; 33] {
        *P256Pubkey::from_p256(&self.p256_secret().public_key()).as_bytes()
    }

    /// The on-chain `owner` field element (`owner_pk_field = hash_field(pubkey)`),
    /// used as the VKA `owner`, the VKA PDA seed, and a transfer recipient's output
    /// owner.
    pub(crate) fn owner_field(&self) -> [u8; 32] {
        let pubkey = P256Pubkey::from_p256(&self.p256_secret().public_key());
        PublicKey::from_p256(&pubkey)
            .owner_pk_field()
            .expect("owner pk field")
    }

    /// A [`SigningKey`] over the P256 owner scalar, for signing
    /// `sha256(private_tx_hash)` on the keypair rail.
    pub(crate) fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.owner_secret).expect("valid p256 owner scalar")
    }

    /// The canonical VKA PDA address for this owner.
    pub(crate) fn viewing_key_account(&self) -> Pubkey {
        Pubkey::find_program_address(
            &[VIEWING_KEY_ACCOUNT_PDA_SEED, &self.owner_field()],
            &squads_program_id(),
        )
        .0
    }
}

/// The deterministic P256 owner keypair for `name`.
pub(crate) fn owner_keypair(name: &str) -> OwnerKeypair {
    OwnerKeypair {
        owner_secret: field_element(name, b"squads-vka-owner-sk"),
    }
}

/// The canonical VKA PDA address for `name` (shorthand for
/// `owner_keypair(name).viewing_key_account()`).
pub(crate) fn viewing_key_account_address(name: &str) -> Pubkey {
    owner_keypair(name).viewing_key_account()
}

/// The backend's deterministic auditor P256 secret. It is also the auditor key
/// configured in `zone_config`, so the shared viewing key each account publishes
/// (encrypted to this key) is recoverable by the backend.
pub(crate) fn auditor_secret() -> SecretKey {
    SecretKey::from_slice(&field_element("auditor", b"squads-zone-auditor-sk"))
        .expect("valid p256 auditor scalar")
}

/// The auditor's compressed P256 public key.
pub(crate) fn auditor_pubkey() -> P256Pubkey {
    P256Pubkey::from_p256(&auditor_secret().public_key())
}
