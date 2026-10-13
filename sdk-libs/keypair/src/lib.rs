//! Client keypairs for the TSPP shielded protocol. They sign spends, derive
//! nullifiers, encrypt UTXOs, derive view tags, and hash shielded addresses.
//!
//! A shielded address is the triple `(signing_pk, nullifier_pk, viewing_pk)`,
//! compressed to an `owner_hash`:
//!
//! ```text
//! owner_hash = Poseidon(pk_field(signing_pk), nullifier_pk)
//! ```
//!
//! # Keys
//! - [`SigningKey`] — Ed25519 spend-authorizing key (a Solana keypair); its
//!   signature over the transaction authorizes a spend.
//! - [`NullifierKey`] — derives `nullifier_pk` and the per-UTXO nullifiers that
//!   prevent double-spends.
//! - [`ViewingKey`] — P-256 key for HPKE-style UTXO encryption and labelled
//!   HKDF derivation of the view-tag secrets a wallet scans for. Secrets expand
//!   from an ECDH-derived `view_root`, so the key can stay in an HSM.
//!
//! # Addresses
//! - [`ShieldedKeypair`] — bundles the three keys and builds the
//!   [`ShieldedAddress`] and compressed [`CompressedShieldedAddress`].
//! - [`PublicKey`], [`Curve`] — scheme-tagged owner keys: Ed25519 signers
//!   and program-derived addresses. [`P256Pubkey`] is the viewing-key point.
//!
//! # Hashing
//! - [`hash`] — Poseidon helpers plus [`PublicKey::owner_proof_input_hash`] and
//!   [`hash::owner_hash`], which compress an address into its `owner_hash`.
//!
//! # Wallet flow
//! ```text
//!  Signing Key ─┐
//!               ├─ owner_hash = Poseidon(pk_field(signing_pk), nullifier_pk)
//!  Nullifier ───┘   └─ nullifier(utxo) spends a UTXO, inserted into the
//!  Key                  nullifier tree
//!
//!  Viewing Key ── encrypt_slot ──→ ciphertexts + view tags
//!             └── decrypt_utxo  ←── scan view tags at the indexer
//! ```

pub mod constants;
pub mod derivation;
pub(crate) mod encryption;
pub mod error;
pub mod hash;
pub mod merge_envelope;
pub mod nullifier_key;
pub mod pda;
pub mod pubkey;
pub mod shielded;
pub mod signing_key;
pub mod traits;
pub mod viewing_key;

pub use encryption::symmetric_apply;
pub use error::KeypairError;
pub use merge_envelope::{
    DecryptedMergeEnvelope, EncryptedMergeEnvelope, MergeEnvelopeDecryption,
    MergeEnvelopeEncryption, MERGE_ENVELOPE_CIPHERTEXT_LEN,
};
pub use nullifier_key::NullifierKey;
pub use pda::ShieldedPda;
pub use pubkey::{Curve, P256Pubkey, PublicKey};
pub use shielded::{
    CompressedShieldedAddress, ShieldedAddress, ShieldedKeypair, SHIELDED_ADDRESS_LEN,
};
pub use signing_key::SigningKey;
pub use traits::{ShieldedKeypairTrait, ViewingKeyTrait};
pub use viewing_key::{random_blinding, random_salt, ViewingKey};

pub type Signature = [u8; 64];
