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
//! - [`SigningKey`] — P-256 spend-authorizing key; signs `private_tx_hash` to
//!   authorize a spend, which the SPP proof checks.
//! - [`NullifierKey`] — derives `nullifier_pk` and the per-UTXO nullifiers that
//!   prevent double-spends.
//! - [`ViewingKey`] — P-256 key for HPKE-style UTXO encryption and labelled
//!   HKDF derivation of the view-tag secrets a wallet scans for. Secrets expand
//!   from an ECDH-derived `view_root`, so the key can stay in an HSM.
//!
//! # Addresses
//! - [`ShieldedKeypair`] — bundles the three keys and builds the
//!   [`ShieldedAddress`] and compressed [`CompressedShieldedAddress`].
//! - [`PublicKey`], [`P256Pubkey`], [`SignatureType`] — scheme-tagged public
//!   keys: P-256 for shielded owners, Ed25519 for Solana-only owners.
//!
//! # Hashing
//! - [`hash`] — Poseidon helpers plus [`PublicKey::hash`] and
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
pub(crate) mod encryption;
pub mod error;
pub mod hash;
pub mod merge;
pub mod nullifier_key;
pub mod pubkey;
pub mod shielded;
pub mod signing_key;
pub(crate) mod slip10;
pub mod traits;
pub mod viewing_key;

pub use error::KeypairError;
pub use nullifier_key::NullifierKey;
pub use pubkey::{P256Pubkey, PublicKey, SignatureType};
pub use shielded::{CompressedShieldedAddress, ShieldedAddress, ShieldedKeypair};
pub use signing_key::SigningKey;
pub use traits::{ShieldedKeypairTrait, ViewingKeyTrait};
pub use viewing_key::{random_blinding, random_salt, ViewingKey};

pub type Signature = [u8; 64];

pub type ECDSASignature = [u8; 64];
