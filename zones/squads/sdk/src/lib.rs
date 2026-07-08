//! Squads zone SDK: shared-viewing-key crypto, zone UTXO/ciphertext
//! (de)serialization, proposal building, and prover glue.
//!
//! Layering:
//! - [`crypto`] holds the pure-crypto gadgets (P-256 ECDH, the Poseidon key
//!   schedule, AES-256-CTR). It is always available and has no network/proof
//!   dependency.
//! - The `encryption` feature (default) adds the wallet-facing construction and
//!   decryption modules: [`proposal`], [`encrypted_utxo`], [`viewing_key_account`],
//!   and [`intent`].
//! - The `prover` feature adds the witness builders and prover-server glue.

pub mod crypto;

#[cfg(feature = "encryption")]
pub mod encrypted_utxo;
#[cfg(feature = "encryption")]
pub mod intent;
#[cfg(feature = "encryption")]
pub mod proposal;
#[cfg(feature = "encryption")]
pub mod viewing_key_account;

#[cfg(feature = "prover")]
pub mod prover;
