//! Squads zone SDK: shared-viewing-key crypto, zone UTXO/ciphertext
//! (de)serialization, proposal building, and prover glue.
//!
//! [`crypto`] holds the pure-crypto gadgets (P-256 ECDH, the Poseidon key
//! schedule, AES-256-CTR). It is always available and has no network/proof
//! dependency.

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
