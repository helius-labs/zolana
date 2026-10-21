//! Compressed accounts: program state kept as shielded-pool UTXOs.
//!
//! [`UniqueDataUtxo`] keeps application state under an immutable reserved address.
//! Its data hash is `Poseidon(UNIQ, address, state.hash())`, matching the circuit
//! type. State implements [`crate::hasher::DataHasher`] and Borsh serialization;
//! the state hash must include a type tag. Address and UTXO blinding are metadata.
//!
//! - **Create** spends an address slot and publishes the first state.
//! - **Update** spends the current UTXO and publishes its replacement at the same address.
//! - **Read** verifies state-tree inclusion and nullifier-tree non-inclusion
//!   under [`ReadRoots`], and checks that the nullifier PDA does not exist.
//!
//! [`SppTransactCpi`] derives the output blindings, UTXO hashes and transaction
//! hashes on chain, then invokes the pool signed by the owning [`PdaOwner`]s.
//! Plaintext output data is `address || Borsh(state)`. Readers recover each
//! output's blinding from the transaction's first nullifier, output index and
//! [`ACCOUNT_BLINDING_SEED`]. The PDA nullifier secret is zero, so the program
//! reconstructs hashes and nullifiers from state and metadata.
//!
//! Rules a program must keep:
//! - Only a UTXO with a non-zero data hash is program state. Anyone can send a
//!   PDA a UTXO with a zero data hash; a non-zero one needs the owner's
//!   signature in the transact circuit, and only the program signs for its PDA.
//! - A program that signs with a state-owning PDA builds every output that PDA
//!   owns itself. It never signs transact data a client built.
//! - The state hash commits to its type tag. The SDK binds it to the address.
//! - Only create derives the address; updates preserve it as metadata, even
//!   when the UTXO moves to another tree.

mod address;
mod cpi;
mod error;
mod owner;
mod read;
mod unique;
mod utxo;

pub use address::{AddressSeed, NewAddress};
pub use cpi::{SppTransactCpi, ACCOUNT_BLINDING_SEED};
pub use error::CompressedAccountError;
pub use owner::PdaOwner;
pub use read::{load_tree_id, ReadRoots};
pub use unique::{UniqueDataUtxo, UtxoMeta};
pub use utxo::UtxoKey;
