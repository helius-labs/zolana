//! Compressed accounts: program state kept as shielded-pool UTXOs.
//!
//! A compressed account is a UTXO a program PDA owns ([`PdaOwner`]) whose data
//! hash commits to the program's plaintext state ([`DataUtxo`]). The PDA's
//! nullifier secret is 0, so the program recomputes the UTXO hash and the
//! nullifier from the state instead of trusting instruction data.
//!
//! - **Create** spends an address slot, which reserves the account's
//!   [`NewAddress`] in the address tree, and outputs the first state.
//! - **Update** spends the current state and outputs the next.
//! - **Read** proves the current state without spending it: the program
//!   verifies its own proof of state-tree inclusion and nullifier-tree
//!   non-inclusion under roots [`ReadRoots`] loads, and checks that the
//!   nullifier PDA does not exist.
//!
//! Create and update are both a [`CompressedAccount`]: one input and one new
//! state. [`SppTransactCpi`] puts the accounts an instruction writes into one
//! shielded-pool transaction and invokes it, signed by the owning PDAs. It
//! derives everything but the proof on chain: every blinding, the output UTXO
//! hashes, the external data hash and the private transaction hash. It hands
//! each new UTXO's blinding to the program, which may store it in the state.
//!
//! Rules a program must keep:
//! - Only a UTXO with a non-zero data hash is program state. Anyone can send a
//!   PDA a UTXO with a zero data hash; a non-zero one needs the owner's
//!   signature in the transact circuit, and only the program signs for its PDA.
//! - A program that signs with a state-owning PDA builds every output that PDA
//!   owns itself. It never signs transact data a client built.
//! - The data hash commits to a type tag and to the account's address.
//! - The address is state. Only create derives it; update and read take it
//!   from the state, and the state's UTXO may move between trees.

mod account;
mod address;
mod cpi;
mod error;
mod owner;
mod proof;
mod read;
mod utxo;

pub use account::{CompressedAccount, CompressedAccountData, CompressedAccountMeta};
pub use address::{AddressSeed, NewAddress};
pub use cpi::{SppTransactCpi, ACCOUNT_BLINDING_SEED};
pub use error::CompressedAccountError;
pub use owner::{PdaOwner, ZERO_NULLIFIER_PUBKEY};
pub use proof::CompressedProof;
pub use read::{load_tree_id, ReadRoots};
pub use utxo::{DataUtxo, UtxoKey, NO_RING_HASH};
