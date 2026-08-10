//! `transact` (tag 0) instruction data (spec: squads `transact`).

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::{instruction::instruction_data::EncryptedUtxos, types::ProofBytes};

/// Per spent input: its nullifier, the tree holding it, and the root-cache
/// indices to verify it against (spec: `transact` `InputContext`). Shared by
/// `transact`, `full_withdrawal`, and `merge_transact`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct InputContext {
    /// Nullifier of the spent input. Inserted into its tree's nullifier tree.
    pub nullifier: [u8; 32],
    /// `tree_accounts` index of the tree holding the input.
    pub tree_index: u8,
    /// Root-cache index in that tree's UTXO tree.
    pub utxo_root_index: u16,
    /// Root-cache index in that tree's nullifier tree.
    pub nullifier_root_index: u16,
}

/// `transact` instruction data (spec: squads `transact`).
///
/// Mirrors the spec's `TransactIxData`: a withdrawal or transfer carrying both
/// the ring proof and the forwarded SPP proof. `public_amount` is `Some` for a
/// withdrawal, `None` for a transfer. `encrypted_utxos` is the ring-serialized
/// output ciphertext blob (`tx_viewing_pk` + sender + recipient ciphertexts),
/// checked by the ring proof and not parsed here.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactIxData {
    /// Compressed Groth16 ring proof with commitment.
    pub ring_proof: ProofBytes,
    /// Compressed Groth16 SPP proof. Forwarded to SPP.
    pub spp_proof: ProofBytes,
    /// `Some` for a withdrawal, `None` for a transfer.
    pub public_amount: Option<u64>,
    /// Canonical bump of the per-mint SPL interface PDA, required on an SPL
    /// withdrawal. SPP validates it against the settlement accounts, so the
    /// ring forwards it without checking.
    pub spl_interface_bump: u8,
    /// Public input shared with the SPP proof.
    pub private_tx_hash: [u8; 32],
    /// Unix timestamp after which the transaction is rejected.
    pub expiry: i64,
    /// Per-transaction encryption salt shared by every output ciphertext.
    /// Forwarded verbatim into the SPP `TransactIxData` the ring constructs
    /// for its CPI (SPP folds it into the logged event, not the ring proof).
    pub salt: [u8; 16],
    /// One `view_tag` per SPP output-ciphertext slot the ring forwards
    /// (sender bundle first, then one per recipient -- same order as
    /// `encrypted_utxos`). Folded into the forwarded SPP proof's
    /// `external_data_hash`, so it must match what the SPP-side proof
    /// committed to. It is opaque to the ring proof itself.
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub output_view_tags: Vec<[u8; 32]>,
    /// One hash per output UTXO. Length `M`.
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub output_utxo_hashes: Vec<[u8; 32]>,
    /// Per spent input. Length `N`.
    #[wincode(with = "containers::Vec<InputContext, FixIntLen<u8>>")]
    pub input_contexts: Vec<InputContext>,
    /// Output ciphertexts, ring serialization (spec `EncryptedUtxos`). Parsed
    /// inline with the rest of the instruction data and bound by the ring proof.
    /// SPP does not parse it.
    pub encrypted_utxos: EncryptedUtxos,
}

impl TransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
