//! `execute_proposal` (tag 13) instruction data (spec: squads
//! `execute_proposal`).

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::{
    instruction::instruction_data::{transact::InputContext, EncryptedUtxos},
    types::ProofBytes,
};

/// `execute_proposal` instruction data (spec: squads `execute_proposal`).
///
/// Settles an approved proposal. Per the spec this matches `transact`'s
/// `TransactIxData` without `expiry`. The proposal supplies the private proposal
/// core, recipient/destination, and asset. Execution validates the public fields
/// against the actual accounts and derives the ring proof's v2 commitment.
/// `public_amount` is `Some` for a withdrawal, `None` for a transfer.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ExecuteProposalIxData {
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
    /// Per-transaction encryption salt shared by every output ciphertext.
    /// Forwarded verbatim into the SPP `TransactIxData` the ring constructs
    /// for its CPI.
    pub salt: [u8; 16],
    /// One `view_tag` per SPP output-ciphertext slot the ring forwards
    /// (sender bundle first, then one per recipient -- same order as
    /// `encrypted_utxos`).
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub output_view_tags: Vec<[u8; 32]>,
    /// One hash per output UTXO. Length `M`.
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub output_utxo_hashes: Vec<[u8; 32]>,
    /// Per spent input. Length `N`.
    #[wincode(with = "containers::Vec<InputContext, FixIntLen<u8>>")]
    pub input_contexts: Vec<InputContext>,
    /// Output ciphertexts, ring serialization (spec `EncryptedUtxos`). Parsed
    /// inline and bound by the ring proof.
    pub encrypted_utxos: EncryptedUtxos,
}

impl ExecuteProposalIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
