//! `merge_transact` (tag 2) instruction data (spec: squads `merge_transact`).

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::{instruction::instruction_data::transact::InputContext, types::ProofBytes};

/// `merge_transact` instruction data (spec: squads `merge_transact`).
///
/// A merge authority consolidates one owner's input UTXOs into a single output
/// UTXO of the same owner and total value. Carries the single forwarded SPP
/// merge proof, which also proves the verifiable encryption of the
/// consolidated output. The consolidated output ciphertext is zone-serialized
/// and checked by that proof, not parsed.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeTransactIxData {
    /// Compressed Groth16 SPP merge proof; forwarded to SPP. Also covers the
    /// verifiable encryption of the consolidated output.
    pub spp_proof: ProofBytes,
    /// Unix timestamp after which the transaction is rejected; forwarded
    /// verbatim into the SPP `MergeTransactIxData` the zone constructs for its
    /// CPI (SPP's `merge_zone` enforces it).
    pub expiry_unix_ts: u64,
    /// Single-use tag indexing the merged output for SPP's `merge_zone`
    /// (spec: SPP `merge_zone` `merge_view_tag`); forwarded verbatim.
    pub merge_view_tag: [u8; 32],
    /// Public input shared with the SPP proof.
    pub private_tx_hash: [u8; 32],
    /// Hash of the consolidated output UTXO.
    pub output_utxo_hash: [u8; 32],
    /// Per spent input. Length `N`.
    #[wincode(with = "containers::Vec<InputContext, FixIntLen<u8>>")]
    pub input_contexts: Vec<InputContext>,
    /// Consolidated output encrypted to the owner's shared viewing key; checked
    /// by the SPP merge proof.
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub encrypted_utxo: Vec<u8>,
}

impl MergeTransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
