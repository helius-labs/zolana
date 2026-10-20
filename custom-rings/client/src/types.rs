//! What an audit returns, the decrypted values themselves.

#[cfg(feature = "rpc")]
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signature::Signature;
use std::fmt;
use zeroize::Zeroizing;
use zolana_client::ProofInputUtxo;
use zolana_keypair::X25519Pubkey;
use zolana_transaction::{AssetRegistry, Data, OutputContext};

use crate::{opening::NoteOpening, AnonymousDisclosure, AuditError};

/// One opened output slot, its asset id resolved to the mint.
#[derive(PartialEq, Eq)]
pub struct AuditedOutput {
    /// The slot index the ciphertext is bound to.
    pub slot_index: u32,
    pub recipient_viewing_pk: X25519Pubkey,
    /// Published recipient tag, or the disclosed owner identity in anonymous mode.
    /// The authoritative ownership commitment is in `output_openings`.
    pub owner_tag: [u8; 32],
    pub asset: Address,
    pub amount: u64,
    pub blinding: Zeroizing<[u8; 32]>,
    pub ring_program_id: Option<Address>,
    pub data: Data,
}

impl fmt::Debug for AuditedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditedOutput")
            .field("slot_index", &self.slot_index)
            .field("recipient_viewing_pk", &self.recipient_viewing_pk)
            .field("owner_tag", &self.owner_tag)
            .field("asset", &self.asset)
            .field("amount", &self.amount)
            .field("blinding", &"redacted")
            .field("ring_program_id", &self.ring_program_id)
            .field("data", &self.data)
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuditedTransaction {
    pub tx_signature: Signature,
    pub slot: u64,
    /// Checked against the key the auditor message carries.
    pub tx_viewing_pk: X25519Pubkey,
    /// Optional recipient metadata. Dedicated openings remain authoritative when delivery fails.
    pub outputs: Vec<AuditedOutput>,
    /// Published contexts aligned with the verified openings, including dummy slots.
    pub output_contexts: Vec<OutputContext>,
    pub output_openings: Vec<ProofInputUtxo>,
    /// The proven hidden sender, spent notes and recipients of an anonymous ring.
    pub anonymous: Option<AnonymousDisclosure>,
    /// Slots without an [`AuditedOutput`], one error per slot.
    pub payload_errors: Vec<OutputPayloadError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputPayloadError {
    pub slot_index: u32,
    pub kind: OutputPayloadErrorKind,
}

/// Why a slot gave no [`AuditedOutput`], the verified openings and the anonymous trace stay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "rpc", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rpc", serde(rename_all = "camelCase"))]
pub enum OutputPayloadErrorKind {
    /// No encrypted body of a known scheme and length.
    Frame,
    /// The body does not open to a well-formed plaintext.
    Decrypt,
    /// The opened note does not hash to the published commitment.
    Commitment,
    /// The note's mint is not in the asset registry.
    Asset,
    /// The opened `pair_u` names no contributory X25519 key, the output is kept.
    PairHint,
}

impl AuditedTransaction {
    /// Asset refresh follows proved mint fields, never unproved recipient asset IDs.
    pub fn has_unknown_assets(&self, assets: &AssetRegistry) -> Result<bool, AuditError> {
        for opening in self.output_openings.iter().filter_map(NoteOpening::new) {
            if opening.mint(assets)?.is_none() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
