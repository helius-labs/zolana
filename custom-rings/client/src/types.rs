//! What an audit returns, the decrypted values themselves.

use solana_address::Address;
use solana_signature::Signature;
use std::fmt;
use zeroize::Zeroizing;
use zolana_client::ProofInputUtxo;
use zolana_keypair::P256Pubkey;
use zolana_transaction::Data;

/// One opened output slot, its asset id resolved to the mint.
#[derive(PartialEq, Eq)]
pub struct AuditedOutput {
    /// The slot index the ciphertext is bound to.
    pub slot_index: u32,
    pub recipient_viewing_pk: P256Pubkey,
    /// Bound by the circuit to the owner, an x-coordinate for a P256 owner.
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
    pub tx_viewing_pk: P256Pubkey,
    pub outputs: Vec<AuditedOutput>,
    pub output_openings: Vec<ProofInputUtxo>,
    /// Dummies, foreign schemes and slots sealed to another key, every transfer pads with dummies.
    pub undecryptable_slots: Vec<u32>,
}
