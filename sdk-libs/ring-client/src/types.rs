//! What an audit returns. These types are the deliverable of the crate: the
//! end-to-end test asserts on them, so they carry the decrypted values
//! themselves, not a "decryption succeeded" flag.

use solana_address::Address;
use solana_signature::Signature;
use std::fmt;
use zeroize::Zeroizing;
use zolana_keypair::P256Pubkey;

#[derive(PartialEq, Eq)]
/// One output slot the auditor opened with the recovered transaction viewing
/// key. Mirrors [`zolana_transaction::serialization::confidential::ConfidentialOutputPlaintext`]
/// with the asset id already resolved to its mint.
pub struct AuditedOutput {
    /// Position of the slot in `ShieldedTransaction::output_slots`, which is also
    /// the slot index the ciphertext is bound to.
    pub slot_index: u32,
    pub recipient_viewing_pk: P256Pubkey,
    /// The slot's view tag, bound by the circuit to the output owner. The Solana
    /// address of an Ed25519 or PDA owner, an x-coordinate for P256.
    pub owner_tag: [u8; 32],
    pub asset: Address,
    pub amount: u64,
    pub blinding: Zeroizing<[u8; 32]>,
    /// Set when the output is owned by a ring program rather than a plain user.
    pub ring_program_id: Option<Address>,
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
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
/// One transaction whose per-transaction viewing key the auditor recovered.
pub struct AuditedTransaction {
    pub tx_signature: Signature,
    pub slot: u64,
    /// The published key, already checked against the key recovered from the
    /// auditor message.
    pub tx_viewing_pk: P256Pubkey,
    pub outputs: Vec<AuditedOutput>,
    /// Positions of output slots this audit could not open as a confidential
    /// plaintext: dummy slots (random bytes by construction), slots published
    /// under another encryption scheme, and slots encrypted to a different
    /// transaction key. They are reported rather than fatal because every real
    /// transfer pads its output list with dummies.
    pub undecryptable_slots: Vec<u32>,
}
