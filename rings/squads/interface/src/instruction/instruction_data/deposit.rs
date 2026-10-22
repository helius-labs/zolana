//! `deposit` (tag 1) instruction data (spec: squads `deposit`).

use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::instruction::instruction_data::deposit::DepositAssetKind;

/// `deposit` instruction data (spec: squads `deposit`). A fully public deposit
/// into a new ring-owned UTXO; amount, asset, and recipient are public.
///
/// The recipient owner is read on-chain from the recipient viewing key account.
/// The ring forwards one SPP `ring_deposit` entry whose `owner_utxo_hash` it
/// computes from that owner and `blinding`, and publishes `blinding` in the
/// entry's deposit record so the recipient reconstructs the UTXO.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct DepositIxData {
    /// Indexing tag for the single output slot, computed by the caller from the
    /// recipient's viewing key so the recipient's wallet discovers the deposit.
    pub view_tag: [u8; 32],
    /// Fresh CSPRNG field element per deposit, sent in the clear so a
    /// third-party depositor needs no shared secret with the recipient.
    pub blinding: [u8; 32],
    /// Public deposit amount moved into the shielded pool.
    pub amount: u64,
    /// SOL or SPL settlement group of the forwarded `ring_deposit`.
    pub asset: DepositAssetKind,
}

impl DepositIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
