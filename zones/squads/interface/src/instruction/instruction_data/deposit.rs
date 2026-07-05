//! `deposit` (tag 1) instruction data (spec: squads `deposit`).

use wincode::{SchemaRead, SchemaWrite};

/// `deposit` instruction data (spec: squads `deposit`). A fully public deposit
/// into a new zone-owned UTXO; amount, asset, and recipient are public.
///
/// The recipient `owner` is derived on-chain from the recipient viewing key
/// account, and the asset (native SOL vs SPL mint) is inferred from the
/// settlement accounts the caller passes, so neither is carried here. The
/// deposited UTXO carries no zone or application data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct DepositIxData {
    /// Indexing tag for the single output slot, computed by the caller from the
    /// recipient's viewing key so the recipient's wallet discovers the deposit.
    pub view_tag: [u8; 32],
    /// Fresh CSPRNG value per deposit, sent in the clear so a third-party
    /// depositor needs no shared secret with the recipient.
    pub blinding: [u8; 31],
    /// Public deposit amount moved into the shielded pool.
    pub amount: u64,
}

impl DepositIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
