//! `deposit` (tag 1) instruction data (spec: squads `deposit`).

use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::instruction::{DepositAssetKind, EncryptedRingDepositData};

/// `deposit` instruction data (spec: squads `deposit`). A fully public deposit
/// into a new zone-owned UTXO. The amount, asset, and recipient are public.
///
/// The recipient `owner` is derived on-chain from the recipient viewing key
/// account, so it is not carried here. The deposited UTXO carries no zone or
/// application data.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct DepositIxData {
    /// Indexing tag for the single output slot, computed by the caller from the
    /// recipient's viewing key so the recipient's wallet discovers the deposit.
    pub view_tag: [u8; 32],
    /// Must agree with the settlement accounts the caller forwards, which SPP
    /// checks against this.
    pub asset: DepositAssetKind,
    /// Public deposit amount moved into the shielded pool.
    pub amount: u64,
    /// Fresh CSPRNG value per deposit, sent in the clear so a third-party
    /// depositor needs no shared secret with the recipient. The program nests it
    /// with the viewing-key-derived owner into the `owner_utxo_hash` it forwards
    /// to SPP, which is what binds the deposit to that recipient.
    pub blinding: [u8; 32],
    /// Passed through to SPP for recipient discovery. SPP and the zone both
    /// treat it as opaque, so it commits to nothing the program checks.
    pub encrypted: EncryptedRingDepositData,
}

impl DepositIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
