use borsh::{BorshDeserialize, BorshSerialize};
use wincode::containers;
use wincode::len::FixIntLen;
use wincode::{SchemaRead, SchemaWrite};

/// Public deposit without a proof (spec: `deposit`, tag 1).
///
/// The program commits the settled amount/asset into the UTXO hash and emits a
/// [`crate::event::GeneralEvent`] carrying a proofless output for wallet
/// discovery.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct DepositIxData {
    /// Indexing tag for the single output slot; chosen per the spec's View
    /// Tag Selection.
    pub view_tag: [u8; 32],
    /// Recipient `owner_hash`; the program nests it with `blinding` into the
    /// UTXO's `owner_utxo_hash`.
    pub owner: [u8; 32],
    /// Fresh CSPRNG per deposit; sent in the clear so a third-party depositor
    /// needs no shared secret and the recipient spends it directly.
    pub blinding: [u8; 31],
    /// Deposited amount. The asset (native SOL vs SPL mint) is inferred from the
    /// settlement accounts the caller passes; deposits are deposit-only.
    pub public_amount: Option<u64>,
    /// Program-defined data hash; requires `cpi_signer`.
    pub program_data_hash: Option<[u8; 32]>,
    /// Preimage of `program_data_hash`.
    #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
    pub program_data: Option<Vec<u8>>,
    /// Invoking program PDA (general program owner, seed `auth`); see
    /// `transact`. Policy-zone deposits use [`ZoneDepositIxData`].
    pub cpi_signer: Option<CpiSignerData>,
}

impl DepositIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Policy-zone analog of [`DepositIxData`] (spec:
/// `zone_deposit`, tag 15). A zone program CPIs into SPP signing with
/// its `zone_auth` PDA (seed `zone_auth`); the created UTXO is owned by the
/// zone and additionally carries the zone's `policy_data`.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ZoneDepositIxData {
    /// As in [`DepositIxData`].
    pub view_tag: [u8; 32],
    pub owner: [u8; 32],
    pub blinding: [u8; 31],
    /// As in [`DepositIxData`]: the asset is inferred from the
    /// settlement accounts the zone forwards.
    pub public_amount: Option<u64>,
    /// Calling zone program; `zone_auth` is re-derived from it (seed `zone_auth`).
    pub cpi_signer: CpiSignerData,
    /// Zone-defined policy data hash.
    pub policy_data_hash: Option<[u8; 32]>,
    /// Preimage of `policy_data_hash`.
    #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
    pub zone_data: Option<Vec<u8>>,
    /// Program-defined data hash.
    pub program_data_hash: Option<[u8; 32]>,
    /// Preimage of `program_data_hash`.
    #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
    pub program_data: Option<Vec<u8>>,
}

impl ZoneDepositIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}
/// Invoking-program signer for the proofless deposit paths (spec:
/// `deposit` / `zone_deposit` `cpi_signer`).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, SchemaRead, SchemaWrite,
)]
pub struct CpiSignerData {
    pub program_id: [u8; 32],
    pub bump: u8,
}
