use borsh::{BorshDeserialize, BorshSerialize};
use wincode::containers;
use wincode::len::FixIntLen;
use wincode::{SchemaRead, SchemaWrite};

/// Public deposit without a proof (spec: `proofless_shield`, tag 1).
///
/// The program commits the settled amount/asset into the UTXO hash and emits a
/// [`crate::event::GeneralEvent`] carrying a proofless output for wallet
/// discovery.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ProoflessShieldIxData {
    /// Indexing tag for the single output slot; chosen per the spec's View
    /// Tag Selection.
    pub view_tag: [u8; 32],
    /// Recipient-hiding owner commitment. Opaque to the program.
    pub owner_utxo_hash: [u8; 32],
    /// Fresh CSPRNG per deposit; the recipient re-derives `blinding` from it
    /// (spec: Blinding derivation).
    pub salt: [u8; 16],
    /// Selects the deposited asset: `PUBLIC_AMOUNT_DEPOSIT_SOL` or
    /// `PUBLIC_AMOUNT_DEPOSIT_SPL`. Proofless shields are deposit-only.
    pub public_amount_mode: u8,
    /// Deposited amount; the asset is decided by `public_amount_mode`.
    pub public_amount: Option<u64>,
    /// Program-defined data hash; requires `cpi_signer`.
    pub program_data_hash: Option<[u8; 32]>,
    /// Preimage of `program_data_hash`.
    #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
    pub program_data: Option<Vec<u8>>,
    /// Invoking program PDA (general program owner, seed `auth`); see
    /// `transact`. Policy-zone deposits use [`ZoneProoflessShieldIxData`].
    pub cpi_signer: Option<CpiSignerData>,
}

impl ProoflessShieldIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Policy-zone analog of [`ProoflessShieldIxData`] (spec:
/// `zone_proofless_shield`, tag 15). A zone program CPIs into SPP signing with
/// its `zone_auth` PDA (seed `zone_auth`); the created UTXO is owned by the
/// zone and additionally carries the zone's `policy_data`.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ZoneProoflessShieldIxData {
    /// As in [`ProoflessShieldIxData`].
    pub view_tag: [u8; 32],
    pub owner_utxo_hash: [u8; 32],
    pub salt: [u8; 16],
    /// As in [`ProoflessShieldIxData`]: selects the deposited asset
    /// (`PUBLIC_AMOUNT_DEPOSIT_SOL` or `PUBLIC_AMOUNT_DEPOSIT_SPL`).
    pub public_amount_mode: u8,
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

impl ZoneProoflessShieldIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}
/// Invoking-program signer for the proofless deposit paths (spec:
/// `proofless_shield` / `zone_proofless_shield` `cpi_signer`).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, SchemaRead, SchemaWrite,
)]
pub struct CpiSignerData {
    pub program_id: [u8; 32],
    pub bump: u8,
}
