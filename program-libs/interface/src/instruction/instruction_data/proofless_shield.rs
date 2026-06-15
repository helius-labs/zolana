use wincode::containers;
use wincode::len::FixIntLen;
use wincode::{SchemaRead, SchemaWrite};

use super::transact::CpiSignerData;

/// Public deposit without a proof (spec: `proofless_shield`, tag 1).
///
/// The program hashes the recipient's UTXO from these fields plus the settled
/// deposit amount/asset, appends the hash to the UTXO tree, and emits a
/// [`crate::event::ProoflessShieldEvent`] for indexing. The owner is committed as
/// `owner_utxo_hash = Poseidon(owner, blinding)` with the blinding derived
/// from the recipient's view-tag secret and `salt` (spec: Blinding
/// derivation), so the recipient is hidden even though the deposit is public.
/// The amount is taken from the actual public deposit, so a depositor cannot
/// mint a UTXO worth more than they deposited.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ProoflessShieldIxData {
    /// Indexing tag for the single output slot; chosen per the spec's View
    /// Tag Selection.
    pub view_tag: [u8; 32],
    /// `owner_utxo_hash = Poseidon(owner, blinding)`. Opaque to the program —
    /// it hides the recipient. A malformed value just yields an unspendable
    /// UTXO (the depositor's loss only).
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
