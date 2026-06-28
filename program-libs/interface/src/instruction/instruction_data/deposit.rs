use borsh::{BorshDeserialize, BorshSerialize};
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

/// A program that governs `data` for a deposited UTXO (its `auth` PDA signs)
/// bundled with the data committed into `program_hash`. `cpi_signer`'s pubkey
/// drives the UTXO's `program_id`. (The zone side carries no `cpi_signer`: its
/// id comes from the `ZoneConfig` account.)
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CpiData {
    pub cpi_signer: CpiSignerData,
    pub data_hash: [u8; 32],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub data: Vec<u8>,
}

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
    /// Invoking program (general program owner, seed `auth`) and its program
    /// data; `None` for a plain user deposit. Policy-zone deposits use
    /// [`ZoneDepositIxData`].
    pub program: Option<CpiData>,
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
    /// Zone-defined data committed into `zone_hash`. The zone's `program_id` is
    /// NOT in instruction data: it is read from the `ZoneConfig` account (the
    /// signing `zone_auth` PDA) the zone forwards.
    pub zone_data_hash: [u8; 32],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub zone_data: Vec<u8>,
    /// Program governing `program_data` (seed `auth`) and its data; `None` if the
    /// zone deposit carries no application program data.
    pub program: Option<CpiData>,
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
