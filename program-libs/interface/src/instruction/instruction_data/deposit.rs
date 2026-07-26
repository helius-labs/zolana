use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

/// Application data committed into the deposited UTXO's `data_hash`. The deposit
/// is authorized by the payer (non-zone) or the `ZoneConfig` account (zone); the
/// UTXO is not program-owned.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UtxoData {
    pub data_hash: [u8; 32],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub data: Vec<u8>,
}

/// Maximum number of distinct assets (settlement groups) per `deposit` batch.
pub const MAX_DEPOSIT_ASSETS: usize = 5;

/// Kind of one settlement group, declaring how many accounts it consumes and how
/// they are validated: `Sol` takes (`system_program`, `sol_interface`), `Spl`
/// takes (`token_program`, `user_token`, `vault`, `registry`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
pub enum DepositAssetKind {
    Sol,
    Spl {
        /// Canonical bump of the initialized per-mint vault PDA.
        vault_bump: u8,
    },
}

/// One output of a batched public deposit (see [`DepositIxData`]).
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct DepositEntry {
    /// Index into [`DepositIxData::assets`]. Selects the asset this entry
    /// deposits and the settlement group that funds it.
    pub asset_index: u8,
    /// Indexing tag for this output slot; chosen per the spec's View Tag
    /// Selection.
    pub view_tag: [u8; 32],
    /// Recipient `owner_hash`; the program nests it with `blinding` into the
    /// UTXO's `owner_utxo_hash`.
    pub owner: [u8; 32],
    /// Fresh CSPRNG per deposit; sent in the clear so a third-party depositor
    /// needs no shared secret and the recipient spends it directly. A big-endian
    /// field element (31 random bytes right-aligned, so always below the BN254
    /// modulus).
    pub blinding: [u8; 32],
    /// Deposited amount of the asset selected by `asset_index`.
    pub amount: u64,
    /// Application data committed into the UTXO's `data_hash`, authorized by the
    /// payer; `None` for a plain user deposit. Policy-zone deposits use
    /// [`ZoneDepositIxData`].
    pub utxo_data: Option<UtxoData>,
    /// Optional free-form memo emitted in the clear with the proofless output.
    /// Not committed into any hash, so it is informational only.
    #[wincode(with = "Option<containers::Vec<u8, FixIntLen<u16>>>")]
    pub memo: Option<Vec<u8>>,
}

/// Batched public deposit without a proof (spec: `deposit`, tag 1).
///
/// Each entry appends one output UTXO. Entries deposit into at most
/// [`MAX_DEPOSIT_ASSETS`] distinct assets; per-asset amounts are summed so each
/// asset settles with a single transfer, and the program emits one
/// [`crate::event::GeneralEvent`] carrying every proofless output for wallet
/// discovery.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct DepositIxData {
    /// Settlement groups in account order. The program reads the accounts each
    /// kind names, in this order, so the account layout is declared rather than
    /// inferred from the account count.
    #[wincode(with = "containers::Vec<DepositAssetKind, FixIntLen<u8>>")]
    pub assets: Vec<DepositAssetKind>,
    #[wincode(with = "containers::Vec<DepositEntry, FixIntLen<u8>>")]
    pub deposits: Vec<DepositEntry>,
}

impl DepositIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// One output of a batched policy-zone deposit.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ZoneDepositEntry {
    /// Common output and settlement-group fields.
    pub deposit: DepositEntry,
    /// Zone-defined data committed into `zone_hash`. The zone's `program_id` is
    /// NOT in instruction data: it is read from the `ZoneConfig` account (the
    /// signing `zone_auth` PDA) the zone forwards.
    pub zone_data_hash: [u8; 32],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub zone_data: Vec<u8>,
}

/// Batched policy-zone analog of [`DepositIxData`] (spec: `zone_deposit`, tag
/// 15). A zone program CPIs into SPP signing with its `zone_auth` PDA. Every
/// output is owned by that zone, while policy data is specified per output.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ZoneDepositIxData {
    #[wincode(with = "containers::Vec<DepositAssetKind, FixIntLen<u8>>")]
    pub assets: Vec<DepositAssetKind>,
    #[wincode(with = "containers::Vec<ZoneDepositEntry, FixIntLen<u8>>")]
    pub deposits: Vec<ZoneDepositEntry>,
}

impl ZoneDepositIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}
