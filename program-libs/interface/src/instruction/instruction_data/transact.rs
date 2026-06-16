use borsh::{BorshDeserialize, BorshSerialize};
use wincode::containers;
use wincode::len::FixIntLen;
use wincode::{SchemaRead, SchemaWrite};

/// One spent input UTXO (spec: `transact` `InputUtxo`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct InputUtxo {
    pub nullifier_hash: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub tree_index: u8,
    pub eddsa_signer_index: u8,
}

/// One created output UTXO slot (spec: `transact` `OutputUtxo`). `data` is the
/// serialized output payload (Output UTXO Serialization); the program does not
/// parse it.
#[derive(
    Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite, BorshDeserialize, BorshSerialize,
)]
pub struct OutputUtxo {
    pub view_tag: [u8; 32],
    pub utxo_hash: [u8; 32],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub data: Vec<u8>,
}

/// Declared invoking-program signer (spec: `transact` `cpi_signer`). The zk
/// program proves over the top-level `TransactIxData::private_tx_hash`.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, SchemaRead, SchemaWrite,
)]
pub struct TransactCpiSigner {
    pub program_id: [u8; 32],
    pub bump: u8,
}

/// `transact` instruction data (spec: SPP `transact`).
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactIxData {
    pub proof: [u8; 192],
    pub expiry_unix_ts: u64,
    pub relayer_fee: u16,
    pub private_tx_hash: [u8; 32],
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
    /// Signed public amount: positive deposits into the pool, negative
    /// withdraws. `None` for a pure shielded transfer.
    pub public_sol_amount: Option<i64>,
    pub public_spl_amount: Option<i64>,
    pub cpi_signer: Option<TransactCpiSigner>,
    /// SEC1-compressed P256 viewing key shared by every output ciphertext in
    /// this transaction; copied verbatim into the emitted `GeneralEvent` so an
    /// indexer need not parse the opaque output payloads.
    pub tx_viewing_pk: [u8; 33],
    pub sender_utxo_data: OutputUtxo,
    #[wincode(with = "containers::Vec<OutputUtxo, FixIntLen<u8>>")]
    pub recipient_utxo_data: Vec<OutputUtxo>,
}

impl TransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Read config for the borrowed views: identical to the default config used by
/// [`TransactIxData::serialize`], except sequences without an explicit
/// `FixIntLen` carry a `u16` length prefix. This matches the byte vectors
/// (`OutputUtxo::data`) the owned struct writes with `FixIntLen<u16>`, while the
/// element vectors keep their explicit `FixIntLen<u8>` override.
type RefConfig = wincode::config::Configuration<
    true,
    { wincode::config::DEFAULT_PREALLOCATION_SIZE_LIMIT },
    FixIntLen<u16>,
>;

/// Borrowed view of an [`OutputUtxo`]; `data` aliases the instruction buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead)]
pub struct OutputUtxoRef<'a> {
    pub view_tag: &'a [u8; 32],
    pub utxo_hash: &'a [u8; 32],
    pub data: &'a [u8],
}

/// Zero-copy view of [`TransactIxData`]. The large payloads (`proof` and the
/// output ciphertexts) alias the instruction buffer; only the small element
/// vectors are read owned.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct TransactIxDataRef<'a> {
    pub proof: &'a [u8; 192],
    pub expiry_unix_ts: u64,
    pub relayer_fee: u16,
    pub private_tx_hash: &'a [u8; 32],
    #[wincode(with = "containers::Vec<InputUtxo, FixIntLen<u8>>")]
    pub inputs: Vec<InputUtxo>,
    pub public_sol_amount: Option<i64>,
    pub public_spl_amount: Option<i64>,
    pub cpi_signer: Option<TransactCpiSigner>,
    pub tx_viewing_pk: &'a [u8; 33],
    pub sender_utxo_data: OutputUtxoRef<'a>,
    #[wincode(with = "containers::Vec<OutputUtxoRef<'a>, FixIntLen<u8>>")]
    pub recipient_utxo_data: Vec<OutputUtxoRef<'a>>,
}

impl<'a> TransactIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        wincode::config::deserialize(data, RefConfig::new())
    }

    /// True when the public amount is an SPL token amount; false for SOL or a
    /// pure shielded transfer (no public amount).
    pub fn is_spl(&self) -> bool {
        self.public_spl_amount.is_some()
    }

    /// True for a shield or unshield (a public amount is present); false for a
    /// pure shielded transfer.
    pub fn is_deposit_or_withdrawal(&self) -> bool {
        self.public_sol_amount.is_some() || self.public_spl_amount.is_some()
    }

    /// Direction of the public amount: `true` deposits into the pool (positive
    /// amount), `false` withdraws (negative amount). Meaningless for a pure
    /// shielded transfer, where no public amount is present.
    pub fn is_deposit(&self) -> bool {
        self.public_spl_amount.or(self.public_sol_amount).unwrap_or(0) > 0
    }
}
