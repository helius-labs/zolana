use borsh::{BorshDeserialize, BorshSerialize};
use wincode::containers;
use wincode::len::FixIntLen;
use wincode::{SchemaRead, SchemaWrite};

/// Per-input data for a transact: the spent nullifier and the root indices it
/// was proven against. One Vec<TransactInput> replaces three parallel vecs,
/// saving two length prefixes on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactInput {
    pub nullifier: [u8; 32],
    pub utxo_tree_root_index: u16,
    pub nullifier_tree_root_index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct TransactIxData {
    // fixed-size (zero-copy prefix)
    pub expiry_unix_ts: u64,
    pub sender_view_tag: [u8; 32],
    pub proof: [u8; 192],
    pub private_tx_hash: [u8; 32],
    pub relayer_fee: u16,
    pub public_amount_mode: u8,
    /// Ownership rail. true: P256-capable circuit (proof carries an ECDSA
    /// signature gadget); false: the ~7x cheaper Solana-only circuit. Selects
    /// the verifying key and whether p256_message_hash is bound in the public
    /// inputs. A mismatch with the actual inputs fails proof verification.
    pub requires_p256: bool,
    // variable-length
    pub public_amount: Option<u64>,
    pub cpi_signer: Option<CpiSignerData>,
    #[wincode(with = "containers::Vec<TransactInput, FixIntLen<u8>>")]
    pub inputs: Vec<TransactInput>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub output_utxo_hashes: Vec<[u8; 32]>,
    #[wincode(with = "Option<containers::Vec<InputUtxoSignerIndex, FixIntLen<u8>>>")]
    pub in_utxo_signer_indices: Option<Vec<InputUtxoSignerIndex>>,
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub encrypted_utxos: Vec<u8>,
}

impl TransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, SchemaRead, SchemaWrite,
)]
pub struct CpiSignerData {
    pub program_id: [u8; 32],
    pub bump: u8,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, SchemaRead, SchemaWrite,
)]
pub struct InputUtxoSignerIndex {
    pub account_index: u8,
    pub input_index: u8,
}

pub const PUBLIC_AMOUNT_NONE: u8 = 0;
pub const PUBLIC_AMOUNT_DEPOSIT_SOL: u8 = 1;
pub const PUBLIC_AMOUNT_DEPOSIT_SPL: u8 = 2;
pub const PUBLIC_AMOUNT_WITHDRAW_SOL: u8 = 3;
pub const PUBLIC_AMOUNT_WITHDRAW_SPL: u8 = 4;
