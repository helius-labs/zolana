use borsh::{BorshDeserialize, BorshSerialize};
use wincode::{SchemaRead, SchemaWrite};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct TransactIxData {
    pub expiry_unix_ts: u64,
    pub sender_view_tag: [u8; 32],
    pub proof: [u8; 192],
    pub relayer_fee: u16,
    pub public_amount_mode: u8,
    pub nullifiers: Vec<[u8; 32]>,
    pub output_utxo_hashes: Vec<[u8; 32]>,
    pub utxo_tree_root_index: Vec<u16>,
    pub nullifier_tree_root_index: Vec<u16>,
    pub private_tx_hash: [u8; 32],
    pub public_sol_amount: Option<u64>,
    pub public_spl_amount: Option<u64>,
    pub cpi_signer: Option<CpiSignerData>,
    pub in_utxo_signer_indices: Option<Vec<InputUtxoSignerIndex>>,
    pub encrypted_utxos: Vec<u8>,
    /// Ownership rail. true: P256-capable circuit (proof carries an ECDSA
    /// signature gadget); false: the ~7x cheaper Solana-only circuit. Selects
    /// the verifying key and whether p256_message_hash is bound in the public
    /// inputs. A mismatch with the actual inputs fails proof verification.
    pub requires_p256: bool,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, SchemaRead, SchemaWrite,
)]
pub struct CpiSignerData {
    pub program_id: [u8; 32],
    pub bump: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct InputUtxoSignerIndex {
    pub account_index: u8,
    pub input_index: u8,
}

pub const PUBLIC_AMOUNT_NONE: u8 = 0;
pub const PUBLIC_AMOUNT_DEPOSIT: u8 = 1;
pub const PUBLIC_AMOUNT_WITHDRAW: u8 = 2;
