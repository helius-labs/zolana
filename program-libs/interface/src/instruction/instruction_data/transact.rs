use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct TransactData {
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
    pub public_spl_asset_id: u64,
    pub encrypted_utxos: Vec<u8>,
}

pub const PUBLIC_AMOUNT_NONE: u8 = 0;
pub const PUBLIC_AMOUNT_DEPOSIT: u8 = 1;
pub const PUBLIC_AMOUNT_WITHDRAW: u8 = 2;
