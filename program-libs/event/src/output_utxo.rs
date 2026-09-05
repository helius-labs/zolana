use borsh::{BorshDeserialize, BorshSerialize};

/// One created output UTXO slot (spec: `transact` `OutputUtxo`). `data` is the
/// serialized output payload (Output UTXO Serialization); the program does not
/// parse it.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct OutputUtxo {
    pub view_tag: [u8; 32],
    pub utxo_hash: [u8; 32],
    pub data: Vec<u8>,
}
