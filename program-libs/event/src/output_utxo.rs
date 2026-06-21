use borsh::{BorshDeserialize, BorshSerialize};
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

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
