use borsh::{BorshDeserialize, BorshSerialize};
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

/// One published data slot not bound to an output position, carried by
/// `TransactIxData::messages` and republished in `GeneralEvent::messages`.
#[derive(
    Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite, BorshDeserialize, BorshSerialize,
)]
pub struct OutputData {
    pub view_tag: [u8; 32],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub data: Vec<u8>,
}
