/// First-byte instruction dispatch tags for the shielded-pool program.
pub const CREATE_POOL_TREE: u8 = 0;
pub const INSERT_ADDRESSES: u8 = 1;
pub const BATCH_UPDATE_ADDRESS_TREE: u8 = 2;
pub const APPEND_STATE_LEAVES: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InstructionTag {
    CreatePoolTree = CREATE_POOL_TREE,
    InsertAddresses = INSERT_ADDRESSES,
    BatchUpdateAddressTree = BATCH_UPDATE_ADDRESS_TREE,
    AppendStateLeaves = APPEND_STATE_LEAVES,
}

impl TryFrom<u8> for InstructionTag {
    type Error = ();

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            CREATE_POOL_TREE => Ok(Self::CreatePoolTree),
            INSERT_ADDRESSES => Ok(Self::InsertAddresses),
            BATCH_UPDATE_ADDRESS_TREE => Ok(Self::BatchUpdateAddressTree),
            APPEND_STATE_LEAVES => Ok(Self::AppendStateLeaves),
            _ => Err(()),
        }
    }
}
