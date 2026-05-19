/// First-byte instruction dispatch tags for the shielded-pool program.
pub const CREATE_ADDRESS_TREE: u8 = 0;
pub const INSERT_ADDRESSES: u8 = 1;
pub const BATCH_UPDATE_ADDRESS_TREE: u8 = 2;
pub const CREATE_STATE_TREE: u8 = 3;
pub const APPEND_STATE_LEAVES: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InstructionTag {
    CreateAddressTree = CREATE_ADDRESS_TREE,
    InsertAddresses = INSERT_ADDRESSES,
    BatchUpdateAddressTree = BATCH_UPDATE_ADDRESS_TREE,
    CreateStateTree = CREATE_STATE_TREE,
    AppendStateLeaves = APPEND_STATE_LEAVES,
}

impl TryFrom<u8> for InstructionTag {
    type Error = ();

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            CREATE_ADDRESS_TREE => Ok(Self::CreateAddressTree),
            INSERT_ADDRESSES => Ok(Self::InsertAddresses),
            BATCH_UPDATE_ADDRESS_TREE => Ok(Self::BatchUpdateAddressTree),
            CREATE_STATE_TREE => Ok(Self::CreateStateTree),
            APPEND_STATE_LEAVES => Ok(Self::AppendStateLeaves),
            _ => Err(()),
        }
    }
}
