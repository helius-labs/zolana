/// First-byte instruction dispatch tags for the shielded-pool program.
pub const CREATE_ADDRESS_TREE: u8 = 0;
pub const INSERT_ADDRESSES: u8 = 1;
pub const BATCH_UPDATE_ADDRESS_TREE: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InstructionTag {
    CreateAddressTree = CREATE_ADDRESS_TREE,
    InsertAddresses = INSERT_ADDRESSES,
    BatchUpdateAddressTree = BATCH_UPDATE_ADDRESS_TREE,
}

impl TryFrom<u8> for InstructionTag {
    type Error = ();

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            CREATE_ADDRESS_TREE => Ok(Self::CreateAddressTree),
            INSERT_ADDRESSES => Ok(Self::InsertAddresses),
            BATCH_UPDATE_ADDRESS_TREE => Ok(Self::BatchUpdateAddressTree),
            _ => Err(()),
        }
    }
}
