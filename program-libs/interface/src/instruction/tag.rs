#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InstructionTag {
    CreateAddressTree = 0,
    InsertAddresses = 1,
    BatchUpdateAddressTree = 2,
}
