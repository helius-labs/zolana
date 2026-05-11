pub mod builders;
pub mod instruction_data;
pub mod tag;

use borsh::{BorshDeserialize, BorshSerialize};

pub use instruction_data::{
    BatchUpdateAddressTreeData, CreateAddressTreeData, InsertAddressesData,
};
pub use tag::InstructionTag;

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum ShieldedPoolInstruction {
    CreateAddressTree(CreateAddressTreeData),
    InsertAddresses(InsertAddressesData),
    BatchUpdateAddressTree(BatchUpdateAddressTreeData),
}

impl ShieldedPoolInstruction {
    pub fn tag(&self) -> InstructionTag {
        match self {
            Self::CreateAddressTree(_) => InstructionTag::CreateAddressTree,
            Self::InsertAddresses(_) => InstructionTag::InsertAddresses,
            Self::BatchUpdateAddressTree(_) => InstructionTag::BatchUpdateAddressTree,
        }
    }
}
