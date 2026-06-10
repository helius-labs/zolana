#[cfg(feature = "solana")]
pub mod builders;
pub mod instruction_data;
pub mod tag;

use borsh::BorshSerialize;

pub use instruction_data::{
    BatchUpdateAddressTreeData, CpiSignerData, CreatePocketConfigData, CreatePoolTreeData,
    CreateProtocolConfigData, CreateSplInterfaceData, InputUtxoSignerIndex,
    PauseTreeData, ProoflessShieldData, TransactData, UpdatePocketConfigData,
    UpdatePocketConfigOwnerData, UpdateProtocolConfigData, PUBLIC_AMOUNT_DEPOSIT,
    PUBLIC_AMOUNT_NONE, PUBLIC_AMOUNT_WITHDRAW,
};
pub use tag::InstructionTag;

#[cfg(feature = "solana")]
pub use builders::*;

pub fn encode_instruction<T: BorshSerialize>(tag: u8, payload: &T) -> Vec<u8> {
    let mut data = vec![tag];
    payload
        .serialize(&mut data)
        .expect("shielded-pool instruction serialization is infallible");
    data
}
