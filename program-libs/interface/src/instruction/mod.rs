#[cfg(feature = "solana")]
pub mod builders;
pub mod instruction_data;
pub use zolana_event::tag;

use borsh::BorshSerialize;

pub use instruction_data::{
    BatchUpdateNullifierTreeData, CompressedProof, CpiSignerData, CreateProtocolConfigData,
    CreateTreeData, CreateZoneConfigData, DepositIxData, InputUtxo, OutputCiphertext,
    OutputCiphertextRef, OutputUtxo, PauseTreeData, TransactIxData, TransactIxDataRef,
    UpdateProtocolConfigData, UpdateZoneConfigData, UpdateZoneConfigOwnerData, ZoneDepositIxData,
};
pub use zolana_event::tag::InstructionTag;

#[cfg(feature = "solana")]
pub use builders::*;

pub fn encode_instruction<T: BorshSerialize>(tag: u8, payload: &T) -> Vec<u8> {
    let mut data = vec![tag];
    payload
        .serialize(&mut data)
        .expect("shielded-pool instruction serialization is infallible");
    data
}
