#[cfg(feature = "solana")]
pub mod builders;
pub mod instruction_data;
use borsh::BorshSerialize;
#[cfg(feature = "solana")]
pub use builders::*;
pub use instruction_data::{
    fetch_tag, BatchUpdateNullifierTreeData, CompressedProof, CreateProtocolConfigData,
    CreateTreeData, CreateZoneConfigData, DepositIxData, FetchTagError, InputUtxo,
    MergeExternalDataHash, MergeTransactIxData, MergeTransactIxDataRef, MergeZoneIxData,
    MergeZoneIxDataRef, OutputData, OutputDataRef, OutputUtxo, OwnerTag, PauseTreeData,
    ResolvedOutput, TransactIxData, TransactIxDataRef, TransactOutput, TransactOutputRef,
    TransactProof, UpdateProtocolConfigData, UpdateZoneConfigData, UpdateZoneConfigOwnerData,
    UtxoData, ZoneDepositIxData,
};
pub use zolana_event::{tag, tag::InstructionTag};

pub fn encode_instruction<T: BorshSerialize>(tag: u8, payload: &T) -> Vec<u8> {
    let mut data = vec![tag];
    payload
        .serialize(&mut data)
        .expect("shielded-pool instruction serialization is infallible");
    data
}
