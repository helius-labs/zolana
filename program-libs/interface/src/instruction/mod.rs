#[cfg(feature = "solana")]
pub mod builders;
pub mod instruction_data;
#[cfg(feature = "borsh")]
use borsh::BorshSerialize;
#[cfg(feature = "solana")]
pub use builders::*;
pub use instruction_data::{
    fetch_tag, BatchUpdateNullifierTreeData, CompressedProof, CreateProtocolConfigData,
    CreateTreeData, CreateZoneConfigData, DepositIxData, InputUtxo, MergeExternalDataHash,
    MergeTransactIxData, MergeTransactIxDataRef, MergeZoneIxData, MergeZoneIxDataRef, MessageData,
    OutputDataRef, OutputUtxo, OwnerTag, P256Proof, P256ProofRef, PauseTreeData, ResolvedOutput,
    TransactIxData, TransactIxDataRef, TransactOutput, TransactOutputRef, TransactProof,
    UpdateProtocolConfigData, UpdateZoneConfigData, UpdateZoneConfigOwnerData, UtxoData,
    ZoneDepositIxData,
};
pub use zolana_event::{tag, tag::InstructionTag};

#[cfg(feature = "borsh")]
pub fn encode_instruction<T: BorshSerialize>(tag: u8, payload: &T) -> Vec<u8> {
    let mut data = vec![tag];
    payload
        .serialize(&mut data)
        .expect("shielded-pool instruction serialization is infallible");
    data
}
