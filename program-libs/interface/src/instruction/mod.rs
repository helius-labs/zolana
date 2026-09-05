#[cfg(feature = "solana")]
pub mod builders;
pub mod instruction_data;
pub mod tag;
#[cfg(feature = "borsh")]
use borsh::BorshSerialize;
#[cfg(feature = "solana")]
pub use builders::*;
pub use instruction_data::{
    deposit_blinding, fetch_tag, validate_interface_transfers, CircuitId, CreateProtocolConfigData,
    CreateRingConfigData, DepositAssetKind, DepositEntry, DepositEntryRef, DepositIxData,
    DepositIxDataRef, EncryptedRingDepositData, EncryptedRingDepositDataRef, InputUtxo,
    InputUtxoRef, InterfaceTransfer, MergeExternalDataHash, MergeRingIxData, MergeRingIxDataRef,
    MergeTransactIxData, MergeTransactIxDataRef, MessageDataRef, OwnerTag, OwnerTagRef,
    PauseTreeData, RingDepositEntry, RingDepositEntryRef, RingDepositIxData, RingDepositIxDataRef,
    TransactIxData, TransactIxDataRef, TransactOutput, TransactOutputRef, TransactProof,
    TransactProofRef, UpdateProtocolConfigData, UpdateRingConfigData, UtxoData, UtxoDataRef,
    DEPOSIT_BLINDING_DOMAIN, MAX_DEPOSIT_ASSETS,
};
#[cfg(feature = "tree")]
pub use instruction_data::{
    BatchUpdateNullifierTreeData, CompressedProof, CreateTreeData, SetTreeFeesData,
};
pub use tag::InstructionTag;

pub use crate::output_data::MessageData;

#[cfg(feature = "borsh")]
pub fn encode_instruction<T: BorshSerialize>(tag: u8, payload: &T) -> Vec<u8> {
    let mut data = vec![tag];
    payload
        .serialize(&mut data)
        .expect("shielded-pool instruction serialization is infallible");
    data
}
