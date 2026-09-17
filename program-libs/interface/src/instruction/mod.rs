#[cfg(feature = "solana")]
pub mod builders;
pub mod instruction_data;
#[cfg(feature = "borsh")]
use borsh::BorshSerialize;
#[cfg(feature = "solana")]
pub use builders::*;
pub use instruction_data::{
    deposit_blinding, fetch_tag, validate_input_tree_contexts, validate_interface_transfers,
    CachedInputs, CircuitId, CreateCacheData, CreateProtocolConfigData, CreateReceiptData,
    CreateRingConfigData, DepositAssetKind, DepositEntry, DepositEntryRef, DepositIxData,
    DepositIxDataRef, EncryptedRingDepositData, EncryptedRingDepositDataRef, ExternalDataPreimage,
    InputUtxo, InterfaceTransfer, MergeExternalDataHash, MergeRingIxData, MergeRingIxDataRef,
    MergeTransactIxData, MergeTransactIxDataRef, MessageData, OutputDataRef, OutputUtxo, OwnerTag,
    PauseTreeData, ResolvedOutput, RingDepositEntry, RingDepositEntryRef, RingDepositIxData,
    RingDepositIxDataRef, SetRingActivationData, TransactIxData, TransactIxDataRef, TransactOutput,
    TransactOutputRef, TransactProof, TreeContext, UpdateProtocolConfigData, UpdateRingConfigData,
    UploadReceiptData, UtxoData, UtxoDataRef, VerifyReceiptData, DEPOSIT_BLINDING_DOMAIN,
    MAX_DEPOSIT_ASSETS, RECEIPT_DOMAIN,
};
#[cfg(feature = "tree")]
pub use instruction_data::{
    BatchUpdateNullifierTreeData, CreateTreeData, NullifierTreeProof, SetTreeFeesData,
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
