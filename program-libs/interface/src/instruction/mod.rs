#[cfg(feature = "solana")]
pub mod builders;
pub mod instruction_data;
#[cfg(feature = "borsh")]
use borsh::BorshSerialize;
#[cfg(feature = "solana")]
pub use builders::*;
pub use instruction_data::{
    deposit_blinding, fetch_tag, validate_interface_transfers, CircuitId, CreateProtocolConfigData,
    CreateRingConfigData, DepositAssetKind, DepositEntry, DepositEntryRef, DepositIxData,
    DepositIxDataRef, EncryptedRingDepositData, EncryptedRingDepositDataRef, InputUtxo,
    InterfaceTransfer, MergeExternalDataHash, MergeRingIxData, MergeRingIxDataRef,
    MergeTransactIxData, MergeTransactIxDataRef, MessageData, OutputDataRef, OutputUtxo, OwnerTag,
    PauseTreeData, ResolvedInterfaceTransfer, ResolvedOutput, RingDepositEntry,
    RingDepositEntryRef, RingDepositIxData, RingDepositIxDataRef, SetRingActivationData,
    TransactIxData, TransactIxDataRef, TransactOutput, TransactOutputRef, TransactProof,
    UpdateProtocolConfigData, UpdateRingConfigData, UtxoData, UtxoDataRef, DEPOSIT_BLINDING_DOMAIN,
    MAX_DEPOSIT_ASSETS,
};
#[cfg(feature = "tree")]
pub use instruction_data::{
    BatchUpdateNullifierTreeData, CompressedProof, CreateTreeData, SetTreeFeesData,
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
