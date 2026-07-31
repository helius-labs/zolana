#[cfg(feature = "solana")]
pub mod builders;
pub mod instruction_data;
#[cfg(feature = "borsh")]
use borsh::BorshSerialize;
#[cfg(feature = "solana")]
pub use builders::*;
pub use instruction_data::{
    fetch_tag, validate_interface_transfers, BatchUpdateNullifierTreeData, CircuitId,
    CompressedProof, CreateProtocolConfigData, CreateRingConfigData, DepositAssetKind,
    DepositEntry, DepositEntryRef, DepositIxData, DepositIxDataRef, EncryptedRingDepositData,
    EncryptedRingDepositDataRef, InputUtxo, InterfaceTransfer, MergeExternalDataHash,
    MergeTransactIxData, MergeTransactIxDataRef, MergeRingIxData, MergeRingIxDataRef, MessageData,
    OutputDataRef, OutputUtxo, OwnerTag, PauseTreeData, ResolvedInterfaceTransfer, ResolvedOutput,
    TransactIxData, TransactIxDataRef, TransactOutput, TransactOutputRef, TransactProof,
    UpdateProtocolConfigData, UpdateRingConfigData, UtxoData, UtxoDataRef, RingDepositEntry,
    RingDepositEntryRef, RingDepositIxData, RingDepositIxDataRef, MAX_DEPOSIT_ASSETS,
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
