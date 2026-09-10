#[cfg(feature = "tree")]
pub mod batch_update_nullifier_tree;
#[cfg(feature = "tree")]
pub mod create_tree;
pub mod deposit;
pub mod merge_ring;
pub mod merge_transact;
pub mod protocol_config;
pub mod ring_config;
#[cfg(feature = "tree")]
pub mod set_tree_fees;
pub mod transact;

use wincode::{
    config::{Configuration, DEFAULT_PREALLOCATION_SIZE_LIMIT},
    len::FixIntLen,
};

/// Configuration shared by the borrowed instruction-data views. Record lists
/// carry explicit `u8` lengths; byte slices inside records carry `u16`.
pub(crate) type RefConfig = Configuration<true, DEFAULT_PREALLOCATION_SIZE_LIMIT, FixIntLen<u16>>;

#[cfg(feature = "tree")]
pub use batch_update_nullifier_tree::{BatchUpdateNullifierTreeData, CompressedProof};
#[cfg(feature = "tree")]
pub use create_tree::CreateTreeData;
pub use deposit::{
    deposit_blinding, DepositAssetKind, DepositEntry, DepositEntryRef, DepositIxData,
    DepositIxDataRef, EncryptedRingDepositData, EncryptedRingDepositDataRef, RingDepositEntry,
    RingDepositEntryRef, RingDepositIxData, RingDepositIxDataRef, UtxoData, UtxoDataRef,
    DEPOSIT_BLINDING_DOMAIN, MAX_DEPOSIT_ASSETS,
};
pub use merge_ring::{MergeRingIxData, MergeRingIxDataRef};
pub use merge_transact::{
    MergeExternalDataHash, MergeProof, MergeProofRef, MergeTransactIxData, MergeTransactIxDataRef,
    MERGE_DEFAULT_INPUT_COUNT,
};
pub use protocol_config::{CreateProtocolConfigData, PauseTreeData, UpdateProtocolConfigData};
pub use ring_config::{CreateRingConfigData, SetRingActivationData, UpdateRingConfigData};
#[cfg(feature = "tree")]
pub use set_tree_fees::SetTreeFeesData;
pub use transact::{
    fetch_tag, validate_interface_transfers, CircuitId, InputUtxo, InputUtxoRef, InterfaceTransfer,
    MessageDataRef, OwnerTag, OwnerTagRef, TransactExternalData, TransactExternalDataRef,
    TransactIxData, TransactIxDataRef, TransactOutput, TransactOutputRef, TransactProof,
    TransactProofRef,
};
