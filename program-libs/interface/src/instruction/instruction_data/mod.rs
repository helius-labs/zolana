pub mod batch_update_nullifier_tree;
pub mod create_tree;
pub mod proofless_shield;
pub mod protocol_config;
pub mod transact;
pub mod zone_config;

pub use batch_update_nullifier_tree::BatchUpdateNullifierTreeData;
pub use create_tree::CreateTreeData;
pub use proofless_shield::{CpiSignerData, ProoflessShieldIxData, ZoneProoflessShieldIxData};
pub use protocol_config::{CreateProtocolConfigData, PauseTreeData, UpdateProtocolConfigData};
pub use transact::{
    InputUtxo, OutputUtxo, OutputUtxoRef, TransactCpiSigner, TransactIxData, TransactIxDataRef,
};
pub use zone_config::{CreateZoneConfigData, UpdateZoneConfigData, UpdateZoneConfigOwnerData};

pub const PUBLIC_AMOUNT_NONE: u8 = 0;
pub const PUBLIC_AMOUNT_DEPOSIT_SOL: u8 = 1;
pub const PUBLIC_AMOUNT_DEPOSIT_SPL: u8 = 2;
pub const PUBLIC_AMOUNT_WITHDRAW_SOL: u8 = 3;
pub const PUBLIC_AMOUNT_WITHDRAW_SPL: u8 = 4;
