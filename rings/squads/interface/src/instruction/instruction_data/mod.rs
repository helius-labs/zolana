//! Owned instruction-data structs for every Squads ring instruction (tags
//! 0..15). Each carries `serialize`/`deserialize` helpers over wincode. Shared
//! `InputContext` lives in [`transact`]. `KeyOperation` is the canonical type
//! from [`crate::state::key_update_proposal`].

pub mod cancel_key_update;
pub mod cancel_proposal;
pub mod close_viewing_key_account;
pub mod create_proposal;
pub mod create_ring_config;
pub mod create_viewing_key_account;
pub mod deposit;
pub mod encrypted_utxos;
pub mod execute_key_update;
pub mod execute_proposal;
pub mod fill_key_update;
pub mod fold_transact;
pub mod full_withdrawal;
pub mod merge_transact;
pub mod toggle_viewing_key_account;
pub mod transact;
pub mod update_ring_config;
pub mod update_viewing_key_account;

pub use cancel_key_update::CancelKeyUpdateIxData;
pub use cancel_proposal::CancelProposalIxData;
pub use close_viewing_key_account::CloseViewingKeyAccountIxData;
pub use create_proposal::CreateProposalIxData;
pub use create_ring_config::CreateRingConfigIxData;
pub use create_viewing_key_account::CreateViewingKeyAccountIxData;
pub use deposit::DepositIxData;
pub use encrypted_utxos::EncryptedUtxos;
pub use execute_key_update::ExecuteKeyUpdateIxData;
pub use execute_proposal::ExecuteProposalIxData;
pub use fill_key_update::FillKeyUpdateIxData;
pub use fold_transact::{FoldTransactIxData, FoldTransactLeg};
pub use full_withdrawal::FullWithdrawalIxData;
pub use merge_transact::MergeTransactIxData;
pub use toggle_viewing_key_account::ToggleViewingKeyAccountIxData;
pub use transact::{InputContext, TransactIxData};
pub use update_ring_config::UpdateRingConfigIxData;
pub use update_viewing_key_account::UpdateViewingKeyAccountIxData;
