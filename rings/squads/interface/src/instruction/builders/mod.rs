//! Client instruction builders for the Squads ring program. Each builder is a
//! struct holding the caller-supplied accounts and instruction data, with an
//! `instruction()` method returning a `solana_instruction::Instruction`. Account
//! order and signer/writable flags follow `docs/squads_policy_program.md`.

pub mod cancel_key_update;
pub mod cancel_proposal;
pub mod close_viewing_key_account;
pub mod create_proposal;
pub mod create_ring_config;
pub mod create_viewing_key_account;
pub mod deposit;
pub mod execute_key_update;
pub mod execute_proposal;
pub mod fill_key_update;
pub mod fold_transact;
pub mod full_withdrawal;
pub mod init_spp_ring_config;
pub mod merge_transact;
pub mod toggle_viewing_key_account;
pub mod transact;
pub mod update_ring_config;
pub mod update_viewing_key_account;

pub use cancel_key_update::CancelKeyUpdate;
pub use cancel_proposal::CancelProposal;
pub use close_viewing_key_account::CloseViewingKeyAccount;
pub use create_proposal::CreateProposal;
pub use create_ring_config::CreateRingConfig;
pub use create_viewing_key_account::CreateViewingKeyAccount;
pub use deposit::{Deposit, DepositSettlement};
pub use execute_key_update::ExecuteKeyUpdate;
pub use execute_proposal::ExecuteProposal;
pub use fill_key_update::FillKeyUpdate;
pub use fold_transact::FoldTransact;
pub use full_withdrawal::FullWithdrawal;
pub use init_spp_ring_config::InitSppRingConfig;
pub use merge_transact::MergeTransact;
pub use toggle_viewing_key_account::ToggleViewingKeyAccount;
pub use transact::{Transact, TransactWithdrawal};
pub use update_ring_config::UpdateRingConfig;
pub use update_viewing_key_account::UpdateViewingKeyAccount;
