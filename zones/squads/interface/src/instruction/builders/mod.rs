//! Client instruction builders for the Squads zone program. Each builder is a
//! struct holding the caller-supplied accounts and instruction data, with an
//! `instruction()` method returning a `solana_instruction::Instruction`. Account
//! order and signer/writable flags follow `docs/squads_policy_program.md`.

pub mod cancel_key_update;
pub mod cancel_proposal;
pub mod close_viewing_key_account;
pub mod create_proposal;
pub mod create_viewing_key_account;
pub mod create_zone_config;
pub mod deposit;
pub mod execute_key_update;
pub mod execute_proposal;
pub mod fill_key_update;
pub mod full_withdrawal;
pub mod init_spp_zone_config;
pub mod merge_transact;
pub mod toggle_viewing_key_account;
pub mod transact;
pub mod update_viewing_key_account;
pub mod update_zone_config;

pub use cancel_key_update::CancelKeyUpdate;
pub use cancel_proposal::CancelProposal;
pub use close_viewing_key_account::CloseViewingKeyAccount;
pub use create_proposal::CreateProposal;
pub use create_viewing_key_account::CreateViewingKeyAccount;
pub use create_zone_config::CreateZoneConfig;
pub use deposit::{Deposit, DepositSettlement};
pub use execute_key_update::ExecuteKeyUpdate;
pub use execute_proposal::ExecuteProposal;
pub use fill_key_update::FillKeyUpdate;
pub use full_withdrawal::FullWithdrawal;
pub use init_spp_zone_config::InitSppZoneConfig;
pub use merge_transact::MergeTransact;
pub use toggle_viewing_key_account::ToggleViewingKeyAccount;
pub use transact::{Transact, TransactWithdrawal};
pub use update_viewing_key_account::UpdateViewingKeyAccount;
pub use update_zone_config::UpdateZoneConfig;
