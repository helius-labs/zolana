//! Squads ring account state: the on-chain account layouts, their discriminators,
//! and the wincode (de)serialization for each.

pub mod discriminator;
pub mod key_update_proposal;
pub mod proposal;
pub mod ring_config;
pub mod viewing_key_account;

pub use key_update_proposal::{KeyOperation, KeyUpdateProposal};
pub use proposal::Proposal;
pub use ring_config::RingConfig;
pub use viewing_key_account::ViewingKeyAccount;
