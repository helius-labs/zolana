//! Account-type discriminators for the Squads zone. The first byte of every
//! account stamps one of these so loaders can reject mismatched accounts.

/// Singleton [`ZoneConfig`](super::zone_config::ZoneConfig).
pub const ZONE_CONFIG: u8 = 1;
/// Per-owner [`ViewingKeyAccount`](super::viewing_key_account::ViewingKeyAccount).
pub const VIEWING_KEY_ACCOUNT: u8 = 2;
/// Async [`Proposal`](super::proposal::Proposal).
pub const PROPOSAL: u8 = 3;
/// Async [`KeyUpdateProposal`](super::key_update_proposal::KeyUpdateProposal).
pub const KEY_UPDATE_PROPOSAL: u8 = 4;
