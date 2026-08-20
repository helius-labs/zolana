pub mod create_config;
pub mod deposit;
pub mod grant_reader;
pub mod init_spp_ring_config;
pub mod loader;
pub mod revoke_reader;
pub mod shared;
pub mod transact;
pub mod verifier;

pub use create_config::process_create_config_ix;
pub use deposit::process_deposit_ix;
pub use grant_reader::process_grant_reader_ix;
pub use init_spp_ring_config::process_init_spp_ring_config_ix;
pub use revoke_reader::process_revoke_reader_ix;
pub use transact::process_transact_ix;
