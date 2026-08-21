mod create_config;
mod deposit;
mod grant_reader;
mod init_spp_ring_config;
mod loader;
mod revoke_reader;
mod shared;
mod transact;
mod verifier;

pub(crate) use create_config::process_create_config_ix;
pub(crate) use deposit::process_deposit_ix;
pub(crate) use grant_reader::process_grant_reader_ix;
pub(crate) use init_spp_ring_config::process_init_spp_ring_config_ix;
pub(crate) use revoke_reader::process_revoke_reader_ix;
pub(crate) use transact::process_transact_ix;
