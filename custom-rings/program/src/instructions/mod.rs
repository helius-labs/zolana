mod create_config;
mod deposit;
mod grant_read_access;
mod init_spp_ring_config;
mod loader;
mod revoke_read_access;
mod shared;
mod transact;
mod verifier;

pub(crate) use create_config::process_create_config_ix;
pub(crate) use deposit::process_deposit_ix;
pub(crate) use grant_read_access::process_grant_read_access_ix;
pub(crate) use init_spp_ring_config::process_init_spp_ring_config_ix;
pub(crate) use revoke_read_access::process_revoke_read_access_ix;
pub(crate) use transact::process_transact_ix;
