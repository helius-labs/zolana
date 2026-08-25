mod create_config;
#[cfg(feature = "policy")]
mod create_policy;
#[cfg(feature = "policy")]
mod create_record;
mod deposit;
mod grant_read_access;
mod init_spp_ring_config;
mod loader;
#[cfg(feature = "policy")]
mod policy_shared;
mod revoke_read_access;
mod set_authority;
mod shared;
mod transact;
#[cfg(feature = "policy")]
mod update_record;
mod verifier;

pub(crate) use create_config::process_create_config_ix;
#[cfg(feature = "policy")]
pub(crate) use create_policy::process_create_policy_ix;
#[cfg(feature = "policy")]
pub(crate) use create_record::process_create_record_ix;
pub(crate) use deposit::process_deposit_ix;
pub(crate) use grant_read_access::process_grant_read_access_ix;
pub(crate) use init_spp_ring_config::process_init_spp_ring_config_ix;
pub(crate) use revoke_read_access::process_revoke_read_access_ix;
pub(crate) use set_authority::process_set_authority_ix;
pub(crate) use transact::process_transact_ix;
#[cfg(feature = "policy")]
pub(crate) use update_record::process_update_record_ix;
