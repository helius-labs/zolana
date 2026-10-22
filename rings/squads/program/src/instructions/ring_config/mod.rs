//! Ring config account family: the singleton config PDA, its loader, and the
//! create/update instructions.

pub mod create;
pub mod init_spp_ring_config;
pub mod loader;
pub mod update;

pub use create::process_create_ring_config_ix;
pub use init_spp_ring_config::process_init_spp_ring_config_ix;
pub use loader::load_ring_config;
pub use update::process_update_ring_config_ix;
