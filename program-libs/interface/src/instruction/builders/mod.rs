mod batch_update_nullifier_tree;
mod create_spl_interface;
mod create_tree;
mod proofless_shield;
mod protocol_config;
mod zone_config;
mod zone_proofless_shield;

use solana_pubkey::Pubkey;

use crate::{DEFAULT_SOL_INTERFACE_INDEX_SEED, SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE_PDA_SEED};

pub use batch_update_nullifier_tree::batch_update_nullifier_tree;
pub use create_spl_interface::{create_spl_interface, CreateSplInterfaceAccounts};
pub use create_tree::create_tree;
pub use proofless_shield::{ProoflessShieldAccounts, ProoflessShieldSplAccounts};
pub use protocol_config::{create_protocol_config, pause_tree, update_protocol_config};
pub use zone_config::{create_zone_config, update_zone_config, update_zone_config_owner};
pub use zone_proofless_shield::{zone_proofless_shield, zone_proofless_shield_cpi};

fn sol_interface_pda() -> Pubkey {
    Pubkey::find_program_address(
        &[SOL_INTERFACE_PDA_SEED, DEFAULT_SOL_INTERFACE_INDEX_SEED],
        &Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
    )
    .0
}
