use solana_address::Address;

use crate::{HeadMapRoot, KeyRegistryRoot};

pub fn head_map_root(program: &Address) -> (Address, u8) {
    Address::find_program_address(&[HeadMapRoot::SEED], program)
}

pub fn key_registry_root(program: &Address) -> (Address, u8) {
    Address::find_program_address(&[KeyRegistryRoot::SEED], program)
}
