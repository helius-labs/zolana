use solana_address::Address;

use crate::{DepositAudit, KeyRegistryRoot};

pub fn deposit_audit(program: &Address) -> (Address, u8) {
    Address::find_program_address(&[DepositAudit::SEED], program)
}

pub fn key_registry_root(program: &Address) -> (Address, u8) {
    Address::find_program_address(&[KeyRegistryRoot::SEED], program)
}
