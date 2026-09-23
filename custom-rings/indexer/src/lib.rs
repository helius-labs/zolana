pub mod key_registry;
pub mod proof;
pub mod spend_record;

use solana_address::Address;

pub struct InstructionView<'a> {
    pub program_id: &'a Address,
    pub accounts: &'a [Address],
    pub data: &'a [u8],
}
