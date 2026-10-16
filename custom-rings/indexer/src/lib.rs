pub mod member_registry;
pub mod proof;

use solana_address::Address;

pub struct InstructionView<'a> {
    pub program_id: &'a Address,
    pub accounts: &'a [Address],
    pub data: &'a [u8],
}
