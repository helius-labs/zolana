use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::tag;

/// Advances the pair's queue head past its expired or cancelled head order.
/// Permissionless and proof-free. `escrow` is the head order's account
/// (`escrow_pda(pair, Pair::head_order_id)`); a cancellation marker closes,
/// and its rent returns to `rent_recipient`, which must be the escrow owner.
/// An expired open order retains its account and reservation until `Cancel`
/// refunds it. Advancing the queue never releases that reservation.
pub struct SkipExpired {
    pub pair: Pubkey,
    pub escrow: Pubkey,
    pub rent_recipient: Pubkey,
}

impl SkipExpired {
    pub fn instruction(self) -> Instruction {
        Instruction {
            program_id: dynamic_swap_program::ID,
            accounts: vec![
                AccountMeta::new(self.pair, false),
                AccountMeta::new(self.escrow, false),
                AccountMeta::new(self.rent_recipient, false),
            ],
            data: vec![tag::SKIP_EXPIRED],
        }
    }
}
