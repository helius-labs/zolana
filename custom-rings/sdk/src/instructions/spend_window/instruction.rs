use custom_ring_interface::{tag, SetSpendWindowIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};

use crate::CustomRing;

/// Sets a mint's public deposit and withdrawal caps and restarts its window counters.
#[must_use]
pub struct SetSpendWindow {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    /// SOL under the zero address.
    pub mint: Address,
    /// Nonzero, windows start at multiples of it.
    pub window_slots: u64,
    /// Zero leaves the direction uncapped.
    pub deposit_cap: u64,
    pub withdrawal_cap: u64,
}

impl SetSpendWindow {
    pub fn instruction(self) -> Result<Instruction, wincode::Error> {
        let Self {
            ring,
            payer,
            authority,
            mint,
            window_slots,
            deposit_cap,
            withdrawal_cap,
        } = self;
        let mut data = vec![tag::SET_SPEND_WINDOW];
        data.extend_from_slice(&wincode::serialize(&SetSpendWindowIxData {
            mint: mint.to_bytes(),
            window_slots,
            deposit_cap,
            withdrawal_cap,
        })?);
        Ok(Instruction {
            program_id: ring.program_id(),
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new_readonly(ring.config_pda(), false),
                AccountMeta::new(ring.spend_window_pda(&mint), false),
                AccountMeta::new_readonly(Address::default(), false),
            ],
            data,
        })
    }
}

/// Removes a mint's public settlement caps and returns its window account rent.
#[must_use]
pub struct ClearSpendWindow {
    pub ring: CustomRing,
    pub authority: Address,
    pub mint: Address,
    pub rent_recipient: Address,
}

impl ClearSpendWindow {
    pub fn instruction(self) -> Instruction {
        let Self {
            ring,
            authority,
            mint,
            rent_recipient,
        } = self;
        let mut data = vec![tag::CLEAR_SPEND_WINDOW];
        data.extend_from_slice(mint.as_array());
        Instruction {
            program_id: ring.program_id(),
            accounts: vec![
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new_readonly(ring.config_pda(), false),
                AccountMeta::new(ring.spend_window_pda(&mint), false),
                AccountMeta::new(rent_recipient, false),
            ],
            data,
        }
    }
}

/// One writable window slot per public leg, in leg order.
pub(crate) fn window_metas(
    ring: CustomRing,
    mints: impl IntoIterator<Item = Address>,
) -> impl Iterator<Item = AccountMeta> {
    mints
        .into_iter()
        .map(move |mint| AccountMeta::new(ring.spend_window_pda(&mint), false))
}
