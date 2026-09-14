use custom_ring_interface::SpendWindow;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address,
};
use zolana_interface::{
    instruction::instruction_data::{
        deposit::{DepositAssetKind, RingDepositIxDataRef, MAX_DEPOSIT_ASSETS},
        transact::InterfaceTransfer,
    },
    MAX_INTERFACE_TRANSFERS,
};

use crate::{error::CustomRingError, instructions::loader::load_spend_window};

pub(crate) const SOL: Address = Address::new_from_array([0; 32]);
const MAX_LEGS: usize = if MAX_INTERFACE_TRANSFERS > MAX_DEPOSIT_ASSETS {
    MAX_INTERFACE_TRANSFERS
} else {
    MAX_DEPOSIT_ASSETS
};
const _: () = assert!(MAX_LEGS <= u32::BITS as usize);

/// Resolves public settlement amounts to mints for co-signing and ring-wide accounting.
pub(crate) struct PublicLegs<'a> {
    settlements: &'a [AccountView],
    mint_at: [u8; MAX_LEGS],
    amounts: [u64; MAX_LEGS],
    deposits: u32,
    len: usize,
}

const SOL_LEG: u8 = u8::MAX;

impl<'a> PublicLegs<'a> {
    pub const NONE: Self = Self {
        settlements: &[],
        mint_at: [SOL_LEG; MAX_LEGS],
        amounts: [0; MAX_LEGS],
        deposits: 0,
        len: 0,
    };

    /// `settlements` are the trailing settlement groups of a transact's forwarded list.
    #[inline(never)]
    pub fn from_transact(
        legs: &[InterfaceTransfer],
        settlements: &'a [AccountView],
    ) -> Result<Self, ProgramError> {
        if legs.len() > MAX_LEGS {
            return Err(CustomRingError::InvalidInstructionData.into());
        }
        let mut flows = Self {
            settlements,
            ..Self::NONE
        };
        let mut offset = 0usize;
        for leg in legs {
            let group = settlements
                .get(offset..offset + leg.settlement_account_count())
                .ok_or(CustomRingError::InvalidInstructionData)?;
            let mint_at = match leg.mint_account_position() {
                Some(position) => u8::try_from(offset + position)
                    .map_err(|_| CustomRingError::InvalidInstructionData)?,
                None => SOL_LEG,
            };
            offset += group.len();
            flows.push(mint_at, leg.amount(), leg.is_deposit());
        }
        Ok(flows)
    }

    /// `settlements` are the asset groups after `[tree, depositor, ring_config, spp]`.
    #[inline(never)]
    pub fn from_ring_deposit(
        data: &RingDepositIxDataRef<'_>,
        settlements: &'a [AccountView],
    ) -> Result<Self, ProgramError> {
        // 1. Resolve deposit asset indices to their settlement mints.
        if data.assets.len() > MAX_DEPOSIT_ASSETS {
            return Err(CustomRingError::InvalidInstructionData.into());
        }
        let mut flows = Self {
            settlements,
            ..Self::NONE
        };
        let mut offset = 0usize;
        for kind in &data.assets {
            let (width, mint_at) = match kind {
                DepositAssetKind::Sol => (2, SOL_LEG),
                DepositAssetKind::Spl { .. } => {
                    let position = offset + 1;
                    if position >= settlements.len() {
                        return Err(CustomRingError::InvalidInstructionData.into());
                    }
                    (4, position as u8)
                }
            };
            offset += width;
            flows.push(mint_at, 0, true);
        }
        // 2. Aggregate every deposit entry into its asset's public flow.
        for entry in &data.deposits {
            let index = usize::from(entry.asset_index);
            if index >= flows.len {
                return Err(CustomRingError::InvalidInstructionData.into());
            }
            flows.amounts[index] = flows.amounts[index]
                .checked_add(entry.amount)
                .ok_or(ProgramError::ArithmeticOverflow)?;
        }
        Ok(flows)
    }

    fn push(&mut self, mint_at: u8, amount: u64, deposit: bool) {
        self.mint_at[self.len] = mint_at;
        self.amounts[self.len] = amount;
        if deposit {
            self.deposits |= 1 << self.len;
        }
        self.len += 1;
    }

    fn mint(&self, leg: usize) -> &'a Address {
        match self.mint_at[leg] {
            SOL_LEG => &SOL,
            at => self.settlements[usize::from(at)].address(),
        }
    }

    fn is_deposit(&self, leg: usize) -> bool {
        self.deposits & (1 << leg) != 0
    }

    fn first_leg(&self, mint: &Address) -> usize {
        (0..self.len)
            .find(|leg| self.mint(*leg) == mint)
            .unwrap_or(self.len)
    }

    fn earlier_withdrawal(&self, leg: usize) -> bool {
        (0..leg).any(|earlier| !self.is_deposit(earlier) && self.mint(earlier) == self.mint(leg))
    }

    fn sum(&self, mint: &Address, deposit: bool) -> Result<u64, ProgramError> {
        (0..self.len)
            .filter(|leg| self.mint(*leg) == mint && self.is_deposit(*leg) == deposit)
            .try_fold(0u64, |sum, leg| sum.checked_add(self.amounts[leg]))
            .ok_or(ProgramError::ArithmeticOverflow)
    }

    pub fn has_deposits(&self) -> bool {
        self.deposits != 0
    }

    pub fn withdrawals(
        &self,
    ) -> impl Iterator<Item = Result<(&'a Address, u64), ProgramError>> + '_ {
        (0..self.len)
            .filter(move |leg| !self.is_deposit(*leg) && !self.earlier_withdrawal(*leg))
            .map(move |leg| {
                let mint = self.mint(leg);
                self.sum(mint, false).map(|sum| (mint, sum))
            })
    }
}

/// A mint on several legs is counted once, each of its slots names one account.
#[inline(never)]
pub(crate) fn apply_spend_windows(
    program_id: &Address,
    windows: &mut [AccountView],
    legs: &PublicLegs,
) -> Result<(), ProgramError> {
    // 1. Require repeated legs of one mint to share the same canonical window account.
    for (leg, window) in windows.iter().enumerate() {
        let first = legs.first_leg(legs.mint(leg));
        if window.address() != windows[first].address() {
            return Err(CustomRingError::InvalidSpendWindow.into());
        }
    }
    // 2. Charge each mint once and commit its counters with the enclosing SPP settlement.
    let slot = Clock::get()?.slot;
    for (leg, window) in windows.iter_mut().enumerate() {
        let mint = legs.mint(leg);
        if legs.first_leg(mint) != leg {
            continue;
        }
        let Some(state) = load_spend_window(program_id, window, mint)?.map(|state| *state) else {
            continue;
        };
        if !window.is_writable() {
            return Err(CustomRingError::InvalidSpendWindow.into());
        }
        let state =
            advance_public_window(state, slot, legs.sum(mint, true)?, legs.sum(mint, false)?)?;
        let mut data = window.try_borrow_mut()?;
        *bytemuck::from_bytes_mut::<SpendWindow>(&mut data) = state;
    }
    Ok(())
}

fn advance_public_window(
    mut state: SpendWindow,
    slot: u64,
    deposited: u64,
    withdrawn: u64,
) -> Result<SpendWindow, ProgramError> {
    // 1. Reset only at a fixed slot boundary.
    let window_slots = state.window_slots();
    if window_slots == 0 {
        return Err(CustomRingError::InvalidSpendWindow.into());
    }
    let start = slot - slot % window_slots;
    if start != state.window_start_slot() {
        state.window_start_slot = start.to_le_bytes();
        state.deposited = [0; 8];
        state.withdrawn = [0; 8];
    }
    // 2. Apply the complete transaction flow before checking either directional cap.
    let deposited = state
        .deposited()
        .checked_add(deposited)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let withdrawn = state
        .withdrawn()
        .checked_add(withdrawn)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let capped = |total: u64, cap: u64| cap != 0 && total > cap;
    if capped(deposited, state.deposit_cap()) || capped(withdrawn, state.withdrawal_cap()) {
        return Err(CustomRingError::SpendWindowExceeded.into());
    }
    state.deposited = deposited.to_le_bytes();
    state.withdrawn = withdrawn.to_le_bytes();
    Ok(state)
}
