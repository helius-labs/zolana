use core::num::NonZeroU64;

use custom_ring_interface::{FixedWindow, SpendWindow};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_interface::{
    instruction::instruction_data::{
        deposit::{DepositAssetKind, RingDepositIxDataRef, MAX_DEPOSIT_ASSETS},
        transact::InterfaceTransfer,
    },
    MAX_INTERFACE_TRANSFERS,
};

use crate::{error::CustomRingError, instructions::loader::load_spend_window_mut};

const SOL: Address = Address::new_from_array([0; 32]);
const MAX_LEGS: usize = if MAX_INTERFACE_TRANSFERS > MAX_DEPOSIT_ASSETS {
    MAX_INTERFACE_TRANSFERS
} else {
    MAX_DEPOSIT_ASSETS
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    Deposit,
    Withdrawal,
}

#[derive(Clone, Copy)]
enum LegMint {
    Sol,
    /// Index of the mint account inside the settlement groups.
    Settlement(u8),
}

#[derive(Clone, Copy)]
struct Leg {
    mint: LegMint,
    amount: u64,
    direction: Direction,
}

impl Leg {
    const EMPTY: Self = Self {
        mint: LegMint::Sol,
        amount: 0,
        direction: Direction::Deposit,
    };
}

pub(crate) struct PublicLegs<'a> {
    settlements: &'a [AccountView],
    legs: [Leg; MAX_LEGS],
    len: usize,
}

impl<'a> PublicLegs<'a> {
    pub const NONE: Self = Self {
        settlements: &[],
        legs: [Leg::EMPTY; MAX_LEGS],
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
            let mint = match leg.mint_account_position() {
                Some(position) => LegMint::Settlement(
                    u8::try_from(offset + position)
                        .map_err(|_| CustomRingError::InvalidInstructionData)?,
                ),
                None => LegMint::Sol,
            };
            offset += group.len();
            let direction = if leg.is_deposit() {
                Direction::Deposit
            } else {
                Direction::Withdrawal
            };
            flows.push(Leg {
                mint,
                amount: leg.amount(),
                direction,
            });
        }
        Ok(flows)
    }

    /// `settlements` are the asset groups after `[tree, depositor, ring_config, spp]`.
    #[inline(never)]
    pub fn from_ring_deposit(
        data: &RingDepositIxDataRef<'_>,
        settlements: &'a [AccountView],
    ) -> Result<Self, ProgramError> {
        if data.assets.len() > MAX_DEPOSIT_ASSETS {
            return Err(CustomRingError::InvalidInstructionData.into());
        }
        let mut flows = Self {
            settlements,
            ..Self::NONE
        };
        let mut offset = 0usize;
        for kind in &data.assets {
            let (width, mint) = match kind {
                DepositAssetKind::Sol => (2, LegMint::Sol),
                DepositAssetKind::Spl { .. } => {
                    let position = offset + 1;
                    if position >= settlements.len() {
                        return Err(CustomRingError::InvalidInstructionData.into());
                    }
                    let at = u8::try_from(position)
                        .map_err(|_| CustomRingError::InvalidInstructionData)?;
                    (4, LegMint::Settlement(at))
                }
            };
            offset += width;
            flows.push(Leg {
                mint,
                amount: 0,
                direction: Direction::Deposit,
            });
        }
        for entry in &data.deposits {
            let leg = flows
                .legs
                .get_mut(..flows.len)
                .and_then(|legs| legs.get_mut(usize::from(entry.asset_index)))
                .ok_or(CustomRingError::InvalidInstructionData)?;
            leg.amount = leg
                .amount
                .checked_add(entry.amount)
                .ok_or(ProgramError::ArithmeticOverflow)?;
        }
        Ok(flows)
    }

    pub fn has_deposits(&self) -> bool {
        self.legs[..self.len]
            .iter()
            .any(|leg| leg.direction == Direction::Deposit)
    }

    pub fn withdrawals(
        &self,
    ) -> impl Iterator<Item = Result<(&'a Address, u64), ProgramError>> + '_ {
        (0..self.len)
            .filter(move |leg| {
                self.legs[*leg].direction == Direction::Withdrawal && !self.earlier_withdrawal(*leg)
            })
            .map(move |leg| {
                let mint = self.mint(leg);
                self.sum(mint, Direction::Withdrawal).map(|sum| (mint, sum))
            })
    }

    /// A mint on several legs is counted once, each of its slots names one account.
    #[inline(never)]
    pub fn apply_windows(
        &self,
        program_id: &Address,
        windows: &mut [AccountView],
    ) -> ProgramResult {
        for (leg, window) in windows.iter().enumerate() {
            if window.address() != windows[self.first_leg(leg)].address() {
                return Err(CustomRingError::InvalidSpendWindow.into());
            }
        }
        let slot = Clock::get()?.slot;
        for (leg, window) in windows.iter_mut().enumerate() {
            if self.first_leg(leg) != leg {
                continue;
            }
            let mint = self.mint(leg);
            let writable = window.is_writable();
            let Some(mut state) = load_spend_window_mut(program_id, window, mint)? else {
                continue;
            };
            if !writable {
                return Err(CustomRingError::InvalidSpendWindow.into());
            }
            WindowCharge {
                slot,
                deposited: self.sum(mint, Direction::Deposit)?,
                withdrawn: self.sum(mint, Direction::Withdrawal)?,
            }
            .apply(&mut state)?;
        }
        Ok(())
    }

    fn push(&mut self, leg: Leg) {
        self.legs[self.len] = leg;
        self.len += 1;
    }

    fn mint(&self, leg: usize) -> &'a Address {
        match self.legs[leg].mint {
            LegMint::Sol => &SOL,
            LegMint::Settlement(at) => self.settlements[usize::from(at)].address(),
        }
    }

    fn first_leg(&self, leg: usize) -> usize {
        (0..leg)
            .find(|earlier| self.mint(*earlier) == self.mint(leg))
            .unwrap_or(leg)
    }

    fn earlier_withdrawal(&self, leg: usize) -> bool {
        (0..leg).any(|earlier| {
            self.legs[earlier].direction == Direction::Withdrawal
                && self.mint(earlier) == self.mint(leg)
        })
    }

    fn sum(&self, mint: &Address, direction: Direction) -> Result<u64, ProgramError> {
        (0..self.len)
            .filter(|leg| self.mint(*leg) == mint && self.legs[*leg].direction == direction)
            .try_fold(0u64, |sum, leg| sum.checked_add(self.legs[leg].amount))
            .ok_or(ProgramError::ArithmeticOverflow)
    }
}

/// The whole transaction flow lands before either directional cap is checked.
#[must_use]
struct WindowCharge {
    slot: u64,
    deposited: u64,
    withdrawn: u64,
}

impl WindowCharge {
    fn apply(self, state: &mut SpendWindow) -> ProgramResult {
        let window = FixedWindow {
            slots: NonZeroU64::new(state.window_slots())
                .ok_or(CustomRingError::InvalidSpendWindow)?,
        };
        let start = window.start(self.slot);
        if start != state.window_start_slot() {
            state.window_start_slot = start.to_le_bytes();
            state.deposited = [0; 8];
            state.withdrawn = [0; 8];
        }
        let deposited = state
            .deposited()
            .checked_add(self.deposited)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        let withdrawn = state
            .withdrawn()
            .checked_add(self.withdrawn)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        let capped = |total: u64, cap: u64| cap != 0 && total > cap;
        if capped(deposited, state.deposit_cap()) || capped(withdrawn, state.withdrawal_cap()) {
            return Err(CustomRingError::SpendWindowExceeded.into());
        }
        state.deposited = deposited.to_le_bytes();
        state.withdrawn = withdrawn.to_le_bytes();
        Ok(())
    }
}
