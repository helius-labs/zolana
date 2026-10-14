use core::num::NonZeroU64;

use custom_ring_interface::{CoSignScope, CustomRingError, FixedWindow, SpendWindow};
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

use crate::instructions::loader::load_spend_window_mut;

const SOL: Address = Address::new_from_array([0; 32]);
const MAX_LEGS: usize = if MAX_INTERFACE_TRANSFERS > MAX_DEPOSIT_ASSETS {
    MAX_INTERFACE_TRANSFERS
} else {
    MAX_DEPOSIT_ASSETS
};

/// One public settlement amount, its mint read from the actual settlement accounts.
#[derive(Clone, Copy)]
struct Leg<'a> {
    mint: &'a Address,
    amount: u64,
    deposit: bool,
}

/// Public value entering or leaving SPP, shared by co-signer thresholds and
/// ring-wide mint caps.
pub(crate) struct PublicLegs<'a> {
    legs: [Leg<'a>; MAX_LEGS],
    len: usize,
}

impl<'a> PublicLegs<'a> {
    pub const NONE: Self = Self {
        legs: [Leg {
            mint: &SOL,
            amount: 0,
            deposit: true,
        }; MAX_LEGS],
        len: 0,
    };

    /// `settlements` are the trailing settlement groups of a transact's forwarded list.
    #[inline(never)]
    pub fn from_transact(
        legs: &[InterfaceTransfer],
        settlements: &'a [AccountView],
    ) -> Result<Self, ProgramError> {
        let invalid = CustomRingError::InvalidInstructionData;
        if legs.len() > MAX_LEGS {
            return Err(invalid.into());
        }
        let mut flows = Self::NONE;
        let mut offset = 0usize;
        for leg in legs {
            let group = settlements
                .get(offset..offset + leg.settlement_account_count())
                .ok_or(invalid)?;
            let mint = match leg.mint_account_position() {
                Some(position) => group.get(position).ok_or(invalid)?.address(),
                None => &SOL,
            };
            offset += group.len();
            flows.push(mint, leg.amount(), leg.is_deposit());
        }
        Ok(flows)
    }

    /// `settlements` are the asset groups after `[tree, depositor, ring_config, spp]`.
    #[inline(never)]
    pub fn from_ring_deposit(
        data: &RingDepositIxDataRef<'_>,
        settlements: &'a [AccountView],
    ) -> Result<Self, ProgramError> {
        let invalid = CustomRingError::InvalidInstructionData;
        if data.assets.len() > MAX_DEPOSIT_ASSETS {
            return Err(invalid.into());
        }
        let mut flows = Self::NONE;
        let mut offset = 0usize;
        for kind in &data.assets {
            let (width, mint) = match kind {
                DepositAssetKind::Sol => (2, &SOL),
                DepositAssetKind::Spl { .. } => {
                    (4, settlements.get(offset + 1).ok_or(invalid)?.address())
                }
            };
            offset += width;
            flows.push(mint, 0, true);
        }
        for entry in &data.deposits {
            let leg = flows.legs[..flows.len]
                .get_mut(usize::from(entry.asset_index))
                .ok_or(invalid)?;
            leg.amount = leg
                .amount
                .checked_add(entry.amount)
                .ok_or(ProgramError::ArithmeticOverflow)?;
        }
        Ok(flows)
    }

    /// A transact is a transfer, each public leg adds its class.
    pub fn classes(&self) -> CoSignScope {
        let mut classes = CoSignScope::TRANSFERS;
        if self.has_deposits() {
            classes = classes | CoSignScope::DEPOSITS;
        }
        if self.withdrawals().next().is_some() {
            classes = classes | CoSignScope::WITHDRAWALS;
        }
        classes
    }

    pub fn has_deposits(&self) -> bool {
        self.legs().iter().any(|leg| leg.deposit)
    }

    /// Each withdrawn mint once, with its total.
    pub fn withdrawals(
        &self,
    ) -> impl Iterator<Item = Result<(&'a Address, u64), ProgramError>> + '_ {
        let legs = self.legs();
        legs.iter()
            .enumerate()
            .filter(move |(index, leg)| {
                !leg.deposit
                    && !legs[..*index]
                        .iter()
                        .any(|earlier| !earlier.deposit && earlier.mint == leg.mint)
            })
            .map(|(_, leg)| self.sum(leg.mint, false).map(|sum| (leg.mint, sum)))
    }

    /// Charges each mint's window once, every leg of the mint names the same slot.
    #[inline(never)]
    pub fn apply_windows(
        &self,
        program_id: &Address,
        windows: &mut [AccountView],
    ) -> ProgramResult {
        // 1. Repeated mint legs must name the same window account.
        for (leg, window) in windows.iter().enumerate() {
            if window.address() != windows[self.first_leg(leg)].address() {
                return Err(CustomRingError::InvalidSpendWindow.into());
            }
        }
        // 2. Charge each mint's aggregate flows to its canonical window once.
        let slot = Clock::get()?.slot;
        for (leg, window) in windows.iter_mut().enumerate() {
            if self.first_leg(leg) != leg {
                continue;
            }
            let mint = self.legs[leg].mint;
            let writable = window.is_writable();
            let Some(mut state) = load_spend_window_mut(program_id, window, mint)? else {
                continue;
            };
            if !writable {
                return Err(CustomRingError::InvalidSpendWindow.into());
            }
            charge(
                &mut state,
                slot,
                self.sum(mint, true)?,
                self.sum(mint, false)?,
            )?;
        }
        Ok(())
    }

    fn legs(&self) -> &[Leg<'a>] {
        &self.legs[..self.len]
    }

    fn push(&mut self, mint: &'a Address, amount: u64, deposit: bool) {
        self.legs[self.len] = Leg {
            mint,
            amount,
            deposit,
        };
        self.len += 1;
    }

    fn first_leg(&self, leg: usize) -> usize {
        let mint = self.legs[leg].mint;
        (0..leg)
            .find(|earlier| self.legs[*earlier].mint == mint)
            .unwrap_or(leg)
    }

    fn sum(&self, mint: &Address, deposit: bool) -> Result<u64, ProgramError> {
        self.legs()
            .iter()
            .filter(|leg| leg.mint == mint && leg.deposit == deposit)
            .try_fold(0u64, |sum, leg| sum.checked_add(leg.amount))
            .ok_or(ProgramError::ArithmeticOverflow)
    }
}

/// The whole transaction lands before either cap is checked, counters reset at
/// each window start.
fn charge(state: &mut SpendWindow, slot: u64, deposited: u64, withdrawn: u64) -> ProgramResult {
    let window = FixedWindow {
        slots: NonZeroU64::new(state.window_slots()).ok_or(CustomRingError::InvalidSpendWindow)?,
    };
    let start = window.start(slot);
    if start != state.window_start_slot() {
        state.window_start_slot = start.to_le_bytes();
        state.deposited = [0; 8];
        state.withdrawn = [0; 8];
    }
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
    Ok(())
}
