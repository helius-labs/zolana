use custom_ring_interface::{CoSignScope, CustomRingError};
use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_interface::{
    instruction::instruction_data::{
        deposit::{DepositAssetKind, RingDepositIxDataRef, MAX_DEPOSIT_ASSETS},
        transact::InterfaceTransfer,
    },
    MAX_INTERFACE_TRANSFERS,
};

use super::shared::check_funding_signer;

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

/// Public value entering or leaving SPP, read by the co-signer thresholds.
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
    /// Check each deposit's actual funding principal before the ring PDA signs the SPP CPI.
    #[inline(never)]
    pub fn from_transact(
        legs: &[InterfaceTransfer],
        settlements: &'a [AccountView],
    ) -> Result<Self, ProgramError> {
        let invalid = CustomRingError::InvalidSettlementAccounts;
        if legs.len() > MAX_LEGS {
            return Err(CustomRingError::TooManyPublicLegs.into());
        }
        let mut flows = Self::NONE;
        let mut offset = 0usize;
        for leg in legs {
            let group = settlements
                .get(offset..offset + leg.settlement_account_count())
                .ok_or(invalid)?;
            match leg {
                InterfaceTransfer::SolDeposit { .. } => check_funding_signer(group, 1)?,
                InterfaceTransfer::SplDeposit { .. } => check_funding_signer(group, 2)?,
                _ => {}
            }
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
        let invalid = CustomRingError::InvalidSettlementAccounts;
        if data.assets.len() > MAX_DEPOSIT_ASSETS {
            return Err(CustomRingError::TooManyPublicLegs.into());
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
                .ok_or(CustomRingError::InvalidDepositData)?;
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

    fn sum(&self, mint: &Address, deposit: bool) -> Result<u64, ProgramError> {
        self.legs()
            .iter()
            .filter(|leg| leg.mint == mint && leg.deposit == deposit)
            .try_fold(0u64, |sum, leg| sum.checked_add(leg.amount))
            .ok_or(ProgramError::ArithmeticOverflow)
    }
}
