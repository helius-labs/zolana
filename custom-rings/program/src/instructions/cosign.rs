use custom_ring_interface::{COSIGN_DEPOSITS, COSIGN_TRANSFERS, COSIGN_WITHDRAWALS};
use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_interface::{
    instruction::instruction_data::transact::InterfaceTransfer, MAX_INTERFACE_TRANSFERS,
};

use crate::{error::CustomRingError, instructions::loader::load_cosigner};

/// Withdrawal legs of one transaction summed per mint, SOL under the zero address.
pub(crate) struct Withdrawals {
    sums: [(Address, u64); MAX_INTERFACE_TRANSFERS],
    len: usize,
}

impl Withdrawals {
    pub const NONE: Self = Self {
        sums: [(Address::new_from_array([0; 32]), 0); MAX_INTERFACE_TRANSFERS],
        len: 0,
    };

    /// `settlements` are the trailing settlement groups of the forwarded list.
    pub fn from_legs(
        legs: &[InterfaceTransfer],
        settlements: &[AccountView],
    ) -> Result<Self, ProgramError> {
        if legs.len() > MAX_INTERFACE_TRANSFERS {
            return Err(CustomRingError::InvalidInstructionData.into());
        }
        let mut sums = Self::NONE;
        let mut offset = 0usize;
        for leg in legs {
            let group = settlements
                .get(offset..offset + leg.settlement_account_count())
                .ok_or(CustomRingError::InvalidInstructionData)?;
            offset += leg.settlement_account_count();
            if leg.is_deposit() {
                continue;
            }
            let mint = match leg.mint_account_position() {
                Some(position) => *group[position].address(),
                None => Address::new_from_array([0; 32]),
            };
            sums.add(mint, leg.amount())?;
        }
        Ok(sums)
    }

    fn add(&mut self, mint: Address, amount: u64) -> Result<(), ProgramError> {
        let slot = match self.sums[..self.len]
            .iter()
            .position(|(known, _)| *known == mint)
        {
            Some(index) => index,
            None => {
                self.sums[self.len] = (mint, 0);
                self.len += 1;
                self.len - 1
            }
        };
        self.sums[slot].1 = self.sums[slot]
            .1
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

pub(crate) struct Demand {
    pub classes: u8,
    pub withdrawals: Withdrawals,
}

impl Demand {
    pub const TRANSFER: Self = Self {
        classes: COSIGN_TRANSFERS,
        withdrawals: Withdrawals::NONE,
    };

    pub const DEPOSIT: Self = Self {
        classes: COSIGN_DEPOSITS,
        withdrawals: Withdrawals::NONE,
    };

    /// A transact is a transfer, each public leg adds its class.
    pub fn transact(
        legs: &[InterfaceTransfer],
        settlements: &[AccountView],
    ) -> Result<Self, ProgramError> {
        let withdrawals = Withdrawals::from_legs(legs, settlements)?;
        let mut classes = COSIGN_TRANSFERS;
        if legs.iter().any(|leg| leg.is_deposit()) {
            classes |= COSIGN_DEPOSITS;
        }
        if !withdrawals.is_empty() {
            classes |= COSIGN_WITHDRAWALS;
        }
        Ok(Self {
            classes,
            withdrawals,
        })
    }
}

/// No account at the canonical address demands nothing.
pub(crate) fn require_cosigner(
    program_id: &Address,
    cosigner_account: &AccountView,
    signer: &AccountView,
    demand: &Demand,
) -> Result<(), ProgramError> {
    let Some(cosigner) = load_cosigner(program_id, cosigner_account)? else {
        return Ok(());
    };
    let in_scope = cosigner.scope & demand.classes & (COSIGN_TRANSFERS | COSIGN_DEPOSITS) != 0
        || (cosigner.scope & demand.classes & COSIGN_WITHDRAWALS != 0
            && demand.withdrawals.sums[..demand.withdrawals.len]
                .iter()
                .any(|(mint, sum)| cosigner.threshold(mint).is_none_or(|limit| *sum > limit)));
    if !in_scope {
        return Ok(());
    }
    if !signer.is_signer() {
        return Err(CustomRingError::MissingCoSigner.into());
    }
    if signer.address() != &cosigner.signer {
        return Err(CustomRingError::UnauthorizedCoSigner.into());
    }
    Ok(())
}
