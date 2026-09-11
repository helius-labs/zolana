use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;

use crate::{
    error::CustomRingError,
    instructions::{
        cosign::{require_cosigner, Demand},
        loader::validate_spp_program,
        public_legs::{apply_spend_windows, PublicLegs},
        shared::cpi_spp_signed,
    },
};

#[derive(Clone, Copy)]
pub(crate) enum Forward {
    Deposit,
    Merge,
}

/// Forwards an SPP ring transition with the ring authority signature, the
/// co-signer prefix and one window slot per deposit asset stay behind.
#[inline(never)]
pub fn process_spp_forward_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
    kind: Forward,
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let cosigner_account = iter.next_account("cosigner_pda")?;
    let cosigner = iter.next_account("cosigner")?;
    let rest = iter.remaining_mut()?;
    let deposit = match kind {
        Forward::Deposit => Some(
            RingDepositIxDataRef::from_bytes(data.get(1..).unwrap_or_default())
                .map_err(|_| CustomRingError::InvalidInstructionData)?,
        ),
        Forward::Merge => None,
    };
    let leg_count = deposit.as_ref().map_or(0, |deposit| deposit.assets.len());
    if rest.len() < leg_count {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (windows, spp_accounts) = rest.split_at_mut(leg_count);
    validate_spp_program(spp_accounts)?;
    let demand = match &deposit {
        Some(deposit) => {
            let settlements = spp_accounts
                .get(4..)
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            Demand::deposit(PublicLegs::from_ring_deposit(deposit, settlements)?)
        }
        None => Demand::TRANSFER,
    };
    require_cosigner(program_id, cosigner_account, cosigner, &demand)?;
    apply_spend_windows(program_id, windows, &demand.legs)?;
    cpi_spp_signed(program_id, spp_accounts, data)
}
