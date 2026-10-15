use custom_ring_interface::{CoSignScope, CustomRingError, KeyEscrow, RingProgramConfig};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;

use crate::instructions::{
    cosign::demanded_cosigner,
    deposit_audit::{verify_deposit_disclosure, AuditedDeposit},
    loader::{load, load_deposit_audit, load_escrow_root, validate_spp_program},
    public_legs::PublicLegs,
    shared::{cpi_spp, SppSigners},
    transact::Controls,
};

/// Deposit and merge routes sharing ring controls before unchanged SPP settlement.
#[derive(Clone, Copy)]
pub(crate) enum Forward {
    Deposit,
    AuditedDeposit,
    Merge,
}

impl Forward {
    #[inline(never)]
    pub fn process(
        self,
        program_id: &Address,
        accounts: &mut [AccountView],
        data: &[u8],
    ) -> ProgramResult {
        let mut iter = AccountIterator::new(accounts);
        let controls = Controls::next(&mut iter)?;
        let config = *load::<RingProgramConfig>(program_id, controls.config)?;
        let escrow = config.key_escrow();
        if matches!(self, Forward::Deposit) && escrow == KeyEscrow::Registry {
            return Err(CustomRingError::DepositAuditRequired.into());
        }
        let audited = match self {
            Forward::AuditedDeposit => Some(AuditedDeposit::parse(data)?),
            _ => None,
        };
        let data = audited.as_ref().map_or(data, |audited| audited.spp_data);
        if !matches!(self, Forward::Merge) {
            let audit = load_deposit_audit(program_id, iter.next_account("deposit_audit")?)?;
            if audit.is_some_and(|audit| audit.required == 1) && audited.is_none() {
                return Err(CustomRingError::DepositAuditRequired.into());
            }
        }
        let key_registry_root = match &audited {
            Some(audited) => load_escrow_root(
                program_id,
                escrow,
                audited.key_registry_root.as_ref(),
                &mut iter,
            )?,
            None => None,
        };
        let rest = iter.remaining_mut()?;
        let deposit = match self {
            Forward::Deposit | Forward::AuditedDeposit => Some(
                RingDepositIxDataRef::from_bytes(data.get(1..).unwrap_or_default())
                    .map_err(|_| CustomRingError::InvalidDepositData)?,
            ),
            Forward::Merge => None,
        };
        let leg_count = deposit.as_ref().map_or(0, |deposit| deposit.assets.len());
        if rest.len() < leg_count {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        let (windows, spp_accounts) = rest.split_at_mut(leg_count);
        validate_spp_program(spp_accounts)?;

        if let (Some(audited), Some(deposit)) = (&audited, &deposit) {
            let tree = spp_accounts
                .first()
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            verify_deposit_disclosure(
                program_id,
                tree.address(),
                &config.auditor_pubkey,
                key_registry_root.as_ref(),
                audited,
                deposit,
            )?;
        }
        let (classes, legs) = match &deposit {
            Some(deposit) => {
                let settlements = spp_accounts
                    .get(4..)
                    .ok_or(ProgramError::NotEnoughAccountKeys)?;
                (
                    CoSignScope::DEPOSITS,
                    PublicLegs::from_ring_deposit(deposit, settlements)?,
                )
            }
            None => (CoSignScope::TRANSFERS, PublicLegs::NONE),
        };
        if let Some(expected) =
            demanded_cosigner(program_id, controls.cosigner_pda, classes, &legs)?
        {
            if !controls.cosigner.is_signer() {
                return Err(CustomRingError::MissingCoSigner.into());
            }
            if controls.cosigner.address() != &expected {
                return Err(CustomRingError::UnauthorizedCoSigner.into());
            }
        }
        legs.apply_windows(program_id, windows)?;

        // A failed settlement rolls the window counters back.
        cpi_spp(program_id, spp_accounts, data, SppSigners::RingAuth)
    }
}
