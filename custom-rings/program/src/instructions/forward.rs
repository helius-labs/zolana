use custom_ring_interface::{CoSignScope, CustomRingError, RingMode};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;

use crate::instructions::{
    cosign::demanded_cosigner,
    deposit_audit::{verify_deposit_disclosure, AuditedDeposit},
    loader::{load_audited_config, load_deposit_audit, load_escrow_root, validate_spp_program},
    public_legs::PublicLegs,
    shared::cpi_spp,
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
        let config = load_audited_config(program_id, controls.config)?;
        let anonymous = config.mode == RingMode::Anonymous;
        if matches!(self, Forward::Deposit) && config.mode != RingMode::Off {
            return Err(CustomRingError::DepositAuditRequired.into());
        }
        // A merge has no auditor proof to disclose an anonymous balance change.
        if matches!(self, Forward::Merge) && anonymous {
            return Err(CustomRingError::InvalidMergeDisclosure.into());
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
        let member_registry_root = match &audited {
            Some(audited) => load_escrow_root(
                program_id,
                config.mode,
                audited.registry_root_index,
                &mut iter,
            )?,
            None => None,
        };
        let spp_accounts = iter.remaining_mut()?;
        let deposit = match self {
            Forward::Deposit | Forward::AuditedDeposit => Some(
                RingDepositIxDataRef::from_bytes(data.get(1..).unwrap_or_default())
                    .map_err(|_| CustomRingError::InvalidDepositData)?,
            ),
            Forward::Merge => None,
        };
        validate_spp_program(spp_accounts)?;
        // Public deposit fields in an anonymous ring would name the recipient.
        if anonymous
            && deposit.as_ref().is_some_and(|deposit| {
                deposit
                    .deposits
                    .iter()
                    .any(|entry| entry.view_tag != &[0; 32] || entry.ring_data_hash != &[0; 32])
            })
        {
            return Err(CustomRingError::InvalidAnonymousOutput.into());
        }

        if let (Some(audited), Some(deposit)) = (&audited, &deposit) {
            let tree = spp_accounts
                .first()
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            verify_deposit_disclosure(
                program_id,
                tree.address(),
                &config,
                member_registry_root.as_ref(),
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
        cpi_spp(program_id, spp_accounts, data)
    }
}
