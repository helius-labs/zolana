use custom_ring_interface::{
    CoSignScope, CustomRingError, CustomRingMergeIxDataRef, MemberRegistryRoot, RingMode,
};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    instruction::instruction_data::deposit::RingDepositIxDataRef, RING_DEPOSIT_ACCOUNT_PREFIX_LEN,
    RING_DEPOSIT_DEPOSITOR_INDEX, RING_MERGE_PAYER_INDEX,
};

use crate::instructions::{
    cosign::demanded_cosigner,
    deposit_audit::{verify_deposit_disclosure, AuditedDeposit},
    loader::{
        load_audited_config, load_deposit_audit, load_escrow_root, load_registry_root,
        validate_spp_program,
    },
    merge_disclosure::verify_merge_disclosure,
    public_legs::PublicLegs,
    shared::{cpi_spp, verify_pda},
    transact::Controls,
};

/// Deposit and merge routes sharing ring controls before SPP settlement.
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
        if matches!(self, Forward::Deposit) {
            return Err(CustomRingError::DepositAuditRequired.into());
        }
        let audited = match self {
            Forward::AuditedDeposit => Some(AuditedDeposit::parse(data)?),
            _ => None,
        };
        let data = audited.as_ref().map_or(data, |audited| audited.spp_data);
        let merge = if matches!(self, Forward::Merge) {
            let request = CustomRingMergeIxDataRef::from_bytes(
                data.get(1..)
                    .ok_or(CustomRingError::InvalidInstructionData)?,
            )
            .map_err(|_| CustomRingError::InvalidInstructionData)?;
            Some(request)
        } else {
            None
        };
        if matches!(self, Forward::AuditedDeposit) {
            // Keep validating the established account slot. Its stored bit can
            // no longer waive the mandatory disclosure proof.
            let _audit = load_deposit_audit(program_id, iter.next_account("deposit_audit")?)?;
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
        let merge_root = if let Some(merge) = &merge {
            let account = iter.next_account("member_registry_root")?;
            verify_pda(
                program_id,
                account.address(),
                &[MemberRegistryRoot::SEED],
                CustomRingError::InvalidMemberRegistryRoot,
            )?;
            Some(load_registry_root(
                program_id,
                account,
                merge.registry_root_index,
            )?)
        } else {
            None
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
                    .any(|entry| entry.ring_data_hash != &[0; 32])
            })
        {
            return Err(CustomRingError::InvalidAnonymousOutput.into());
        }

        let (classes, legs) = match &deposit {
            Some(deposit) => {
                let settlements = spp_accounts
                    .get(RING_DEPOSIT_ACCOUNT_PREFIX_LEN..)
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
        // SPP debits the depositor on deposits and the payer on merges.
        let funding_signer = match self {
            Self::Deposit | Self::AuditedDeposit => RING_DEPOSIT_DEPOSITOR_INDEX,
            Self::Merge => RING_MERGE_PAYER_INDEX,
        };
        let funder = spp_accounts
            .get(funding_signer)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        if !funder.is_signer() {
            return Err(CustomRingError::MissingFundingSigner.into());
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
        if let (Some(merge), Some(root)) = (&merge, &merge_root) {
            verify_merge_disclosure(program_id, &config, merge, root)?;
        }
        // SPP waives the escrow key only under the flag, set from the ring's own mode.
        let forwarded_merge = merge.zip(merge_root).map(|(merge, root)| {
            let mut forwarded = Vec::with_capacity(1 + 32 + 32 + 1 + merge.merge_body.len());
            forwarded.push(data[0]);
            forwarded.extend_from_slice(merge.output_ring_data_hash);
            forwarded.extend_from_slice(&root);
            forwarded.push(u8::from(anonymous));
            forwarded.extend_from_slice(merge.merge_body);
            forwarded
        });
        cpi_spp(
            program_id,
            spp_accounts,
            forwarded_merge.as_deref().unwrap_or(data),
        )
    }
}
