use custom_ring_interface::{RingMode, VIEWING_PUBKEY_LEN};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use wincode::{config::DefaultConfig, SchemaRead};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::{
    deposit::RingDepositIxDataRef, merge_ring::MergeRingIxDataRef,
};

use crate::{
    error::CustomRingError,
    instructions::{
        cosign::{require_cosigner, CoSignerRequirement},
        deposit_audit::{AuditedDeposit, DepositVerification},
        key_escrow::EscrowRoot,
        loader::{load_audited_config, load_deposit_audit, validate_spp_program},
        public_legs::PublicLegs,
        shared::{cpi_spp_signed, SppSigners},
    },
};

/// Deposit and merge routes sharing ring controls before unchanged SPP
/// settlement.
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
        // 1. Load ring controls and require disclosure when the deposit setting
        // or key escrow demands it.
        let mut iter = AccountIterator::new(accounts);
        let config_account = iter.next_account("config")?;
        let cosigner_account = iter.next_account("cosigner_pda")?;
        let cosigner = iter.next_account("cosigner")?;
        let config = load_audited_config(program_id, config_account)?;
        let anonymous = config.mode == RingMode::Anonymous;
        if matches!(self, Forward::Deposit) && config.mode != RingMode::Off {
            return Err(CustomRingError::DepositAuditRequired.into());
        }
        if matches!(self, Forward::Merge) {
            check_merge_disclosure(data, anonymous.then_some(&config.auditor_pubkey))?;
        }
        let audited = match self {
            Forward::AuditedDeposit => Some(AuditedDeposit::parse(data)?),
            _ => None,
        };
        let data = audited.as_ref().map_or(data, |audited| audited.spp_data);
        if !matches!(self, Forward::Merge) {
            let audit_account = iter.next_account("deposit_audit")?;
            let audit = load_deposit_audit(program_id, audit_account)?;
            if audit.as_deref().is_some_and(|audit| audit.required == 1) && audited.is_none() {
                return Err(CustomRingError::DepositAuditRequired.into());
            }
        }
        let key_registry_root = match &audited {
            Some(audited) => EscrowRoot {
                program_id,
                mode: config.mode,
                index: audited.key_registry_root_index,
            }
            .load(&mut iter)?,
            None => None,
        };
        let rest = iter.remaining_mut()?;
        let deposit = match self {
            Forward::Deposit | Forward::AuditedDeposit => Some(
                RingDepositIxDataRef::from_bytes(data.get(1..).unwrap_or_default())
                    .map_err(|_| CustomRingError::InvalidInstructionData)?,
            ),
            Forward::Merge => None,
        };
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
        let leg_count = deposit.as_ref().map_or(0, |deposit| deposit.assets.len());
        if rest.len() < leg_count {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        let (windows, spp_accounts) = rest.split_at_mut(leg_count);
        validate_spp_program(spp_accounts)?;
        // 2. Verify supplied disclosure against the actual destination, deposit
        // bytes and escrow registry root, then apply public approval and caps.
        if let (Some(audited), Some(deposit)) = (&audited, &deposit) {
            let tree = spp_accounts
                .first()
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            DepositVerification {
                program_id,
                tree: tree.address(),
                auditor_pk: &config.auditor_pubkey,
                key_registry_root: key_registry_root.as_ref(),
                audited,
                deposit,
            }
            .verify()?;
        }
        let demand = match &deposit {
            Some(deposit) => {
                let settlements = spp_accounts
                    .get(4..)
                    .ok_or(ProgramError::NotEnoughAccountKeys)?;
                CoSignerRequirement::deposit(PublicLegs::from_ring_deposit(deposit, settlements)?)
            }
            None => CoSignerRequirement::TRANSFER,
        };
        require_cosigner(
            demand.demanded_signer(program_id, cosigner_account)?,
            cosigner,
        )?;
        demand.legs.apply_windows(program_id, windows)?;
        // 3. Authorize SPP settlement, any failure rolls back the public window
        // counters.
        cpi_spp_signed(program_id, spp_accounts, data, SppSigners::RingAuth)
    }
}

/// An anonymous ring merge carries the audited layout, the plain layout plus
/// the auditor key and its envelope. Any other ring forwards the plain layout.
fn check_merge_disclosure(
    data: &[u8],
    auditor_pk: Option<&[u8; VIEWING_PUBKEY_LEN]>,
) -> ProgramResult {
    let mut appended = data
        .get(1..)
        .ok_or(CustomRingError::InvalidInstructionData)?;
    <MergeRingIxDataRef<'_> as SchemaRead<'_, DefaultConfig>>::get(&mut appended)
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    let recipient = appended.get(..VIEWING_PUBKEY_LEN);
    match auditor_pk {
        Some(auditor_pk) if recipient == Some(auditor_pk.as_slice()) => Ok(()),
        None if appended.is_empty() => Ok(()),
        _ => Err(CustomRingError::InvalidMergeDisclosure.into()),
    }
}
