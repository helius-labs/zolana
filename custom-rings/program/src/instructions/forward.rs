use custom_ring_interface::KeyEscrow;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;

use crate::{
    error::CustomRingError,
    instructions::{
        cosign::{require_cosigner, CoSignerRequirement},
        deposit_audit::{AuditedDeposit, DepositVerification},
        key_escrow::EscrowRoot,
        loader::{load_config, load_deposit_audit, validate_spp_program},
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
        let config = *load_config(program_id, config_account)?;
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
            let audit_account = iter.next_account("deposit_audit")?;
            let audit = load_deposit_audit(program_id, audit_account)?;
            if audit.as_deref().is_some_and(|audit| audit.required == 1) && audited.is_none() {
                return Err(CustomRingError::DepositAuditRequired.into());
            }
        }
        let key_registry_root = match &audited {
            Some(audited) => EscrowRoot {
                program_id,
                escrow,
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
        let leg_count = deposit.as_ref().map_or(0, |deposit| deposit.assets.len());
        if rest.len() < leg_count {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        let (windows, spp_accounts) = rest.split_at_mut(leg_count);
        validate_spp_program(spp_accounts)?;
        // 2. Verify supplied disclosure against the actual destination, deposit
        // bytes and escrow registry root, then apply public approval and caps.
        if let Some(audited) = &audited {
            let tree = spp_accounts
                .first()
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            DepositVerification {
                program_id,
                tree: tree.address(),
                auditor_pk: &config.auditor_pubkey,
                key_registry_root: key_registry_root.as_ref(),
                audited,
                deposit: deposit
                    .as_ref()
                    .ok_or(CustomRingError::InvalidInstructionData)?,
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
