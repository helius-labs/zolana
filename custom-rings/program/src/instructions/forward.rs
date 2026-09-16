use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;
use zolana_ring_policy::VelocityMode;

use crate::{
    error::CustomRingError,
    instructions::{
        cosign::CoSignerRequirement,
        deposit_audit::{AuditedDeposit, DepositVerification},
        loader::{load_config, load_deposit_audit, load_policy_config, validate_spp_program},
        policy_shared::require_entries_trees,
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
    /// The SPP tree the forward creates a note in.
    const fn destination_tree(self) -> core::ops::Range<usize> {
        match self {
            Forward::Deposit | Forward::AuditedDeposit => 0..1,
            Forward::Merge => 1..2,
        }
    }

    #[inline(never)]
    pub fn process(
        self,
        program_id: &Address,
        accounts: &mut [AccountView],
        data: &[u8],
    ) -> ProgramResult {
        // 1. Load ring controls and require disclosure when the deposit setting
        // demands it.
        let mut iter = AccountIterator::new(accounts);
        let config_account = iter.next_account("config")?;
        let cosigner_account = iter.next_account("cosigner_pda")?;
        let cosigner = iter.next_account("cosigner")?;
        let config = *load_config(program_id, config_account)?;
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
        let policy_config_account = if config.has_policy != 0 {
            Some(iter.next_account("policy_config")?)
        } else {
            None
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
        // 2. Verify supplied disclosure against the actual destination and
        // deposit bytes.
        if let Some(audited) = &audited {
            let tree = spp_accounts
                .first()
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            DepositVerification {
                program_id,
                tree: tree.address(),
                auditor_pk: &config.auditor_pubkey,
                audited,
                deposit: deposit
                    .as_ref()
                    .ok_or(CustomRingError::InvalidInstructionData)?,
            }
            .verify()?;
        }
        // 3. Confine windowed outputs to the entries tree and apply public
        // approval and caps.
        if let Some(policy_config_account) = policy_config_account {
            let policy = load_policy_config(program_id, policy_config_account)?;
            // A windowed ring creates notes only in the entries tree, a merge input may be foreign.
            if let VelocityMode::PerWindow { .. } = policy.rules.velocity_mode() {
                let trees = spp_accounts
                    .get(self.destination_tree())
                    .ok_or(ProgramError::NotEnoughAccountKeys)?;
                require_entries_trees(trees, &policy.entries_tree)?;
            }
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
        if let Some(expected) = demand.demanded_signer(program_id, cosigner_account)? {
            if !cosigner.is_signer() {
                return Err(CustomRingError::MissingCoSigner.into());
            }
            if cosigner.address() != &expected {
                return Err(CustomRingError::UnauthorizedCoSigner.into());
            }
        }
        demand.legs.apply_windows(program_id, windows)?;
        // 4. Authorize SPP settlement, any failure rolls back the public window
        // counters.
        cpi_spp_signed(program_id, spp_accounts, data, SppSigners::RingAuth)
    }
}
