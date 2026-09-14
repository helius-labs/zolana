use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;
use zolana_ring_policy::VelocityMode;

use crate::{
    error::CustomRingError,
    instructions::{
        cosign::{require_cosigner, CoSignerRequirement},
        loader::{load_config, load_policy_config, validate_spp_program},
        policy_shared::require_entries_trees,
        public_legs::{apply_spend_windows, PublicLegs},
        shared::cpi_spp_signed,
    },
};

#[derive(Clone, Copy)]
pub(crate) enum Forward {
    Deposit,
    Merge,
}

impl Forward {
    /// The SPP tree the forward creates a note in.
    const fn destination_tree(self) -> core::ops::Range<usize> {
        match self {
            Forward::Deposit => 0..1,
            Forward::Merge => 1..2,
        }
    }
}

/// Applies ring controls to proofless deposits and owner-preserving SPP merges.
#[inline(never)]
pub fn process_spp_forward_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
    kind: Forward,
) -> ProgramResult {
    // 1. Select controls from the ring config before separating the SPP account list.
    let mut iter = AccountIterator::new(accounts);
    let config_account = iter.next_account("config")?;
    let cosigner_account = iter.next_account("cosigner_pda")?;
    let cosigner = iter.next_account("cosigner")?;
    let has_policy = { load_config(program_id, config_account)?.has_policy };
    let policy_config_account = if has_policy != 0 {
        Some(iter.next_account("policy_config")?)
    } else {
        None
    };
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
    // 2. Keep windowed-ring outputs in the tree that also holds their spend records.
    if let Some(policy_config_account) = policy_config_account {
        let policy = load_policy_config(program_id, policy_config_account)?;
        // A windowed ring creates notes only in the entries tree, a merge input may be foreign.
        if let VelocityMode::PerWindow { .. } = policy.rules.velocity_mode() {
            let trees = spp_accounts
                .get(kind.destination_tree())
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            require_entries_trees(trees, &policy.entries_tree)?;
        }
    }
    // 3. Enforce scoped approval and public deposit caps without charging merge change.
    let demand = match &deposit {
        Some(deposit) => {
            let settlements = spp_accounts
                .get(4..)
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            CoSignerRequirement::deposit(PublicLegs::from_ring_deposit(deposit, settlements)?)
        }
        None => CoSignerRequirement::TRANSFER,
    };
    require_cosigner(program_id, cosigner_account, cosigner, &demand)?;
    apply_spend_windows(program_id, windows, &demand.legs)?;
    // 4. Delegate settlement and merge conservation to SPP with no namespace signature.
    cpi_spp_signed(program_id, spp_accounts, data, None)
}
