use custom_ring_interface::{
    CoSigner, SetCoSignerIxData, WithdrawalThreshold, COSIGN_SCOPE_MASK, MAX_CO_SIGNER_THRESHOLDS,
};
use pinocchio::{
    cpi::{Seed, Signer},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_authorized_config, load_cosigner},
        shared::PdaCheck,
    },
    state::CoSignerInitParams,
};

/// Creates the co-signer at the canonical bump or replaces it in place.
#[inline(never)]
pub fn process_set_cosigner_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // 1. Admit one unambiguous scope and one withdrawal threshold per mint.
    let SetCoSignerIxData {
        signer,
        scope,
        thresholds,
    } = wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;
    if scope == 0 || scope & !COSIGN_SCOPE_MASK != 0 {
        return Err(CustomRingError::InvalidCoSignerScope.into());
    }
    if thresholds.len() > MAX_CO_SIGNER_THRESHOLDS {
        return Err(CustomRingError::InvalidCoSignerThresholds.into());
    }
    let mut rows = [WithdrawalThreshold {
        mint: Address::new_from_array([0; 32]),
        amount: [0; 8],
    }; MAX_CO_SIGNER_THRESHOLDS];
    for (index, threshold) in thresholds.iter().enumerate() {
        if thresholds[..index]
            .iter()
            .any(|earlier| earlier.mint == threshold.mint)
        {
            return Err(CustomRingError::InvalidCoSignerThresholds.into());
        }
        rows[index] = WithdrawalThreshold {
            mint: Address::new_from_array(threshold.mint),
            amount: threshold.amount.to_le_bytes(),
        };
    }

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_account("config")?;
    let cosigner_account = iter.next_mut("cosigner")?;
    let system_program = iter.next_account("system_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    // 2. Let only the config authority replace the approval requirement.
    load_authorized_config(program_id, config_account, authority)?;

    // 3. Replace the canonical control account or initialize it on first configuration.
    let existing = load_cosigner(program_id, cosigner_account)?.map(|cosigner| cosigner.bump);
    let params = |bump| CoSignerInitParams {
        signer: Address::new_from_array(signer),
        scope,
        thresholds: rows,
        threshold_count: thresholds.len() as u8,
        bump,
    };
    if let Some(bump) = existing {
        let mut data = cosigner_account.try_borrow_mut()?;
        *bytemuck::from_bytes_mut::<CoSigner>(&mut data) = params(bump).value();
        return Ok(());
    }
    let bump = PdaCheck {
        program_id,
        address: cosigner_account.address(),
        seeds: &[CoSigner::SEED],
        mismatch: CustomRingError::InvalidCoSigner,
    }
    .verify()?;
    let bump_seed = [bump];
    let seeds = [Seed::from(CoSigner::SEED), Seed::from(bump_seed.as_ref())];
    pinocchio_system::create_account_with_minimum_balance_signed(
        cosigner_account,
        CoSigner::SIZE,
        program_id,
        payer,
        None,
        &[Signer::from(seeds.as_ref())],
    )?;
    params(bump).init(cosigner_account)
}
