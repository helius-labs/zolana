//! Batch incarnation of create_escrow: same state, compose hub for proofs.

use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::{
    error::DynamicSwapError,
    instructions::{
        create_escrow::{
            CreateEscrowIxData, EscrowOpenPublicInput, CREATED_AT_SLOT_TOLERANCE,
            ORDER_OUTPUT_INDEX, RESERVATION_OUTPUT_INDEX,
        },
        shared::{
            compose_ix_data, cpi_spp_compose_signed, escrow_authority_owner_hash, verify_pda,
            CreatePdaAccount,
        },
    },
    state::{discriminator::ESCROW, load_pair, Escrow},
};

#[inline(never)]
#[profile]
pub fn process_create_escrow_batch_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer_mut("authority")?;
    let owner = iter.next_signer("owner")?;
    let pair_account = iter.next_account("pair")?;
    let escrow_account = iter.next_mut("escrow")?;
    let system_program = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let CreateEscrowIxData {
        proof,
        created_at,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let pair = load_pair(pair_account)?;
    if &pair.authority != authority.address() {
        return Err(DynamicSwapError::Unauthorized.into());
    }
    let pair_address = *pair_account.address();
    let source_asset = pair.source_asset;
    let destination_asset = pair.destination_asset;
    let execution_price = pair.price;
    drop(pair);
    if execution_price == 0 {
        return Err(DynamicSwapError::InvalidPrice.into());
    }

    let escrow_authority_owner_hash = escrow_authority_owner_hash(&pair_address)?;

    let current_slot = Clock::get()?.slot;
    if current_slot.abs_diff(created_at) > CREATED_AT_SLOT_TOLERANCE {
        return Err(DynamicSwapError::CreatedAtOutOfTolerance.into());
    }

    let foreign_pi = EscrowOpenPublicInput {
        private_tx_hash: &transact.private_tx_hash,
        created_at,
        escrow_authority_owner_hash: &escrow_authority_owner_hash,
        source_asset: &source_asset,
        destination_asset: &destination_asset,
    }
    .hash()?;

    let order_out_hash = transact
        .outputs
        .get(ORDER_OUTPUT_INDEX)
        .ok_or(DynamicSwapError::InvalidInstructionData)?
        .utxo_hash;
    let reservation_out_hash = transact
        .outputs
        .get(RESERVATION_OUTPUT_INDEX)
        .ok_or(DynamicSwapError::InvalidInstructionData)?
        .utxo_hash;

    let owner_key = *owner.address().as_array();
    let escrow_bump = verify_pda(
        escrow_account.address(),
        &[Escrow::SEED_PREFIX, &owner_key],
        &crate::ID,
    )?;
    CreatePdaAccount::<2> {
        fee_payer: authority,
        new_account: escrow_account,
        space: Escrow::SIZE,
        owner: &crate::ID,
        signer_seeds: [Escrow::SEED_PREFIX, &owner_key],
        bump: escrow_bump,
    }
    .execute()?;

    {
        let mut bytes = escrow_account
            .try_borrow_mut()
            .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
        let state: &mut Escrow = bytemuck::from_bytes_mut(&mut bytes[..]);
        state.discriminator = ESCROW;
        state.bump = escrow_bump;
        state.pair = pair_address;
        state.escrow_utxo_hash = order_out_hash;
        state.reservation_utxo_hash = reservation_out_hash;
        state.owner = *owner.address();
        state.created_at = created_at;
        state.execution_price = execution_price;
    }

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    let compose = compose_ix_data(
        &foreign_pi,
        &proof.proof_a,
        &proof.proof_b,
        &proof.proof_c,
        &transact_bytes,
    );
    let spp_accounts = iter.remaining()?;
    cpi_spp_compose_signed(
        &pair_address,
        crate::ESCROW_AUTHORITY_PDA_SEED,
        spp_accounts,
        &compose,
    )
}
