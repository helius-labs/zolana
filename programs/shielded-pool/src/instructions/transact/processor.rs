use light_hasher::{sha256::Sha256BE, Hasher};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{InputUtxo, TransactIxDataRef},
        tag::TRANSACT,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    transact_event::Input,
};
use zolana_tree::{TreeAccount, TreeError};

use super::account::{validate_input_signer, Settlement, TransactAccounts};
use super::event::{build_transact_event, emit_event, TreeWrite};
use super::sol::settle_sol;
use super::spl::settle_spl;
use super::verify::P256_OWNED_SIGNER;
use crate::{
    error::ShieldedPoolError,
    instructions::{
        hash::solana_pk_hash,
        transact::verify::{TransactProof, TransactProofInputs},
    },
};

const PROOF_LEN: usize = 192;

#[inline(never)]
pub fn process_transact_ix(
    _program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let after_proof = data
        .get(PROOF_LEN..)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let external_data_hash = Sha256BE::hashv(&[&[TRANSACT], after_proof])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    let ix =
        TransactIxDataRef::from_bytes(data).map_err(|_| ProgramError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    if clock.unix_timestamp < 0 || (clock.unix_timestamp as u64) > ix.expiry_unix_ts {
        return Err(ShieldedPoolError::ExpiredTransaction.into());
    }

    let mut proof_inputs = TransactProofInputs::default();
    proof_inputs.external_data_hash = external_data_hash;
    check_input_signers(accounts, &ix.inputs, &mut proof_inputs)?;

    let tree_write = {
        let tree = accounts
            .get_mut(1)
            .ok_or(ProgramError::AccountBorrowFailed)?;
        let output_tree = tree.address().to_bytes();
        // Note currently only one tree is supported for the entire protocol
        let mut tree =
            TreeAccount::from_account_view_mut(tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
                .map_err(tree_error)?;

        apply_tree(&mut tree, &ix, clock.slot, output_tree, &mut proof_inputs)?
    };
    let transact_accounts = TransactAccounts::validate_and_parse(accounts, &ix)?;

    proof_inputs.payer_pubkey_hash = Sha256BE::hash(&transact_accounts.payer.address().to_bytes())
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    if let Some(Settlement::Spl(spl)) = transact_accounts.settlement.as_ref() {
        proof_inputs.spl_mint = Some(read_spl_token_account_mint(spl.vault)?);
    }

    let event = build_transact_event(&ix, &proof_inputs, tree_write);
    TransactProof::new(&ix, proof_inputs).verify()?;

    match transact_accounts.settlement.as_ref() {
        Some(Settlement::Sol(sol)) => settle_sol(sol, public_amount(ix.public_sol_amount)?)?,
        Some(Settlement::Spl(spl)) => settle_spl(spl, public_amount(ix.public_spl_amount)?)?,
        None => {}
    }
    emit_event(&event)
}

fn public_amount(amount: Option<i64>) -> Result<u64, ProgramError> {
    Ok(amount
        .ok_or(ShieldedPoolError::InvalidTransactShape)?
        .unsigned_abs())
}

fn apply_tree(
    tree: &mut TreeAccount<'_>,
    ix: &TransactIxDataRef<'_>,
    current_slot: u64,
    output_tree: [u8; 32],
    proof_inputs: &mut TransactProofInputs,
) -> Result<TreeWrite, ProgramError> {
    let error = ShieldedPoolError::InvalidTransactShape;
    let mut inputs = Vec::with_capacity(ix.inputs.len());
    let nullifier_seq_base = tree.nullifer_tree.queue_batches.next_index;
    for (i, input) in ix.inputs.iter().enumerate() {
        *proof_inputs.utxo_roots.get_mut(i).ok_or(error)? = tree
            .get_utxo_tree_root(input.utxo_tree_root_index)
            .map_err(tree_error)?;
        *proof_inputs.nullifier_tree_roots.get_mut(i).ok_or(error)? = tree
            .get_nullifier_tree_root(input.nullifier_tree_root_index)
            .map_err(tree_error)?;
        tree.nullifer_tree
            .insert_address_into_queue(&input.nullifier_hash, &current_slot)
            .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?;
        inputs.push(Input {
            tree: output_tree,
            input_queue_seq: nullifier_seq_base + i as u64,
            nullifier: input.nullifier_hash,
        });
    }

    // Leaf index the sender output lands at; recipients follow sequentially.
    let first_output_leaf_index = tree.utxo_tree.next_index();
    tree.utxo_tree.append(*ix.sender_utxo_data.utxo_hash);
    for recipient in &ix.recipient_utxo_data {
        tree.utxo_tree.append(*recipient.utxo_hash);
    }
    Ok(TreeWrite {
        inputs,
        first_output_leaf_index,
        output_tree,
    })
}

// The vault is an SPL token account; its mint is the first 32 bytes.
fn read_spl_token_account_mint(account: &AccountView) -> Result<[u8; 32], ProgramError> {
    let data = account.try_borrow()?;
    data.get(..32)
        .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?
        .try_into()
        .map_err(|_| ShieldedPoolError::InvalidSettlementAccounts.into())
}

fn tree_error(e: TreeError) -> ProgramError {
    match e {
        TreeError::Paused => ShieldedPoolError::TreePaused.into(),
        TreeError::InvalidRootIndex => ShieldedPoolError::StaleNullifierRoot.into(),
        _ => ShieldedPoolError::InvalidTreeAccounts.into(),
    }
}

// Validate each Ed25519 input owner is a signer and record its `pk_field`
// (`Poseidon(low, high)`) in `proof_inputs`; P256-owned inputs stay zero.
fn check_input_signers(
    accounts: &[AccountView],
    inputs: &[InputUtxo],
    proof_inputs: &mut TransactProofInputs,
) -> Result<(), ProgramError> {
    for (i, input) in inputs.iter().enumerate() {
        if input.eddsa_signer_index == P256_OWNED_SIGNER {
            continue;
        }
        let account = accounts
            .get(usize::from(input.eddsa_signer_index))
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        let owner = validate_input_signer(account)?;
        *proof_inputs
            .solana_owner_pk_hashes
            .get_mut(i)
            .ok_or(ShieldedPoolError::InvalidTransactShape)? = solana_pk_hash(&owner)?;
    }
    Ok(())
}
