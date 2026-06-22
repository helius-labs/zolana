use light_hasher::{sha256::Sha256BE, Hasher};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_interface::{
    error::ShieldedPoolError,
    event::{EventKind, Input},
    instruction::{
        instruction_data::transact::{ExternalDataHash, InputUtxo, TransactIxDataRef},
        tag::TRANSACT,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::{TreeAccount, TreeError};

use super::{
    account::{validate_input_signer, TransactAccounts},
    event::{build_transact_event, TreeWrite},
    verify::P256_OWNED_SIGNER,
};
use crate::instructions::{
    event::emit_general_event,
    hash::solana_pk_hash,
    settlement::{settle_sol, settle_spl, Settlement},
    transact::verify::{TransactProof, TransactProofInputs},
};

#[inline(never)]
pub fn process_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix =
        TransactIxDataRef::from_bytes(data).map_err(|_| ProgramError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    if clock.unix_timestamp < 0 || (clock.unix_timestamp as u64) > ix.expiry_unix_ts {
        return Err(ShieldedPoolError::ExpiredTransaction.into());
    }

    let mut proof_inputs = TransactProofInputs::default();
    check_input_signers(accounts, &ix.inputs, &mut proof_inputs)?;
    let transact_accounts = TransactAccounts::validate_and_parse(&crate::ID, accounts, &ix)?;

    let tree_write = {
        let output_tree = transact_accounts.tree.address().to_bytes();
        // Note currently only one tree is supported for the entire protocol
        let mut tree = TreeAccount::from_account_view_mut(
            transact_accounts.tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;

        apply_tree(&mut tree, &ix, clock.slot, output_tree, &mut proof_inputs)?
    };

    let (user_sol_account, user_spl_token_account, spl_token_interface) =
        settlement_accounts(&transact_accounts);
    proof_inputs.external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: TRANSACT,
        expiry_unix_ts: ix.expiry_unix_ts,
        relayer_fee: ix.relayer_fee,
        public_sol_amount: ix.public_sol_amount,
        public_spl_amount: ix.public_spl_amount,
        user_sol_account: &user_sol_account,
        user_spl_token_account: &user_spl_token_account,
        spl_token_interface: &spl_token_interface,
        cpi_signer: ix.cpi_signer,
        output_utxo_hashes: &ix.output_utxo_hashes,
        output_ciphertexts: &ix.output_ciphertexts,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    proof_inputs.payer_pubkey_hash = Sha256BE::hash(&transact_accounts.payer.address().to_bytes())
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    proof_inputs.spl_mint = transact_accounts.spl_mint;

    let event = build_transact_event(&ix, &proof_inputs, tree_write);
    TransactProof::new(&ix, proof_inputs).verify()?;

    match transact_accounts.settlement.as_ref() {
        Some(Settlement::Sol(sol)) => {
            settle_sol(sol, public_amount(ix.public_sol_amount)?, ix.is_deposit())?
        }
        Some(Settlement::Spl(spl)) => settle_spl(spl, public_amount(ix.public_spl_amount)?)?,
        None => {}
    }
    emit_general_event(EventKind::Transact, event)
}

fn public_amount(amount: Option<i64>) -> Result<u64, ProgramError> {
    Ok(amount
        .ok_or(ShieldedPoolError::InvalidTransactShape)?
        .unsigned_abs())
}

// The settlement account addresses bound into `external_data_hash`: the external
// SOL recipient, the user's SPL token account, and the pool's SPL interface
// vault. Zeroed for a pure shielded transfer (no settlement).
fn settlement_accounts(accounts: &TransactAccounts) -> ([u8; 32], [u8; 32], [u8; 32]) {
    match accounts.settlement.as_ref() {
        Some(Settlement::Sol(sol)) => (sol.recipient.address().to_bytes(), [0u8; 32], [0u8; 32]),
        Some(Settlement::Spl(spl)) => (
            [0u8; 32],
            spl.user_token_account.address().to_bytes(),
            spl.vault.address().to_bytes(),
        ),
        None => ([0u8; 32], [0u8; 32], [0u8; 32]),
    }
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

    // Leaf index the first output lands at; the rest follow sequentially.
    let first_output_leaf_index = tree.utxo_tree.next_index();
    for utxo_hash in &ix.output_utxo_hashes {
        tree.utxo_tree.append(*utxo_hash);
    }
    Ok(TreeWrite {
        inputs,
        first_output_leaf_index,
        output_tree,
    })
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
