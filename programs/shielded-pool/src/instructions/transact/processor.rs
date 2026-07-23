use arrayvec::ArrayVec;
use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::checks::check_signer;
use zolana_hasher::{sha256::Sha256BE, Hasher};
use zolana_interface::{
    error::ShieldedPoolError,
    event::{EventKind, Input},
    instruction::{
        instruction_data::transact::{ExternalDataHash, ResolvedOutput, TransactIxDataRef},
        tag::TRANSACT,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::{TreeAccount, TreeError};

use super::{
    account::TransactAccounts,
    event::{build_transact_event, TreeWrite},
    verify::{MAX_OUTPUTS, P256_OWNED_SIGNER},
};
use crate::instructions::{
    event::emit_general_event,
    hash::solana_pk_hash,
    settlement::{settle_sol, settle_spl, Settlement},
    shared::check_not_expired,
    transact::verify::{TransactProof, TransactProofInputs},
    verifier,
};

#[inline(never)]
#[profile]
pub fn process_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix =
        TransactIxDataRef::from_bytes(data).map_err(|_| ProgramError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    check_not_expired(ix.expiry_unix_ts, &clock)?;

    let resolved_outputs = resolve_outputs(accounts, &ix)?;
    let mut proof_inputs = prepare_proof_inputs::<false, false>(accounts, &ix, &resolved_outputs)?;
    let transact_accounts = TransactAccounts::validate_and_parse(accounts, &ix)?;

    process_transact_core::<false, false>(
        &ix,
        &mut proof_inputs,
        transact_accounts,
        TRANSACT,
        &resolved_outputs,
    )
}

#[inline(never)]
pub(crate) fn resolve_outputs<'a>(
    accounts: &[AccountView],
    ix: &TransactIxDataRef<'a>,
) -> Result<ArrayVec<ResolvedOutput<'a>, MAX_OUTPUTS>, ProgramError> {
    let mut outputs = ArrayVec::new();
    for output in &ix.outputs {
        let resolved = output.into_resolved(ix.p256_signing_pk_x.as_ref(), |i| {
            accounts.get(usize::from(i)).map(|a| a.address().to_bytes())
        })?;
        outputs
            .try_push(resolved)
            .map_err(|_| ShieldedPoolError::InvalidTransactShape)?;
    }
    Ok(outputs)
}

/// Derive the proof inputs that come from the raw account slice and instruction
/// data, before the settlement accounts are parsed. The anonymous policy-zone
/// variant (`IS_ZONE`) leaves output owners free (a view tag), so it skips the
/// output-owner public inputs the confidential variant binds. The zone-authority
/// variant (`IS_AUTHORITY`) requires no per-owner spend signature (the zone
/// authorizes via its `zone_config`), so it skips the input-signer checks.
// `TransactProofInputs` is a large (~1 KB) fixed-array struct; build it once with
// `default()` and fill fields in place. Struct-update syntax
// (`..Default::default()`) would materialize a second copy on the stack and push
// this frame over the SBF limit, so the `field_reassign_with_default` lint is
// suppressed for the whole function.
#[inline(never)]
#[allow(clippy::field_reassign_with_default)]
pub(crate) fn prepare_proof_inputs<const IS_ZONE: bool, const IS_AUTHORITY: bool>(
    accounts: &[AccountView],
    ix: &TransactIxDataRef<'_>,
    resolved_outputs: &[ResolvedOutput],
) -> Result<TransactProofInputs, ProgramError> {
    let mut proof_inputs = TransactProofInputs::default();
    // Hash the raw P256 signing key x-coordinate into its field element once (one
    // Poseidon syscall), before `check_input_signers` folds it for P256-owned
    // inputs. Absent on the eddsa rail (folded as the `0` sentinel).
    proof_inputs.p256_signing_pk_field = match ix.p256_signing_pk_x {
        Some(x) => verifier::hash_field(&x, ShieldedPoolError::TransactProofVerificationFailed)?,
        None => [0u8; 32],
    };
    if !IS_AUTHORITY {
        check_input_signers::<IS_ZONE>(accounts, ix, &mut proof_inputs)?;
    }
    if !IS_ZONE {
        fill_output_owner_pk_hashes(resolved_outputs, &mut proof_inputs)?;
    }
    Ok(proof_inputs)
}

/// Shared tail for `transact` and `zone_transact`: append outputs / nullify
/// inputs, recompute `external_data_hash` (under `discriminator`), verify the
/// proof, settle the public amount, and emit the event. `proof_inputs` already
/// carries the input/output owner state and, for the zone variant, `is_zone` +
/// `zone_program_id`.
#[inline(never)]
pub(crate) fn process_transact_core<const IS_ZONE: bool, const IS_AUTHORITY: bool>(
    ix: &TransactIxDataRef<'_>,
    proof_inputs: &mut TransactProofInputs,
    transact_accounts: TransactAccounts<'_>,
    discriminator: u8,
    resolved_outputs: &[ResolvedOutput],
) -> ProgramResult {
    // The parser picks one settlement branch, so both amounts set would move only
    // SPL while the proven SOL leg never settles: an unbacked note. Reject first.
    if ix.public_sol_amount.is_some() && ix.public_spl_amount.is_some() {
        return Err(ShieldedPoolError::BothPublicAmountsSet.into());
    }

    let tree_write = {
        let output_tree = transact_accounts.tree.address().to_bytes();
        // Note currently only one tree is supported for the entire protocol
        let mut tree = TreeAccount::from_account_view_mut(
            transact_accounts.tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;

        apply_tree(&mut tree, ix, output_tree, proof_inputs)?
    };

    let (user_sol_account, user_spl_token_account, spl_token_interface) =
        settlement_accounts(&transact_accounts);
    proof_inputs.external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: discriminator,
        expiry_unix_ts: ix.expiry_unix_ts,
        relayer_fee: ix.relayer_fee,
        public_sol_amount: ix.public_sol_amount,
        public_spl_amount: ix.public_spl_amount,
        user_sol_account: &user_sol_account,
        user_spl_token_account: &user_spl_token_account,
        spl_token_interface: &spl_token_interface,
        data_hash: ix.data_hash,
        zone_data_hash: ix.zone_data_hash,
        outputs: resolved_outputs,
        messages: &ix.messages,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    proof_inputs.payer_pubkey_hash = Sha256BE::hash(&transact_accounts.payer.address().to_bytes())
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    proof_inputs.spl_mint = transact_accounts.spl_mint;

    let event = build_transact_event(ix, proof_inputs, tree_write, resolved_outputs);
    TransactProof::new(ix, proof_inputs).verify::<IS_ZONE, IS_AUTHORITY>()?;

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

#[profile]
fn apply_tree(
    tree: &mut TreeAccount<'_>,
    ix: &TransactIxDataRef<'_>,
    output_tree: [u8; 32],
    proof_inputs: &mut TransactProofInputs,
) -> Result<TreeWrite, ProgramError> {
    let error = ShieldedPoolError::InvalidTransactShape;
    let mut inputs = Vec::with_capacity(ix.inputs.len());
    let nullifier_seq_base = tree.nullifer_tree().queue_batches.next_index;
    for (i, input) in ix.inputs.iter().enumerate() {
        *proof_inputs.utxo_roots.get_mut(i).ok_or(error)? = tree
            .get_utxo_tree_root(input.utxo_tree_root_index)
            .map_err(tree_error)?;
        *proof_inputs.nullifier_tree_roots.get_mut(i).ok_or(error)? = tree
            .get_nullifier_tree_root(input.nullifier_tree_root_index)
            .map_err(tree_error)?;
        tree.nullifer_tree()
            .insert_address_into_queue(&input.nullifier_hash)
            .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?;
        inputs.push(Input {
            tree: output_tree,
            input_queue_seq: nullifier_seq_base + i as u64,
            nullifier: input.nullifier_hash,
        });
    }

    // Leaf index the first output lands at; the rest follow sequentially.
    let first_output_leaf_index = tree.utxo_tree().next_index();
    tree.utxo_tree()
        .append_batch(ix.outputs.iter().map(|o| o.utxo_hash));
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

// Record each input owner's `pk_field` (`Poseidon(low, high)`) in `proof_inputs`.
// Ed25519 inputs must have their owner account as a signer and use its
// `solana_pk_hash` (every variant). P256-owned inputs differ by variant: the
// confidential rail folds the shared P256 signing key's `pk_field`
// (`proof_inputs.p256_signing_pk_field`, hashed once in `prepare_proof_inputs`)
// so the circuit routes ownership by equality,
// while the anonymous policy-zone rail (`IS_ZONE`) keeps P256 owners private and
// folds the `0` sentinel -- the circuit proves P256 ownership internally from the
// signature, so the public input carries no owner identity (matching
// `OwnerMode::Zone` in the prover).
#[profile]
fn check_input_signers<const IS_ZONE: bool>(
    accounts: &[AccountView],
    ix: &TransactIxDataRef<'_>,
    proof_inputs: &mut TransactProofInputs,
) -> Result<(), ProgramError> {
    let p256_signing_pk_field = proof_inputs.p256_signing_pk_field;
    for (i, input) in ix.inputs.iter().enumerate() {
        let pk_hash = if input.eddsa_signer_index == P256_OWNED_SIGNER {
            if IS_ZONE {
                [0u8; 32]
            } else {
                p256_signing_pk_field
            }
        } else {
            let account = accounts
                .get(usize::from(input.eddsa_signer_index))
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            check_signer(account)?;
            solana_pk_hash(account.address().as_array())?
        };
        *proof_inputs
            .input_owner_pk_hashes
            .get_mut(i)
            .ok_or(ShieldedPoolError::InvalidTransactShape)? = pk_hash;
    }
    Ok(())
}

#[profile]
fn fill_output_owner_pk_hashes(
    resolved_outputs: &[ResolvedOutput],
    proof_inputs: &mut TransactProofInputs,
) -> Result<(), ProgramError> {
    let error = ShieldedPoolError::InvalidTransactShape;
    for (slot, output) in proof_inputs
        .output_owner_pk_hashes
        .iter_mut()
        .zip(resolved_outputs.iter())
    {
        *slot = verifier::hash_field(&output.owner_tag, error)?;
    }
    Ok(())
}
