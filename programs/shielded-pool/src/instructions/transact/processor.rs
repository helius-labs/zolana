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
        instruction_data::transact::{
            ExternalDataHash, PublicLeg, ResolvedOutput, ResolvedPublicLeg, TransactIxDataRef,
        },
        tag::TRANSACT,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    N_PUBLIC_SLOTS, SOL_ASSET_FIELD,
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
    let mut outputs = ArrayVec::new(); // TODO: check whether we really need this allocation.
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
    // Poseidon syscall). The confidential variants publish it; it is absent on the
    // eddsa rail (`0`).
    proof_inputs.p256_signing_pk_field = match ix.p256_signing_pk_x {
        Some(x) => verifier::hash_field(&x, ShieldedPoolError::TransactProofVerificationFailed)?,
        None => [0u8; 32],
    };
    if !IS_AUTHORITY {
        check_input_signers(accounts, ix, &mut proof_inputs)?;
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
    fill_public_slots(ix, &transact_accounts.settlements, proof_inputs)?;
    let resolved_public_legs = resolve_public_legs(ix, &transact_accounts.settlements)?;

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

    proof_inputs.external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: discriminator,
        expiry_unix_ts: ix.expiry_unix_ts,
        public_legs: &resolved_public_legs,
        data_hash: ix.data_hash,
        zone_data_hash: ix.zone_data_hash,
        outputs: resolved_outputs,
        messages: &ix.messages,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    proof_inputs.payer_pubkey_hash = Sha256BE::hash(&transact_accounts.payer.address().to_bytes())
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    let event = build_transact_event(
        ix,
        &transact_accounts.settlements,
        tree_write,
        resolved_outputs,
    );
    TransactProof::new(ix, proof_inputs).verify::<IS_ZONE, IS_AUTHORITY>()?;

    for (leg, settlement) in ix
        .public_legs
        .iter()
        .zip(transact_accounts.settlements.iter())
    {
        match settlement {
            Settlement::Sol(sol) => settle_sol(sol, leg.amount(), leg.is_deposit())?,
            Settlement::Spl(spl) => settle_spl(spl, leg.amount())?,
        }
    }
    emit_general_event(EventKind::Transact, event)
}

struct PublicAssetAggregate {
    asset: [u8; 32],
    amount: i128,
}

fn fill_public_slots(
    ix: &TransactIxDataRef<'_>,
    settlements: &[Settlement<'_>],
    proof_inputs: &mut TransactProofInputs,
) -> Result<(), ProgramError> {
    if ix.public_legs.len() != settlements.len() {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }

    // Distinct assets can cancel to zero, so retain them until aggregation is
    // complete. This lives on the heap: the u8 wire ceiling must not turn into
    // a large fixed SBF stack allocation.
    let mut aggregates: Vec<PublicAssetAggregate> = Vec::new();
    for (leg, settlement) in ix.public_legs.iter().zip(settlements.iter()) {
        let asset = match (leg, settlement) {
            (PublicLeg::Sol { .. }, Settlement::Sol(_)) => SOL_ASSET_FIELD,
            (PublicLeg::Spl { .. }, Settlement::Spl(spl)) => verifier::hash_field(
                &spl.mint,
                ShieldedPoolError::TransactProofVerificationFailed,
            )?,
            _ => return Err(ShieldedPoolError::InvalidSettlementAccounts.into()),
        };
        if let Some(existing) = aggregates.iter_mut().find(|entry| entry.asset == asset) {
            existing.amount = existing
                .amount
                .checked_add(signed_amount(*leg))
                .ok_or(ShieldedPoolError::PublicAssetAmountOverflow)?;
        } else {
            aggregates.push(PublicAssetAggregate {
                asset,
                amount: signed_amount(*leg),
            });
        }
    }

    let active_count = aggregates.iter().filter(|entry| entry.amount != 0).count();
    if active_count > N_PUBLIC_SLOTS {
        return Err(ShieldedPoolError::TooManyPublicAssets.into());
    }
    for ((asset_slot, amount_slot), aggregate) in proof_inputs
        .public_slot_assets
        .iter_mut()
        .zip(proof_inputs.public_slot_amounts.iter_mut())
        .zip(aggregates.iter().filter(|entry| entry.amount != 0))
    {
        let magnitude = u64::try_from(aggregate.amount.unsigned_abs())
            .map_err(|_| ShieldedPoolError::PublicAssetAmountOverflow)?;
        *asset_slot = aggregate.asset;
        *amount_slot = if aggregate.amount.is_negative() {
            -i128::from(magnitude)
        } else {
            i128::from(magnitude)
        };
    }
    Ok(())
}

fn signed_amount(leg: PublicLeg) -> i128 {
    let amount = i128::from(leg.amount());
    if leg.is_deposit() {
        amount
    } else {
        -amount
    }
}

fn resolve_public_legs(
    ix: &TransactIxDataRef<'_>,
    settlements: &[Settlement<'_>],
) -> Result<Vec<ResolvedPublicLeg>, ProgramError> {
    if ix.public_legs.len() != settlements.len() {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    let mut resolved = Vec::with_capacity(ix.public_legs.len());
    for (leg, settlement) in ix.public_legs.iter().zip(settlements.iter()) {
        let public_leg = match (leg, settlement) {
            (PublicLeg::Sol { is_deposit, amount }, Settlement::Sol(sol)) => {
                ResolvedPublicLeg::Sol {
                    is_deposit: *is_deposit,
                    amount: *amount,
                    recipient: sol.recipient.address().to_bytes(),
                }
            }
            (PublicLeg::Spl { is_deposit, amount }, Settlement::Spl(spl)) => {
                ResolvedPublicLeg::Spl {
                    is_deposit: *is_deposit,
                    amount: *amount,
                    user_token_account: spl.user_token_account.address().to_bytes(),
                    vault: spl.vault.address().to_bytes(),
                }
            }
            _ => return Err(ShieldedPoolError::InvalidSettlementAccounts.into()),
        };
        resolved.push(public_leg);
    }
    Ok(resolved)
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
        .append_batch(ix.outputs.iter().map(|o| o.utxo_hash))
        .map_err(tree_error)?;
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
        TreeError::TreeIsFull => ShieldedPoolError::StateAppendFailed.into(),
        _ => ShieldedPoolError::InvalidTreeAccounts.into(),
    }
}

// Assign input owner public inputs.
// Either assign p256 pubkey or check signer and assign eddsa pubkey.
// The circuit checks the p256 signature.
#[profile]
fn check_input_signers(
    accounts: &[AccountView],
    ix: &TransactIxDataRef<'_>,
    proof_inputs: &mut TransactProofInputs,
) -> Result<(), ProgramError> {
    for (i, input) in ix.inputs.iter().enumerate() {
        let pk_hash = if input.eddsa_signer_index == P256_OWNED_SIGNER {
            // A P256-owned input routes to the transaction's shared P256 key on this
            // sentinel; the circuit checks that key's signature. The confidential
            // variants publish the key itself as `p256_signing_pk_field`, so the
            // sentinel hides nothing there. The eddsa variant has no P256 path, so
            // the sentinel is only valid when the selector declares P256.
            if !ix.circuit.is_p256() {
                return Err(ShieldedPoolError::MismatchedCircuitVariant.into());
            }
            [0u8; 32]
        } else {
            // Eddsa signer check. The circuit relies on the program to check the signer.
            let account = accounts
                .get(usize::from(input.eddsa_signer_index))
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            check_signer(account)?;
            // TODO: use a hash cache.
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
        // TODO: use a hash cache.
        *slot = verifier::hash_field(&output.owner_tag, error)?; // TODO: check whether we can compute hashes offchain
    }
    Ok(())
}
