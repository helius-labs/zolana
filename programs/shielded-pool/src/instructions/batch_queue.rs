//! Two-phase operator batch queue (`docs/batching/two-phase.md`): enqueue
//! pure-shielded transact entries into an operator-owned account, verify them
//! in one RLC, then apply them in slices. Authorization happens at enqueue:
//! the entry's eddsa input signers co-sign that transaction and the queue
//! stores the payload immutably, so verify and apply cover exactly the
//! authorized bytes.

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::negate_g1_be,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_groth16_batch::{
    groth16_batch_verify, vk_from_solana, PodG1Point, PodG2Point, PodScalar, Proof,
    RandomizerMode, Version,
};
use zolana_hasher::{sha256::Sha256BE, Hasher};
use zolana_interface::{
    error::ShieldedPoolError,
    event::EventKind,
    instruction::{
        instruction_data::transact::{
            CircuitId, ExternalDataHash, OwnerTag, ResolvedOutput, TransactIxDataRef,
        },
        tag::InstructionTag,
    },
    state::{batch_queue as queue, discriminator::TREE_ACCOUNT_DISCRIMINATOR},
};
use zolana_tree::TreeAccount;

use crate::instructions::{
    event::emit_general_event,
    shared::{check_not_expired, collect_forester_fee, tree_error},
    transact::{
        event::build_transact_event,
        tree::{apply_input_tree, apply_output_tree},
        validate_circuit_type,
        verify::{TransactProof, TransactProofInputs},
    },
};

/// Entries applied per `ApplyBatch` call. Four keeps the call near the solo
/// apply cost while the whole queue drains in at most four calls.
pub const APPLY_BATCH_CHUNK: usize = 4;

fn queue_error(_: queue::BatchQueueError) -> ProgramError {
    ShieldedPoolError::InvalidInstructionData.into()
}

fn check_queue_account(account: &AccountView, writable: bool) -> ProgramResult {
    if !account.owned_by(&crate::ID) || (writable && !account.is_writable()) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    Ok(())
}

fn check_operator(account: &AccountView, data: &[u8]) -> ProgramResult {
    if !account.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if queue::operator(data).map_err(queue_error)? != *account.address().as_array() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

fn queue_circuit(data: &[u8]) -> Result<CircuitId, ProgramError> {
    let bytes = queue::circuit(data).map_err(queue_error)?;
    if bytes[0] != 0 {
        return Err(ShieldedPoolError::MismatchedCircuitType.into());
    }
    Ok(CircuitId::ConfidentialEddsa(bytes[1], bytes[2], bytes[3]))
}

/// Mirror of `TransactProofInputs::check_input_signers` over the enqueue
/// account list with the queue at index 1 skipped: entry signer index 0 is the
/// operator and indexes 2 and up are the extra signer accounts.
fn check_entry_signers(
    proof_inputs: &mut TransactProofInputs,
    segments: &[&[AccountView]; 2],
    ix: &TransactIxDataRef<'_>,
) -> ProgramResult {
    use zolana_account_checks::checks::check_signer;
    for (i, input) in ix.inputs.iter().enumerate() {
        let index = usize::from(input.eddsa_signer_index);
        let account = if index == 0 {
            segments[0].first()
        } else {
            // Indexes 2 and up map past the queue account.
            index.checked_sub(2).and_then(|at| segments[1].get(at))
        }
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
        check_signer(account).map_err(|_| ProgramError::MissingRequiredSignature)?;
        let pk_hash = zolana_hasher::primitives::hash_bytes(account.address().as_array())
            .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
        *proof_inputs
            .input_owner_pk_hashes
            .get_mut(i)
            .ok_or(ShieldedPoolError::InvalidTransactShape)? = pk_hash;
    }
    Ok(())
}

/// Inline-only resolution: `Account` tags index a transaction account list
/// that no longer exists at apply time, so enqueue rejects them.
fn resolve_inline_outputs<'a>(
    ix: &'a TransactIxDataRef<'a>,
) -> Result<Vec<ResolvedOutput<'a>>, ProgramError> {
    ix.outputs
        .iter()
        .map(|output| {
            if !matches!(output.owner_tag, OwnerTag::Inline(_)) {
                return Err(ShieldedPoolError::InvalidTransactShape.into());
            }
            output
                .into_resolved(|_| None)
                .map_err(|_| ShieldedPoolError::InvalidTransactShape.into())
        })
        .collect()
}

/// Create the queue. Accounts: `[payer (signer), operator (signer), queue
/// (writable)]`. The queue account is created in the same transaction with the
/// program as owner and `QUEUE_ACCOUNT_SIZE` bytes. Data: the circuit as
/// `[variant, inputs, outputs, public slots]`.
pub fn process_create_batch_queue_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [payer, operator, queue_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() || !operator.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let circuit_bytes: [u8; 4] = data
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    if circuit_bytes[0] != 0 {
        return Err(ShieldedPoolError::MismatchedCircuitType.into());
    }
    let circuit =
        CircuitId::ConfidentialEddsa(circuit_bytes[1], circuit_bytes[2], circuit_bytes[3]);
    let verifying_key = circuit
        .verifying_key()
        .ok_or(ShieldedPoolError::InvalidTransactShape)?;
    if !circuit.is_supported() || verifying_key.vk_commitment.is_some() {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    if !queue_account.owned_by(&crate::ID) || !queue_account.is_writable() {
        return Err(ProgramError::InvalidAccountOwner);
    }
    let mut queue_data = queue_account
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    if queue_data.first() != Some(&0) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    queue::init(
        &mut queue_data,
        circuit_bytes,
        *operator.address().as_array(),
    )
    .map_err(queue_error)
}

/// Enqueue one entry. Accounts: `[operator (signer), queue (writable), more
/// entry eddsa signers...]`. Data: the transact payload, the same bytes
/// `Transact` takes. The entry's `eddsa_signer_index` values resolve into this
/// account list, so index 0 is the operator, which matches the solo layout
/// where index 0 is the payer.
pub fn process_enqueue_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (before_queue, from_queue) = accounts.split_at_mut(1);
    let operator = &before_queue[0];
    let (queue_slot, extra_signers) = from_queue.split_at_mut(1);
    let queue_account = &mut queue_slot[0];
    check_queue_account(queue_account, true)?;
    let mut queue_data = queue_account
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    check_operator(operator, &queue_data)?;
    if queue::stage(&queue_data).map_err(queue_error)? != queue::STAGE_FILLING {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }

    let ix =
        TransactIxDataRef::from_bytes(data).map_err(|_| ProgramError::InvalidInstructionData)?;
    validate_circuit_type(&ix, InstructionTag::Transact)?;
    if ix.circuit != queue_circuit(&queue_data)? {
        return Err(ShieldedPoolError::MismatchedCircuitType.into());
    }
    if !ix.interface_transfers.is_empty() {
        return Err(ShieldedPoolError::InvalidTransactShape.into());
    }
    // Resolution also enforces Inline owner tags.
    resolve_inline_outputs(&ix)?;
    let clock = Clock::get()?;
    check_not_expired(ix.expiry_unix_ts, &clock)?;

    // Authorization: the entry's input owners sign this transaction. Their
    // hashes travel with the entry so verify derives the same public inputs.
    let mut proof_inputs = TransactProofInputs::default();
    let signer_view = [core::slice::from_ref(operator), &*extra_signers];
    check_entry_signers(&mut proof_inputs, &signer_view, &ix)?;

    // Store the proof fold-ready: decompressed, with `a` un-negated.
    let encoding_err = ShieldedPoolError::InvalidTransactProofEncoding;
    let a = negate_g1_be(&decompress_g1(&ix.proof.a).map_err(|_| encoding_err)?);
    let b = decompress_g2(&ix.proof.b).map_err(|_| encoding_err)?;
    let c = decompress_g1(&ix.proof.c).map_err(|_| encoding_err)?;
    let mut proof = [0u8; queue::ENTRY_PROOF_BYTES];
    proof[..64].copy_from_slice(&a);
    proof[64..192].copy_from_slice(&b);
    proof[192..].copy_from_slice(&c);

    let n_inputs = ix.inputs.len();
    queue::push_entry(
        &mut queue_data,
        data,
        &proof,
        proof_inputs
            .input_owner_pk_hashes
            .get(..n_inputs)
            .ok_or(ShieldedPoolError::InvalidTransactShape)?,
    )
    .map_err(queue_error)?;
    Ok(())
}

/// Verify every enqueued entry in one RLC. Accounts: `[operator (signer),
/// queue (writable), input tree (writable), output tree (writable)]`. Trees
/// are read for roots and the dummy policy, nothing mutates until apply.
pub fn process_execute_batch_verify_ix(accounts: &mut [AccountView]) -> ProgramResult {
    let [operator, queue_account, input_tree, _output_tree, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_queue_account(queue_account, false)?;
    let queue_data = queue_account
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    check_operator(operator, &queue_data)?;
    if queue::stage(&queue_data).map_err(queue_error)? != queue::STAGE_FILLING {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let count = queue::count(&queue_data).map_err(queue_error)?;
    if count == 0 {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let circuit = queue_circuit(&queue_data)?;
    let payer_pubkey_hash = Sha256BE::hash(queue::operator(&queue_data).map_err(queue_error)?.as_ref())
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    let (allow_dummy, proofs) = {
        let mut tree =
            TreeAccount::from_account_view_mut(input_tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
                .map_err(tree_error)?;
        let allow_dummy = tree.allow_dummy_inputs().map_err(tree_error)?;
        let allow_dummy_field = crate::instructions::shared::bool_field(allow_dummy);

        let mut proofs = Vec::with_capacity(count);
        for index in 0..count {
            let entry = queue::entry(&queue_data, index).map_err(queue_error)?;
            let ix = TransactIxDataRef::from_bytes(entry.payload)
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            let resolved = resolve_inline_outputs(&ix)?;

            let mut proof_inputs = TransactProofInputs {
                allow_dummy_inputs: allow_dummy_field,
                payer_pubkey_hash,
                ..Default::default()
            };
            for (i, input) in ix.inputs.iter().enumerate() {
                *proof_inputs
                    .utxo_roots
                    .get_mut(i)
                    .ok_or(ShieldedPoolError::InvalidTransactShape)? = tree
                    .get_utxo_tree_root(input.utxo_tree_root_index)
                    .map_err(tree_error)?;
                *proof_inputs
                    .nullifier_tree_roots
                    .get_mut(i)
                    .ok_or(ShieldedPoolError::InvalidTransactShape)? = tree
                    .get_nullifier_tree_root(input.nullifier_tree_root_index)
                    .map_err(tree_error)?;
                *proof_inputs
                    .input_owner_pk_hashes
                    .get_mut(i)
                    .ok_or(ShieldedPoolError::InvalidTransactShape)? =
                    entry.input_owner_pk_hash(i).map_err(queue_error)?;
            }
            proof_inputs.fill_output_owner_pk_hashes(&resolved)?;
            proof_inputs.external_data_hash = ExternalDataHash {
                spp_instruction_discriminator: InstructionTag::Transact as u8,
                expiry_unix_ts: ix.expiry_unix_ts,
                interface_transfers: &[],
                data_hash: ix.data_hash,
                zone_data_hash: ix.zone_data_hash,
                tx_viewing_pk: ix.tx_viewing_pk,
                salt: ix.salt,
                outputs: &resolved,
                messages: &ix.messages,
            }
            .hash()
            .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

            let public_input_hash =
                TransactProof::new(&ix, &proof_inputs).public_input_hash_value()?;
            let mut a = [0u8; 64];
            a.copy_from_slice(&entry.proof[..64]);
            let mut b = [0u8; 128];
            b.copy_from_slice(&entry.proof[64..192]);
            let mut c = [0u8; 64];
            c.copy_from_slice(&entry.proof[192..]);
            proofs.push(Proof {
                vk_index: 0,
                a: PodG1Point(a),
                b: PodG2Point(b),
                c: PodG1Point(c),
                commitment: None,
                public_inputs: alloc_inputs(public_input_hash),
            });
        }
        (allow_dummy, proofs)
    };

    let verifying_key = circuit
        .verifying_key()
        .ok_or(ShieldedPoolError::InvalidTransactShape)?;
    let validated = vk_from_solana(verifying_key)
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
    let ok = groth16_batch_verify(
        Version::V0,
        core::slice::from_ref(&validated),
        &proofs,
        RandomizerMode::Independent,
    )
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;
    if !ok {
        return Err(ShieldedPoolError::TransactProofVerificationFailed.into());
    }

    drop(queue_data);
    check_queue_account(queue_account, true)?;
    let mut queue_data = queue_account
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    queue::set_allow_dummy(&mut queue_data, allow_dummy).map_err(queue_error)?;
    queue::set_stage(&mut queue_data, queue::STAGE_VERIFIED).map_err(queue_error)
}

fn alloc_inputs(hash: [u8; 32]) -> Vec<PodScalar> {
    vec![PodScalar(hash)]
}

/// Apply up to [`APPLY_BATCH_CHUNK`] verified entries from the cursor.
/// Accounts: `[operator (signer, writable), queue (writable), input tree
/// (writable), output tree (writable)]`. The dummy policy must still match
/// the value captured at verify, so the batch fails closed when the tree
/// crossed the threshold in between.
pub fn process_apply_batch_ix(accounts: &mut [AccountView]) -> ProgramResult {
    let [operator, queue_account, input_tree, output_tree, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let (count, from, entries_allow_dummy) = {
        check_queue_account(queue_account, false)?;
    let queue_data = queue_account
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
        check_operator(operator, &queue_data)?;
        if queue::stage(&queue_data).map_err(queue_error)? != queue::STAGE_VERIFIED {
            return Err(ShieldedPoolError::InvalidInstructionData.into());
        }
        (
            queue::count(&queue_data).map_err(queue_error)?,
            queue::applied(&queue_data).map_err(queue_error)?,
            queue::allow_dummy(&queue_data).map_err(queue_error)?,
        )
    };
    let to = count.min(from + APPLY_BATCH_CHUNK);
    if from >= to {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }

    for index in from..to {
        let payload = {
            let queue_data = queue_account
                .try_borrow()
                .map_err(|_| ProgramError::AccountBorrowFailed)?;
            queue::entry(&queue_data, index)
                .map_err(queue_error)?
                .payload
                .to_vec()
        };
        let ix = TransactIxDataRef::from_bytes(&payload)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let resolved = resolve_inline_outputs(&ix)?;

        let mut proof_inputs = TransactProofInputs::default();
        let (inputs, zkp_batch_size) = {
            let addr = input_tree.address().to_bytes();
            let mut tree = TreeAccount::from_account_view_mut(
                &mut *input_tree,
                &crate::ID,
                TREE_ACCOUNT_DISCRIMINATOR,
            )
            .map_err(tree_error)?;
            if tree.allow_dummy_inputs().map_err(tree_error)? != entries_allow_dummy {
                return Err(ShieldedPoolError::TransactProofVerificationFailed.into());
            }
            let inputs = apply_input_tree(&mut tree, &ix, addr, &mut proof_inputs)?;
            let zkp = tree.nullifer_tree().queue_batches.zkp_batch_size;
            (inputs, zkp)
        };
        let tree_write = {
            let addr = output_tree.address().to_bytes();
            let mut tree = TreeAccount::from_account_view_mut(
                &mut *output_tree,
                &crate::ID,
                TREE_ACCOUNT_DISCRIMINATOR,
            )
            .map_err(tree_error)?;
            apply_output_tree(&mut tree, &ix, addr, inputs)?
        };
        collect_forester_fee(operator, input_tree, ix.inputs.len() as u64, zkp_batch_size)?;
        let event = build_transact_event(&ix, &[], tree_write, &resolved);
        emit_general_event(EventKind::Transact, event)?;
    }

    check_queue_account(queue_account, true)?;
    let mut queue_data = queue_account
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    queue::set_applied(&mut queue_data, to).map_err(queue_error)?;
    if to == count {
        queue::set_stage(&mut queue_data, queue::STAGE_APPLIED).map_err(queue_error)?;
    }
    Ok(())
}

/// Close an applied or empty queue and move the rent to a dedicated
/// recipient. Accounts: `[operator (signer), queue (writable), rent recipient
/// (writable)]`.
pub fn process_close_batch_queue_ix(accounts: &mut [AccountView]) -> ProgramResult {
    let [operator, queue_account, rent_recipient] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    {
        check_queue_account(queue_account, false)?;
    let queue_data = queue_account
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
        check_operator(operator, &queue_data)?;
        let stage = queue::stage(&queue_data).map_err(queue_error)?;
        let count = queue::count(&queue_data).map_err(queue_error)?;
        if stage != queue::STAGE_APPLIED && count != 0 {
            return Err(ShieldedPoolError::InvalidInstructionData.into());
        }
    }
    if queue_account.address() == rent_recipient.address() {
        return Err(ProgramError::InvalidAccountData);
    }
    check_queue_account(queue_account, true)?;
    let mut queue_data = queue_account
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    queue_data[0] = 0;
    drop(queue_data);
    let rent = queue_account.lamports();
    let recipient_balance = rent_recipient
        .lamports()
        .checked_add(rent)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    queue_account.set_lamports(0);
    rent_recipient.set_lamports(recipient_balance);
    Ok(())
}
