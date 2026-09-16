use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    direct_spend::{
        certificate_id, field, Payload, PaymentInputs, ADMITTED_DAG_PAYMENT_DOMAIN,
        ADMITTED_PAYMENT_DOMAIN, CERTIFICATE_INPUTS, MAX_CERTIFICATES, MAX_INPUTS, PAYMENT_DOMAIN,
    },
    error::ShieldedPoolError,
    event::{EventKind, GeneralEvent, Input, InputTreeSequence},
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    verifying_keys::{
        direct_payment_512_2, direct_payment_admitted_144_2, direct_payment_admitted_512_2,
        direct_payment_admitted_dag10_512_2, direct_payment_gkr_144_2, direct_payment_gkr_512_2,
        spend_balance_16_2,
    },
};
use zolana_tree::TreeAccount;

use super::{buffer, check_freshness, load_payload, tree_layout, verify, verify_with_commitment};
use crate::instructions::{
    event::emit_event,
    nullifier_pda::{
        create_nullifier_pdas, uses_nullifier_filter, InputTreeResult, NullifierAdmission,
    },
    shared::tree_error,
};

#[light_program_profiler::profile]
pub fn process_commit(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut iter = AccountIterator::new(accounts);
    let owner = iter.next_signer("owner")?;
    let payment = iter.next_mut("payment")?;
    let input_tree = iter.next_mut("input_tree")?;
    let output_tree = iter.next_mut("output_tree")?;
    let pending = iter.next_mut("pending_nullifiers")?;
    let filter = if uses_nullifier_filter(input_tree)? {
        Some(iter.next_mut("nullifier_filter")?)
    } else {
        None
    };
    let system = iter.next_account("system_program")?;
    let program = iter.next_account("shielded_pool_program")?;
    if !pinocchio_system::check_id(system.address()) || program.address() != &crate::ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    let receipts = iter.remaining_unchecked_mut()?;
    let (statement, proof, commitment, capacity, domain) =
        match load_payload(payment, owner.address().as_array())? {
            Payload::Payment { statement, proof } => {
                (statement, proof, None, MAX_INPUTS, PAYMENT_DOMAIN)
            }
            Payload::GkrPayment {
                statement,
                proof,
                commitment,
                inputs,
            } if zolana_interface::direct_spend::GKR_PAYMENT_INPUTS
                .contains(&usize::from(inputs)) =>
            {
                (
                    statement,
                    proof,
                    Some(commitment),
                    usize::from(inputs),
                    PAYMENT_DOMAIN,
                )
            }
            Payload::AdmittedPayment {
                statement,
                proof,
                commitment,
                inputs,
            } if zolana_interface::direct_spend::GKR_PAYMENT_INPUTS
                .contains(&usize::from(inputs)) =>
            {
                (
                    statement,
                    proof,
                    Some(commitment),
                    usize::from(inputs),
                    ADMITTED_PAYMENT_DOMAIN,
                )
            }
            Payload::DagPayment {
                statement,
                proof,
                commitment,
                inputs,
            } if usize::from(inputs) == MAX_INPUTS => (
                statement,
                proof,
                Some(commitment),
                MAX_INPUTS,
                ADMITTED_DAG_PAYMENT_DOMAIN,
            ),
            _ => return Err(ProgramError::InvalidAccountData),
        };
    let admitted = domain != PAYMENT_DOMAIN;
    if admitted && filter.is_none() {
        return Err(ShieldedPoolError::InvalidNullifierFilter.into());
    }
    let clock = Clock::get()?;
    if !statement.validate()
        || clock.slot > statement.expiry_slot
        || statement.output_tree != output_tree.address().to_bytes()
    {
        return Err(ProgramError::InvalidArgument);
    }
    let output_tree_id = {
        let bytes = output_tree.try_borrow()?;
        if !output_tree.owned_by(&crate::ID) {
            return Err(ProgramError::IllegalOwner);
        }
        let tree = TreeAccount::read_layout(&bytes).map_err(tree_error)?;
        if tree.discriminator != TREE_ACCOUNT_DISCRIMINATOR
            || tree.state != zolana_tree::INITIALIZED
        {
            return Err(ShieldedPoolError::InvalidTreeAccounts.into());
        }
        tree.tree_id
    };
    let intent = statement.intent(owner.address().as_array(), payment.address().as_array())?;
    let nullifier_capacity = match &statement.inputs {
        PaymentInputs::Certificates(addresses) => addresses
            .len()
            .checked_mul(CERTIFICATE_INPUTS)
            .ok_or(ProgramError::ArithmeticOverflow)?,
        PaymentInputs::Notes { certificate, .. } => certificate.nullifiers.len(),
    };
    let mut nullifiers = Vec::with_capacity(nullifier_capacity);
    let mut values = Vec::with_capacity(MAX_CERTIFICATES);
    {
        let bytes = input_tree.try_borrow()?;
        let tree = tree_layout(input_tree, &bytes)?;
        match &statement.inputs {
            PaymentInputs::Certificates(addresses) => {
                if commitment.is_some() {
                    return Err(ProgramError::InvalidArgument);
                }
                if addresses.len() != receipts.len() {
                    return Err(ProgramError::NotEnoughAccountKeys);
                }
                for (index, (address, receipt)) in addresses.iter().zip(receipts.iter()).enumerate()
                {
                    if address != receipt.address().as_array()
                        || addresses[..index].contains(address)
                    {
                        return Err(ProgramError::InvalidArgument);
                    }
                    let Payload::Certificate {
                        statement: certificate,
                        ..
                    } = load_payload(receipt, owner.address().as_array())?
                    else {
                        return Err(ProgramError::InvalidAccountData);
                    };
                    if !certificate.validate(CERTIFICATE_INPUTS)
                        || certificate.tree != input_tree.address().to_bytes()
                    {
                        return Err(ProgramError::InvalidAccountData);
                    }
                    let receipt_bytes = receipt.try_borrow()?;
                    let buffer = buffer::read(&receipt_bytes)?;
                    if buffer.status() != 1 {
                        return Err(ProgramError::InvalidAccountData);
                    }
                    check_freshness(tree, buffer.freshness())?;
                    if nullifiers
                        .len()
                        .checked_add(certificate.nullifiers.len())
                        .is_none_or(|count| count > MAX_INPUTS)
                    {
                        return Err(ProgramError::InvalidArgument);
                    }
                    values.push([certificate_id(address)?, certificate.value_commitment]);
                    nullifiers.extend(certificate.nullifiers);
                }
                let fields =
                    statement.balance_fields(intent, output_tree_id, &values, MAX_CERTIFICATES)?;
                verify(&proof, &fields, &spend_balance_16_2::VERIFYINGKEY)?;
            }
            PaymentInputs::Notes {
                certificate,
                freshness,
            } => {
                if !certificate.validate(capacity)
                    || !receipts.is_empty()
                    || certificate.tree != input_tree.address().to_bytes()
                    || tree.utxo.root_by_index(certificate.state_root.index).ok()
                        != Some(certificate.state_root.value)
                {
                    return Err(ProgramError::InvalidArgument);
                }
                if admitted {
                    if freshness.index != 0 || freshness.value != [0; 32] {
                        return Err(ProgramError::InvalidArgument);
                    }
                } else {
                    check_freshness(tree, *freshness)?;
                }
                let id = certificate_id(payment.address().as_array())?;
                values.push([id, certificate.value_commitment]);
                let mut fields = vec![field(domain)];
                fields.extend(certificate.fields(
                    id,
                    owner.address().as_array(),
                    tree.tree_id,
                    capacity,
                )?);
                if !admitted {
                    fields.extend(certificate.freshness_fields(
                        *freshness,
                        tree.tree_id,
                        capacity,
                    )?);
                }
                fields.extend(statement.balance_fields(intent, output_tree_id, &values, 1)?);
                let key = match (domain, commitment.is_some(), capacity) {
                    (ADMITTED_PAYMENT_DOMAIN, true, 144) => {
                        &direct_payment_admitted_144_2::VERIFYINGKEY
                    }
                    (ADMITTED_PAYMENT_DOMAIN, true, MAX_INPUTS) => {
                        &direct_payment_admitted_512_2::VERIFYINGKEY
                    }
                    (ADMITTED_DAG_PAYMENT_DOMAIN, true, MAX_INPUTS) => {
                        &direct_payment_admitted_dag10_512_2::VERIFYINGKEY
                    }
                    (PAYMENT_DOMAIN, false, MAX_INPUTS) => &direct_payment_512_2::VERIFYINGKEY,
                    (PAYMENT_DOMAIN, true, 144) => &direct_payment_gkr_144_2::VERIFYINGKEY,
                    (PAYMENT_DOMAIN, true, MAX_INPUTS) => &direct_payment_gkr_512_2::VERIFYINGKEY,
                    _ => return Err(ProgramError::InvalidArgument),
                };
                verify_with_commitment(&proof, commitment.as_ref(), &fields, key)?;
                nullifiers.extend_from_slice(&certificate.nullifiers);
            }
        }
    }
    if nullifiers.len() > MAX_INPUTS {
        return Err(ProgramError::InvalidArgument);
    }
    let input_address = input_tree.address().to_bytes();
    let result = {
        let mut tree =
            TreeAccount::from_account_view_mut(input_tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
                .map_err(tree_error)?;
        let first_input_queue_seq = tree.nullifier_tree().queue_next_index;
        for nullifier in &nullifiers {
            tree.nullifier_tree()
                .insert_nullifier_into_queue(nullifier)
                .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?;
        }
        let forester_fee = tree
            .credit_insertion_fee(nullifiers.len() as u64)
            .map_err(tree_error)?;
        if forester_fee > statement.max_forester_fee {
            return Err(ProgramError::InvalidArgument);
        }
        InputTreeResult {
            input_tree: InputTreeSequence {
                tree: input_address,
                first_input_queue_seq,
            },
            forester_fee,
            fee_balance: tree.fee_balance(),
            tree_id: tree.tree_id(),
        }
    };
    let mut nullifier_accounts = vec![pending];
    if let Some(filter) = filter {
        nullifier_accounts.push(filter);
    }
    create_nullifier_pdas(
        owner,
        input_tree,
        &mut nullifier_accounts,
        nullifiers.iter(),
        &result,
        if admitted {
            NullifierAdmission::FilterNegative
        } else {
            NullifierAdmission::ExactProof
        },
    )?;
    let first_output_leaf_index = {
        let mut tree =
            TreeAccount::from_account_view_mut(output_tree, &crate::ID, TREE_ACCOUNT_DISCRIMINATOR)
                .map_err(tree_error)?;
        let start = tree.utxo_tree().next_index();
        tree.utxo_tree()
            .append_batch(
                statement
                    .outputs
                    .iter()
                    .map(|output| &output.utxo.utxo_hash),
                clock.slot,
            )
            .map_err(tree_error)?;
        start
    };
    buffer::mark_spent(&mut payment.try_borrow_mut()?);
    // Each event fits the CPI limit and carries its own complete queue coordinates.
    let mut event_inputs = Vec::with_capacity(64);
    for (chunk_index, chunk) in nullifiers.chunks(64).enumerate() {
        event_inputs.clear();
        event_inputs.extend(chunk.iter().enumerate().map(|(index, nullifier)| Input {
            tree: input_address,
            input_queue_seq: result.input_tree.first_input_queue_seq
                + (chunk_index * 64 + index) as u64,
            nullifier: *nullifier,
        }));
        let first = chunk_index == 0;
        let event = GeneralEvent {
            inputs: std::mem::take(&mut event_inputs),
            outputs: if first {
                statement
                    .outputs
                    .iter()
                    .map(|output| output.utxo.clone())
                    .collect()
            } else {
                Vec::new()
            },
            messages: Vec::new(),
            tx_viewing_pk: statement.tx_viewing_pk,
            salt: statement.salt,
            first_output_leaf_index: first_output_leaf_index
                + if first {
                    0
                } else {
                    statement.outputs.len() as u64
                },
            output_tree: statement.output_tree,
            spl_transfers: Vec::new(),
        };
        emit_event(EventKind::DirectSpend, &event)?;
        event_inputs = event.inputs;
    }
    Ok(())
}
