use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    direct_spend::{
        certificate_id, field, Certificate, Payload, Payment, PaymentInputs, Root,
        ADMITTED_DAG_PAYMENT_DOMAIN, ADMITTED_PAYMENT_DOMAIN, CERTIFICATE_INPUTS, INLINE_INPUTS,
        MAX_CERTIFICATES, MAX_INPUTS, PAYMENT_DOMAIN,
    },
    error::ShieldedPoolError,
    event::{EventKind, GeneralEvent, Input, InputTreeSequence},
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    verifying_keys::{
        direct_payment_512_2, direct_payment_admitted_144_2, direct_payment_admitted_512_2,
        direct_payment_admitted_dag10_512_2, direct_payment_gkr_100_1, direct_payment_gkr_144_2,
        direct_payment_gkr_512_2, spend_balance_16_2, Bsb22Commitment,
    },
};
use zolana_tree::{nullifier_filter::NullifierFilter, SppTreeLayout, TreeAccount};

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
    if admitted {
        // Without non-inclusion in the proof, the filter must still cover the
        // whole history: no checkpoint has cleared it.
        let filter = filter
            .as_deref()
            .ok_or(ShieldedPoolError::InvalidNullifierFilter)?;
        if filter_checkpoint(filter, &input_tree.address().to_bytes())?.1 != 1 {
            return Err(ShieldedPoolError::NullifierFilterCheckpointed.into());
        }
    }
    let mut spend = Spend {
        owner,
        input_tree,
        output_tree,
        pending,
        filter,
    };
    let output_tree_id = spend.check_statement(&statement)?;
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
        let bytes = spend.input_tree.try_borrow()?;
        let tree = tree_layout(spend.input_tree, &bytes)?;
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
                        || certificate.tree != spend.input_tree.address().to_bytes()
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
                if !receipts.is_empty() {
                    return Err(ProgramError::InvalidArgument);
                }
                NotesProof {
                    statement: &statement,
                    certificate,
                    freshness,
                    proof: &proof,
                    commitment: commitment.as_ref(),
                    capacity,
                    domain,
                    owner: owner.address().as_array(),
                    binding: payment.address().as_array(),
                    input_tree: tree,
                    input_tree_address: &spend.input_tree.address().to_bytes(),
                    output_tree_id,
                    intent,
                    checkpoint: None,
                }
                .verify()?;
                nullifiers.extend_from_slice(&certificate.nullifiers);
            }
        }
    }
    let settled = spend.settle(&nullifiers, &statement, admitted)?;
    buffer::mark_spent(&mut payment.try_borrow_mut()?);
    emit_events(&statement, &nullifiers, &settled)
}

/// A note payment's proof and everything its public input is computed from.
pub(super) struct NotesProof<'a> {
    pub statement: &'a Payment,
    pub certificate: &'a Certificate,
    pub freshness: &'a Root,
    pub proof: &'a zolana_interface::direct_spend::Proof,
    pub commitment: Option<&'a Bsb22Commitment>,
    pub capacity: usize,
    pub domain: u64,
    pub owner: &'a [u8; 32],
    /// The buffer address, or `INLINE_BINDING` for an inline spend; it fixes
    /// the certificate id and the intent.
    pub binding: &'a [u8; 32],
    pub input_tree: &'a SppTreeLayout,
    pub input_tree_address: &'a [u8; 32],
    pub output_tree_id: u16,
    pub intent: [u8; 32],
    /// The filter's checkpoint root when freshness is proven against it
    /// instead of a root in history.
    pub checkpoint: Option<[u8; 32]>,
}

/// `(checkpoint_root, checkpoint_index)` of the tree's active filter. A
/// filter negative is only meaningful once a checkpoint rebuild has settled.
pub(super) fn filter_checkpoint(
    filter: &AccountView,
    tree: &[u8; 32],
) -> Result<([u8; 32], u64), ProgramError> {
    if !filter.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidNullifierFilter.into());
    }
    let (root, index, settled) = NullifierFilter::read_checkpoint(&filter.try_borrow()?, tree)
        .map_err(|_| ShieldedPoolError::InvalidNullifierFilter)?;
    if !settled {
        return Err(ShieldedPoolError::NullifierFilterRebuilding.into());
    }
    Ok((root, index))
}

impl NotesProof<'_> {
    /// Check the certificate against the input tree and verify the proof
    /// under the key of `(domain, capacity, outputs)`.
    pub fn verify(self) -> ProgramResult {
        let admitted = self.domain != PAYMENT_DOMAIN;
        let tree = self.input_tree;
        if !self.certificate.validate(self.capacity)
            || self.certificate.tree != *self.input_tree_address
            || tree
                .utxo
                .root_by_index(self.certificate.state_root.index)
                .ok()
                != Some(self.certificate.state_root.value)
        {
            return Err(ProgramError::InvalidArgument);
        }
        match (admitted, self.checkpoint) {
            (true, _) => {
                if self.freshness.index != 0 || self.freshness.value != [0; 32] {
                    return Err(ProgramError::InvalidArgument);
                }
            }
            (false, Some(root)) => {
                if self.freshness.index != 0 || self.freshness.value != root {
                    return Err(ProgramError::InvalidArgument);
                }
            }
            (false, None) => check_freshness(tree, *self.freshness)?,
        }
        let id = certificate_id(self.binding)?;
        let values = [[id, self.certificate.value_commitment]];
        let mut fields = vec![field(self.domain)];
        fields.extend(
            self.certificate
                .fields(id, self.owner, tree.tree_id, self.capacity)?,
        );
        if !admitted {
            fields.extend(self.certificate.freshness_fields(
                *self.freshness,
                tree.tree_id,
                self.capacity,
            )?);
        }
        fields.extend(self.statement.balance_fields(
            self.intent,
            self.output_tree_id,
            &values,
            1,
        )?);
        let outputs = self.statement.outputs.len();
        let key = match (
            self.domain,
            self.commitment.is_some(),
            self.capacity,
            outputs,
        ) {
            (PAYMENT_DOMAIN, true, INLINE_INPUTS, 1) => &direct_payment_gkr_100_1::VERIFYINGKEY,
            (ADMITTED_PAYMENT_DOMAIN, true, 144, 2) => &direct_payment_admitted_144_2::VERIFYINGKEY,
            (ADMITTED_PAYMENT_DOMAIN, true, MAX_INPUTS, 2) => {
                &direct_payment_admitted_512_2::VERIFYINGKEY
            }
            (ADMITTED_DAG_PAYMENT_DOMAIN, true, MAX_INPUTS, 2) => {
                &direct_payment_admitted_dag10_512_2::VERIFYINGKEY
            }
            (PAYMENT_DOMAIN, false, MAX_INPUTS, 2) => &direct_payment_512_2::VERIFYINGKEY,
            (PAYMENT_DOMAIN, true, 144, 2) => &direct_payment_gkr_144_2::VERIFYINGKEY,
            (PAYMENT_DOMAIN, true, MAX_INPUTS, 2) => &direct_payment_gkr_512_2::VERIFYINGKEY,
            _ => return Err(ProgramError::InvalidArgument),
        };
        verify_with_commitment(self.proof, self.commitment, &fields, key)
    }
}

/// The accounts every spend settles into.
pub(super) struct Spend<'a> {
    pub owner: &'a AccountView,
    pub input_tree: &'a mut AccountView,
    pub output_tree: &'a mut AccountView,
    pub pending: &'a mut AccountView,
    pub filter: Option<&'a mut AccountView>,
}

pub(super) struct Settled {
    pub input: InputTreeResult,
    pub first_output_leaf_index: u64,
}

impl Spend<'_> {
    /// Statement shape, expiry and output tree; returns the output tree id.
    pub fn check_statement(&self, statement: &Payment) -> Result<u16, ProgramError> {
        let clock = Clock::get()?;
        if !statement.validate()
            || clock.slot > statement.expiry_slot
            || statement.output_tree != self.output_tree.address().to_bytes()
        {
            return Err(ProgramError::InvalidArgument);
        }
        let bytes = self.output_tree.try_borrow()?;
        if !self.output_tree.owned_by(&crate::ID) {
            return Err(ProgramError::IllegalOwner);
        }
        let tree = TreeAccount::read_layout(&bytes).map_err(tree_error)?;
        if tree.discriminator != TREE_ACCOUNT_DISCRIMINATOR
            || tree.state != zolana_tree::INITIALIZED
        {
            return Err(ShieldedPoolError::InvalidTreeAccounts.into());
        }
        Ok(tree.tree_id)
    }

    /// Queue and admit `nullifiers`, charge the forester fee, append the
    /// outputs. The proof must already be verified.
    pub fn settle(
        &mut self,
        nullifiers: &[[u8; 32]],
        statement: &Payment,
        admitted: bool,
    ) -> Result<Settled, ProgramError> {
        if nullifiers.len() > MAX_INPUTS {
            return Err(ProgramError::InvalidArgument);
        }
        let input_address = self.input_tree.address().to_bytes();
        let input = {
            let mut tree = TreeAccount::from_account_view_mut(
                self.input_tree,
                &crate::ID,
                TREE_ACCOUNT_DISCRIMINATOR,
            )
            .map_err(tree_error)?;
            let first_input_queue_seq = tree.nullifier_tree().queue_next_index;
            for nullifier in nullifiers {
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
        let mut nullifier_accounts = vec![&mut *self.pending];
        if let Some(filter) = self.filter.as_deref_mut() {
            nullifier_accounts.push(filter);
        }
        create_nullifier_pdas(
            self.owner,
            self.input_tree,
            &mut nullifier_accounts,
            nullifiers.iter(),
            &input,
            if admitted {
                NullifierAdmission::FilterNegative
            } else {
                NullifierAdmission::ExactProof
            },
        )?;
        let first_output_leaf_index = {
            let mut tree = TreeAccount::from_account_view_mut(
                self.output_tree,
                &crate::ID,
                TREE_ACCOUNT_DISCRIMINATOR,
            )
            .map_err(tree_error)?;
            let start = tree.utxo_tree().next_index();
            tree.utxo_tree()
                .append_batch(
                    statement
                        .outputs
                        .iter()
                        .map(|output| &output.utxo.utxo_hash),
                    Clock::get()?.slot,
                )
                .map_err(tree_error)?;
            start
        };
        Ok(Settled {
            input,
            first_output_leaf_index,
        })
    }
}

/// One event per 64 nullifiers, each within the CPI limit and carrying its
/// own complete queue coordinates.
pub(super) fn emit_events(
    statement: &Payment,
    nullifiers: &[[u8; 32]],
    settled: &Settled,
) -> ProgramResult {
    let input_address = settled.input.input_tree.tree;
    let mut event_inputs = Vec::with_capacity(64);
    for (chunk_index, chunk) in nullifiers.chunks(64).enumerate() {
        event_inputs.clear();
        event_inputs.extend(chunk.iter().enumerate().map(|(index, nullifier)| Input {
            tree: input_address,
            input_queue_seq: settled.input.input_tree.first_input_queue_seq
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
            first_output_leaf_index: settled.first_output_leaf_index
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
