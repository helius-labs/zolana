use ark_ff::Zero;
use spr_instruction::{
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};

use super::utxo::{CreatedAddress, Output, SpentInput};
use crate::{
    circuit::{
        builtins::field::var::system_of, constant, labels::Scope, nonzero_hash_chain, poseidon,
        zero, Assert, Bool, CircuitType, CircuitVar, DataHash, DataUtxo, NewAddress,
        PublicHashOutput, PublicTransfer, TokenUtxos, Uint, UniqueDataUtxo, UtxoData, UtxoMeta,
    },
    CircuitError, CircuitErrorKind,
};

#[derive(Clone, Debug)]
pub struct TxContext {
    pub(crate) native: bool,
    pub blinding_seed: CircuitVar,
    pub output_tree_id: Uint<16>,
    pub uses_output_tree_id: Bool,
}

impl TxContext {
    #[track_caller]
    fn output_tree_id(&self, first: &SpentInput) -> Result<CircuitVar, CircuitError> {
        self.uses_output_tree_id
            .or(&first.meta.has_latest_tree_id)
            .var()
            .assert_equal(
                &constant(1u64),
                "the first input reports no latest tree and the transaction sets no output tree",
            )?;
        Ok(self
            .uses_output_tree_id
            .select(&self.output_tree_id.var(), &first.meta.latest_tree_id))
    }

    fn is_native(&self) -> bool {
        self.native
    }
}

fn private_tx_blinding(
    first_nullifier: &CircuitVar,
    blinding_seed: &CircuitVar,
) -> Result<CircuitVar, CircuitError> {
    poseidon(&[
        constant(u64::from(DOMAIN_PRIVATE_TX_BLINDING_V1)),
        first_nullifier.clone(),
        blinding_seed.clone(),
    ])
}

fn output_blinding_seed(
    first_nullifier: &CircuitVar,
    blinding_seed: &CircuitVar,
) -> Result<CircuitVar, CircuitError> {
    poseidon(&[
        constant(u64::from(DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1)),
        first_nullifier.clone(),
        blinding_seed.clone(),
    ])
}

fn output_blinding(
    first_nullifier: &CircuitVar,
    output_blinding_seed: &CircuitVar,
    slot: usize,
) -> Result<CircuitVar, CircuitError> {
    let slot = u64::try_from(slot).map_err(|_| CircuitErrorKind::ValueTooLarge { bits: 64 })?;
    poseidon(&[
        constant(u64::from(DOMAIN_TRANSACT_OUTPUT_BLINDING_V1)),
        first_nullifier.clone(),
        output_blinding_seed.clone(),
        constant(slot),
    ])
}

pub trait PublicInputs {
    fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, CircuitError>;
}

/// A UTXO or address reservation that can be registered in a transaction.
pub trait TransactionItem {
    #[track_caller]
    fn register<P: PublicInputs>(self, transaction: &mut ConfidentialTransaction<'_, P>);
}

#[cfg_attr(not(feature = "client"), allow(dead_code))]
#[derive(Clone, Debug)]
pub(crate) struct CheckedOutput {
    pub(crate) output: Output,
    pub(crate) hash: CircuitVar,
    pub(crate) empty: Bool,
}

impl CheckedOutput {
    fn private_hash(&self) -> CircuitVar {
        if self.output.empty_if_zero {
            self.empty.select(&zero(), &self.hash)
        } else {
            self.hash.clone()
        }
    }
}

#[cfg_attr(not(feature = "client"), allow(dead_code))]
#[derive(Clone, Debug)]
pub struct CheckedTransaction {
    pub(crate) preserve_input_slots: bool,
    pub(crate) blinding_seed: CircuitVar,
    pub(crate) first_nullifier: CircuitVar,
    pub(crate) output_tree_id: CircuitVar,
    pub(crate) inputs: Vec<CircuitVar>,
    pub(crate) addresses: Vec<CreatedAddress>,
    pub(crate) outputs: Vec<CheckedOutput>,
    pub(crate) public_transfers: Vec<PublicTransfer>,
    pub(crate) private_tx_hash: CircuitVar,
    pub(crate) transaction_hash: CircuitVar,
    public_hash: CircuitVar,
}

impl CheckedTransaction {
    pub fn public_hash(&self) -> &CircuitVar {
        &self.public_hash
    }

    pub fn private_tx_hash(&self) -> &CircuitVar {
        &self.private_tx_hash
    }

    pub fn transaction_hash(&self) -> &CircuitVar {
        &self.transaction_hash
    }
}

#[must_use]
pub struct ConfidentialTransaction<'a, P> {
    tx_context: &'a TxContext,
    public: &'a P,
    inputs: Vec<(SpentInput, Bool)>,
    addresses: Vec<CreatedAddress>,
    outputs: Vec<Output>,
    public_transfers: Vec<PublicTransfer>,
    transferred: CircuitVar,
    error: Option<CircuitError>,
    preserve_input_slots: bool,
}

impl<'a, P: PublicInputs> ConfidentialTransaction<'a, P> {
    /// Starts a transaction with compact padding by default.
    pub fn new(tx_context: &'a TxContext, public: &'a P) -> Self {
        Self {
            tx_context,
            public,
            inputs: Vec::new(),
            addresses: Vec::new(),
            outputs: Vec::new(),
            public_transfers: Vec::new(),
            transferred: zero(),
            error: None,
            preserve_input_slots: false,
        }
    }

    /// Preserve dummy input slots and publish dummy padding, so the SPP shape
    /// does not disclose how many of an application's optional inputs exist.
    pub fn with_dummy_padding(mut self) -> Self {
        self.preserve_input_slots = true;
        self
    }

    /// Registers a UTXO or address reservation, deferring errors to `check()`.
    #[track_caller]
    pub fn with(mut self, item: impl TransactionItem) -> Self {
        item.register(&mut self);
        self
    }

    #[track_caller]
    fn add_data_utxo<S: DataHash>(
        &mut self,
        utxo: &DataUtxo<S>,
        data: impl FnOnce() -> Result<Option<Vec<u8>>, CircuitError>,
    ) {
        self.inputs.extend(
            utxo.spent_input()
                .map(|input| (input, Bool::constant(false))),
        );
        self.public_transfers
            .extend(utxo.public_transfers().iter().cloned());
        self.transferred = self.transferred.plus(utxo.transferred());
        let native = self.tx_context.is_native();
        let output = utxo.output().and_then(|output| {
            output
                .map(|mut output| {
                    if native {
                        output.data = data()?;
                    }
                    Ok(output)
                })
                .transpose()
        });
        match output {
            Ok(Some(output)) => self.outputs.push(output),
            Ok(None) => {}
            Err(error) => self.record(error),
        }
    }

    #[track_caller]
    pub fn check(self) -> Result<CheckedTransaction, CircuitError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let inputs: Vec<SpentInput> = self
            .addresses
            .iter()
            .map(address_slot)
            .chain(ordered_inputs(self.inputs))
            .collect();
        let _scope = Scope::open(
            &system_of(
                [&self.tx_context.blinding_seed, &self.transferred]
                    .into_iter()
                    .chain(inputs.iter().map(|input| &input.hash)),
            ),
            "the transaction's outputs and hashes",
        );
        self.transferred.assert_equal(
            &zero(),
            "value leaves the transaction: a utxo was not added",
        )?;
        let first = inputs.first().ok_or(CircuitErrorKind::RuleBroken(
            "a transaction spends at least one input",
        ))?;
        let first_nullifier = first.meta.nullifier.clone();
        let output_tree_id = self.tx_context.output_tree_id(first)?;
        let blinding_seed = self.tx_context.blinding_seed.clone();
        let output_blinding_seed = output_blinding_seed(&first_nullifier, &blinding_seed)?;
        let empties = trailing_empties(&self.outputs)?;
        let outputs = self
            .outputs
            .into_iter()
            .zip(empties)
            .enumerate()
            .map(|(slot, (output, empty))| {
                let blinding = output_blinding(&first_nullifier, &output_blinding_seed, slot)?;
                let hash = output.hash(&empty, blinding, output_tree_id.clone())?;
                Ok(CheckedOutput {
                    output,
                    hash,
                    empty,
                })
            })
            .collect::<Result<Vec<_>, CircuitError>>()?;
        let input_hashes: Vec<CircuitVar> = inputs.iter().map(|input| input.hash.clone()).collect();
        let output_hashes: Vec<CircuitVar> =
            outputs.iter().map(CheckedOutput::private_hash).collect();
        let private_tx_hash = poseidon(&[
            nonzero_hash_chain(&input_hashes)?,
            nonzero_hash_chain(&output_hashes)?,
            nonzero_hash_chain(
                &self
                    .addresses
                    .iter()
                    .map(|created| created.address.clone())
                    .collect::<Vec<_>>(),
            )?,
            private_tx_blinding(&first_nullifier, &blinding_seed)?,
        ])?;
        let transaction_hash = transaction_hash(&private_tx_hash, &self.public_transfers)?;
        let public_hash = self.public.hash(&transaction_hash)?;
        Ok(CheckedTransaction {
            preserve_input_slots: self.preserve_input_slots,
            blinding_seed,
            first_nullifier,
            output_tree_id,
            inputs: input_hashes,
            addresses: self.addresses,
            outputs,
            public_transfers: self.public_transfers,
            private_tx_hash,
            transaction_hash,
            public_hash,
        })
    }

    fn record(&mut self, error: CircuitError) {
        self.error.get_or_insert(error);
    }
}

impl TransactionItem for NewAddress {
    fn register<P: PublicInputs>(self, transaction: &mut ConfidentialTransaction<'_, P>) {
        transaction.addresses.push(self.created);
    }
}

impl TransactionItem for TokenUtxos {
    #[track_caller]
    fn register<P: PublicInputs>(self, transaction: &mut ConfidentialTransaction<'_, P>) {
        transaction
            .inputs
            .extend(self.spent_inputs().iter().cloned());
        transaction
            .public_transfers
            .extend(self.public_transfers().iter().cloned());
        transaction.transferred = transaction.transferred.plus(self.transferred());
        match self.change() {
            Ok(Some(change)) => transaction.outputs.push(change),
            Ok(None) => {}
            Err(error) => transaction.record(error),
        }
    }
}

impl<S: UtxoData> TransactionItem for DataUtxo<S> {
    #[track_caller]
    fn register<P: PublicInputs>(self, transaction: &mut ConfidentialTransaction<'_, P>) {
        transaction.add_data_utxo(&self, || self.utxo_data().map(Some));
    }
}

impl TransactionItem for DataUtxo<CircuitVar> {
    #[track_caller]
    fn register<P: PublicInputs>(self, transaction: &mut ConfidentialTransaction<'_, P>) {
        transaction.add_data_utxo(&self, || Ok(None));
    }
}

impl<S: UtxoData> TransactionItem for UniqueDataUtxo<S> {
    #[track_caller]
    fn register<P: PublicInputs>(self, transaction: &mut ConfidentialTransaction<'_, P>) {
        transaction.addresses.extend(self.created_address());
        transaction.add_data_utxo(self.data_utxo(), || self.utxo_data());
    }
}

// Stable partition using circuit selections: the input count and output order
// remain fixed while every real input precedes every dummy input.
fn ordered_inputs(mut inputs: Vec<(SpentInput, Bool)>) -> Vec<SpentInput> {
    for end in (1..inputs.len()).rev() {
        for index in 0..end {
            let (left, right) = inputs.split_at_mut(index + 1);
            let (left, left_dummy) = &mut left[index];
            let (right, right_dummy) = &mut right[0];
            let swap = left_dummy.and(&right_dummy.not());
            let selected_left = select_input(&swap, right, left);
            let selected_right = select_input(&swap, left, right);
            let selected_left_dummy = swap.select(right_dummy, left_dummy);
            let selected_right_dummy = swap.select(left_dummy, right_dummy);
            *left = selected_left;
            *right = selected_right;
            *left_dummy = selected_left_dummy;
            *right_dummy = selected_right_dummy;
        }
    }
    inputs.into_iter().map(|(input, _)| input).collect()
}

fn select_input(condition: &Bool, if_true: &SpentInput, if_false: &SpentInput) -> SpentInput {
    SpentInput {
        hash: condition.select(&if_true.hash, &if_false.hash),
        meta: UtxoMeta {
            nullifier: condition.select(&if_true.meta.nullifier, &if_false.meta.nullifier),
            latest_tree_id: condition
                .select(&if_true.meta.latest_tree_id, &if_false.meta.latest_tree_id),
            has_latest_tree_id: condition.select(
                &if_true.meta.has_latest_tree_id,
                &if_false.meta.has_latest_tree_id,
            ),
        },
    }
}

#[track_caller]
fn trailing_empties(outputs: &[Output]) -> Result<Vec<Bool>, CircuitError> {
    let mut later_empty = Bool::constant(true);
    let mut token_suffix = true;
    let mut empties = outputs
        .iter()
        .rev()
        .map(|output| {
            token_suffix &= output.empty_if_zero;
            if !token_suffix {
                later_empty = Bool::constant(false);
                return Ok(later_empty.clone());
            }
            later_empty = match later_empty.var().constant_value() {
                Some(value) if value.is_zero() => Bool::constant(false),
                Some(_) => output.is_zero()?,
                None => output.is_zero()?.and(&later_empty),
            };
            Ok(later_empty.clone())
        })
        .collect::<Result<Vec<_>, CircuitError>>()?;
    empties.reverse();
    Ok(empties)
}

fn address_slot(address: &CreatedAddress) -> SpentInput {
    SpentInput {
        hash: zero(),
        meta: UtxoMeta {
            nullifier: address.address.clone(),
            ..UtxoMeta::default()
        },
    }
}

fn transaction_hash(
    private_tx_hash: &CircuitVar,
    public_transfers: &[PublicTransfer],
) -> Result<CircuitVar, CircuitError> {
    if public_transfers.is_empty() {
        return Ok(private_tx_hash.clone());
    }
    let transfers_hash = public_transfers
        .iter()
        .try_fold(zero(), |chain, transfer| {
            poseidon(&[chain, transfer.hash()?])
        })?;
    poseidon(&[private_tx_hash.clone(), transfers_hash])
}

impl CircuitType for TxContext {}

impl PublicHashOutput for CheckedTransaction {
    fn public_hash(&self) -> &CircuitVar {
        CheckedTransaction::public_hash(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::{ConstraintSystem, SolanaAddress, UtxoOwner, VariableRole},
        conversion::Allocator,
    };
    use ark_bn254::Fr;

    #[test]
    fn a_data_output_makes_every_earlier_slot_statically_nonempty() {
        let cs = ConstraintSystem::new_ref();
        let output = |empty_if_zero| Output {
            owner: UtxoOwner::default(),
            asset: SolanaAddress::constant(&spr_transaction::SOL_MINT),
            amount: Uint::trusted(
                Allocator::R1cs(cs.clone())
                    .witness(Fr::from(0u64), "an amount", VariableRole::Constrained)
                    .unwrap(),
            ),
            data_hash: zero(),
            data: None,
            empty_if_zero,
        };
        let flags = trailing_empties(&[output(true), output(false), output(true)]).unwrap();
        assert_eq!(flags.len(), 3);
        for flag in flags.iter().take(2) {
            assert_eq!(flag.var().constant_value(), Some(Fr::from(0u64)));
        }
        assert!(flags.last().unwrap().var().constant_value().is_none());
    }
}
