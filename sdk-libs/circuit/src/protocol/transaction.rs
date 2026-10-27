use crate::{CircuitError, CircuitErrorKind, Field, poseidon, nonzero_hash_chain, require, require_eq};
use crate::protocol::{PublicTransfer, DataUtxo, TokenUtxos, UniqueDataUtxo, UtxoData, NewAddress};
use super::utxo::{CreatedAddress, Output, SpentInput};
use zolana_instruction::{DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_V1};

#[xark::input]
pub struct TxContext { pub blinding_seed: Field, pub output_tree_id: u16, pub uses_output_tree_id: bool }
impl TxContext {
    fn output_tree(&self, first: &SpentInput) -> u16 {
        require(self.uses_output_tree_id || first.meta.has_latest_tree_id);
        if self.uses_output_tree_id { self.output_tree_id } else { first.meta.latest_tree_id }
    }
}

pub trait PublicInputs { fn hash(&self, transaction_hash: &Field) -> Result<Field, CircuitError>; }

#[derive(Clone, Debug)]
pub struct CheckedOutput { pub output: Output, pub hash: Field, pub empty: bool }

#[derive(Clone, Debug)]
pub struct CheckedTransaction {
    pub preserve_input_slots: bool, pub blinding_seed: Field, pub first_nullifier: Field,
    pub output_tree_id: u16, pub inputs: Vec<Field>, pub addresses: Vec<CreatedAddress>,
    pub outputs: Vec<CheckedOutput>, pub public_transfers: Vec<PublicTransfer>,
    private_tx_hash: Field, transaction_hash: Field, public_hash: Field,
}
impl CheckedTransaction {
    pub fn private_tx_hash(&self) -> &Field { &self.private_tx_hash }
    pub fn transaction_hash(&self) -> &Field { &self.transaction_hash }
    pub fn public_hash(&self) -> &Field { &self.public_hash }
}

pub trait TransactionItem {
    fn register<P: PublicInputs>(self, transaction: &mut ConfidentialTransaction<'_, P>);
}

#[must_use]
pub struct ConfidentialTransaction<'a, P> {
    context: &'a TxContext, public: &'a P, inputs: Vec<(SpentInput, bool)>,
    addresses: Vec<CreatedAddress>, outputs: Vec<Output>, public_transfers: Vec<PublicTransfer>,
    transferred: Field, error: Option<CircuitError>, preserve_input_slots: bool,
}
impl<'a, P: PublicInputs> ConfidentialTransaction<'a, P> {
    pub fn new(context: &'a TxContext, public: &'a P) -> Self {
        Self { context, public, inputs: Vec::new(), addresses: Vec::new(), outputs: Vec::new(),
            public_transfers: Vec::new(), transferred: Field::zero(), error: None, preserve_input_slots: false }
    }
    pub fn with_dummy_padding(mut self) -> Self { self.preserve_input_slots = true; self }
    pub fn with(mut self, item: impl TransactionItem) -> Self { item.register(&mut self); self }
    fn add_data<S: super::DataHash>(&mut self, utxo: &DataUtxo<S>, data: impl FnOnce() -> Result<Option<Vec<u8>>, CircuitError>) {
        if let Some(input) = utxo.spent_input() { self.inputs.push((input, false)); }
        self.public_transfers.extend_from_slice(utxo.public_transfers());
        self.transferred += *utxo.transferred();
        match utxo.output() {
            Ok(Some(output)) => {
                #[cfg(not(xark))]
                let mut output = output;
                #[cfg(not(xark))]
                match data() { Ok(bytes) => output.data = bytes, Err(error) => { self.error = Some(error); return; } }
                #[cfg(xark)]
                let _ = data;
                self.outputs.push(output);
            },
            Ok(None) => {},
            Err(error) => self.error = Some(error),
        }
    }
    pub fn check(self) -> Result<CheckedTransaction, CircuitError> {
        if let Some(error) = self.error { return Err(error); }
        require_eq(self.transferred, Field::zero());
        let mut slots = Vec::new();
        for address in &self.addresses {
            slots.push(SpentInput { hash: Field::zero(), meta: super::UtxoMeta { nullifier: address.address, ..super::UtxoMeta::default() } });
        }
        slots.extend(ordered_inputs(self.inputs));
        let first = slots.first().ok_or(CircuitErrorKind::RuleBroken("a transaction spends at least one input"))?;
        let first_nullifier = first.meta.nullifier;
        let output_tree_id = self.context.output_tree(first);
        let blinding_seed = self.context.blinding_seed;
        let output_seed = poseidon(&[Field::from(DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1), first_nullifier, blinding_seed])?;
        let private_blinding = poseidon(&[Field::from(DOMAIN_PRIVATE_TX_BLINDING_V1), first_nullifier, blinding_seed])?;
        let empties = trailing_empties(&self.outputs);
        let mut outputs = Vec::with_capacity(self.outputs.len());
        for (slot, (output, empty)) in self.outputs.into_iter().zip(empties).enumerate() {
            let blinding = poseidon(&[Field::from(DOMAIN_TRANSACT_OUTPUT_BLINDING_V1), first_nullifier, output_seed, Field::from(slot as u64)])?;
            let hash = output.hash(empty, blinding, output_tree_id)?;
            outputs.push(CheckedOutput { output, hash, empty });
        }
        let inputs: Vec<_> = slots.iter().map(|slot| slot.hash).collect();
        let output_hashes: Vec<_> = outputs.iter().map(|output| if output.empty { Field::zero() } else { output.hash }).collect();
        let addresses: Vec<_> = self.addresses.iter().map(|address| address.address).collect();
        let private_tx_hash = poseidon(&[nonzero_hash_chain(&inputs)?, nonzero_hash_chain(&output_hashes)?, nonzero_hash_chain(&addresses)?, private_blinding])?;
        let mut transaction_hash = private_tx_hash;
        if !self.public_transfers.is_empty() {
            let mut chain = Field::zero();
            for transfer in &self.public_transfers { chain = poseidon(&[chain, transfer.hash()?])?; }
            transaction_hash = poseidon(&[private_tx_hash, chain])?;
        }
        let public_hash = self.public.hash(&transaction_hash)?;
        Ok(CheckedTransaction { preserve_input_slots: self.preserve_input_slots, blinding_seed, first_nullifier,
            output_tree_id, inputs, addresses: self.addresses, outputs, public_transfers: self.public_transfers,
            private_tx_hash, transaction_hash, public_hash })
    }
}
impl TransactionItem for NewAddress {
    fn register<P: PublicInputs>(self, tx: &mut ConfidentialTransaction<'_, P>) { tx.addresses.push(self.created); }
}
impl TransactionItem for TokenUtxos {
    fn register<P: PublicInputs>(self, tx: &mut ConfidentialTransaction<'_, P>) {
        tx.inputs.extend_from_slice(self.spent_inputs());
        tx.public_transfers.extend_from_slice(self.public_transfers());
        tx.transferred += *self.transferred();
        match self.change() { Ok(Some(output)) => tx.outputs.push(output), Ok(None) => {}, Err(error) => tx.error = Some(error) }
    }
}
impl<S: UtxoData> TransactionItem for DataUtxo<S> {
    fn register<P: PublicInputs>(self, tx: &mut ConfidentialTransaction<'_, P>) { tx.add_data(&self, || self.utxo_data().map(Some)); }
}
impl TransactionItem for DataUtxo<Field> {
    fn register<P: PublicInputs>(self, tx: &mut ConfidentialTransaction<'_, P>) { tx.add_data(&self, || Ok(None)); }
}
impl<S: UtxoData> TransactionItem for UniqueDataUtxo<S> {
    fn register<P: PublicInputs>(self, tx: &mut ConfidentialTransaction<'_, P>) {
        if let Some(address) = self.created_address() { tx.addresses.push(address); }
        tx.add_data(self.data_utxo(), || self.utxo_data());
    }
}
fn ordered_inputs(mut inputs: Vec<(SpentInput, bool)>) -> Vec<SpentInput> {
    for end in (1..inputs.len()).rev() {
        for i in 0..end {
            let left = inputs[i];
            let right = inputs[i + 1];
            if left.1 && !right.1 { inputs[i] = right; inputs[i + 1] = left; }
        }
    }
    inputs.into_iter().map(|(input, _)| input).collect()
}
fn trailing_empties(outputs: &[Output]) -> Vec<bool> {
    let mut later_empty = true;
    let mut token_suffix = true;
    let mut empties = Vec::with_capacity(outputs.len());
    for output in outputs.iter().rev() {
        token_suffix &= output.empty_if_zero;
        later_empty = token_suffix && later_empty && output.is_zero();
        empties.push(later_empty);
    }
    empties.reverse();
    empties
}
