use ark_r1cs_std::R1CSVar;
use zolana_interface::UTXO_DOMAIN;
use zolana_program::{
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};

use super::{
    constant, hash_chain4, poseidon, utxo::Output, zero, CircuitVar, DataUtxo, OutputTokenUtxo,
    TokenUtxo, Utxo, UtxoData,
};
use crate::RelationError;

#[derive(Clone, Debug)]
pub struct TxContext {
    pub first_nullifier: CircuitVar,
    pub blinding_seed: CircuitVar,
    pub output_tree_id: CircuitVar,
    pub sender: CircuitVar,
}

impl TxContext {
    pub fn private_tx_blinding(&self) -> Result<CircuitVar, RelationError> {
        poseidon(&[
            constant(u64::from(DOMAIN_PRIVATE_TX_BLINDING_V1)),
            self.first_nullifier.clone(),
            self.blinding_seed.clone(),
        ])
    }

    fn output_blinding(
        &self,
        output_blinding_seed: &CircuitVar,
        slot: usize,
    ) -> Result<CircuitVar, RelationError> {
        let slot = u64::try_from(slot).map_err(|_| RelationError::Slot {
            kind: "output",
            slot,
            problem: "is outside the transaction",
        })?;
        poseidon(&[
            constant(u64::from(DOMAIN_TRANSACT_OUTPUT_BLINDING_V1)),
            self.first_nullifier.clone(),
            output_blinding_seed.clone(),
            constant(slot),
        ])
    }

    fn output_blinding_seed(&self) -> Result<CircuitVar, RelationError> {
        poseidon(&[
            constant(u64::from(DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1)),
            self.first_nullifier.clone(),
            self.blinding_seed.clone(),
        ])
    }

    fn is_native(&self) -> bool {
        self.first_nullifier.is_constant()
    }
}

pub trait PublicInputs {
    fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError>;
}

#[cfg_attr(not(feature = "client"), allow(dead_code))]
#[derive(Clone, Debug)]
pub(crate) struct CheckedOutput {
    pub(crate) output: Output,
    pub(crate) hash: CircuitVar,
}

#[cfg_attr(not(feature = "client"), allow(dead_code))]
#[derive(Clone, Debug)]
pub struct CheckedTransaction {
    pub(crate) tx_context: TxContext,
    pub(crate) inputs: Vec<CircuitVar>,
    pub(crate) outputs: Vec<CheckedOutput>,
    pub(crate) private_tx_hash: CircuitVar,
    public_hash: CircuitVar,
}

impl CheckedTransaction {
    pub fn public_hash(&self) -> &CircuitVar {
        &self.public_hash
    }

    pub fn private_tx_hash(&self) -> &CircuitVar {
        &self.private_tx_hash
    }
}

#[must_use]
pub struct ConfidentialTransaction<'a, P, const IN: usize, const OUT: usize> {
    tx_context: &'a TxContext,
    public: &'a P,
    inputs: Vec<CircuitVar>,
    outputs: Vec<Output>,
    error: Option<RelationError>,
}

impl<'a, P: PublicInputs, const IN: usize, const OUT: usize>
    ConfidentialTransaction<'a, P, IN, OUT>
{
    pub fn new(tx_context: &'a TxContext, public: &'a P) -> Self {
        Self {
            tx_context,
            public,
            inputs: Vec::with_capacity(IN),
            outputs: Vec::with_capacity(OUT),
            error: None,
        }
    }

    pub fn with_token_utxos<const N: usize>(mut self, token: TokenUtxo<N>) -> Self {
        self.inputs.extend(token.input_hashes().iter().cloned());
        match token.change() {
            Ok(Some(change)) => self.outputs.push(change),
            Ok(None) => {}
            Err(error) => self.record(error),
        }
        self
    }

    pub fn with_output_token_utxo(mut self, output: OutputTokenUtxo) -> Self {
        self.outputs.push(Output::from(output));
        self
    }

    pub fn with_data_utxo<S: UtxoData>(mut self, utxo: DataUtxo<S>) -> Self {
        if let Some(input_hash) = utxo.input_hash() {
            self.inputs.push(input_hash);
        }
        let output = utxo.output().and_then(|output| {
            output
                .map(|mut output| {
                    if self.tx_context.is_native() {
                        output.data = Some(utxo.utxo_data()?);
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
        self
    }

    pub fn check(self) -> Result<CheckedTransaction, RelationError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.inputs.is_empty() {
            return Err(RelationError::Violated(
                "a transaction spends at least one input",
            ));
        }
        let inputs = padded("input", self.inputs, IN)?;
        if self.outputs.len() > OUT {
            return Err(RelationError::Slot {
                kind: "output",
                slot: OUT,
                problem: "is outside the transaction",
            });
        }
        let mut outputs = self.outputs;
        while outputs.len() < OUT {
            outputs.push(Output::padding(&self.tx_context.sender)?);
        }
        let output_blinding_seed = self.tx_context.output_blinding_seed()?;
        let outputs = outputs
            .into_iter()
            .enumerate()
            .map(|(slot, output)| {
                let blinding = self
                    .tx_context
                    .output_blinding(&output_blinding_seed, slot)?;
                let hash = Utxo {
                    domain: constant(u64::from(UTXO_DOMAIN)),
                    owner: output.owner.clone(),
                    asset: output.asset.clone(),
                    amount: output.amount.clone(),
                    blinding,
                    data_hash: output.data_hash.clone(),
                    ring_data_hash: zero(),
                    ring_program_id: zero(),
                    tree_id: self.tx_context.output_tree_id.clone(),
                }
                .hash()?;
                Ok(CheckedOutput { output, hash })
            })
            .collect::<Result<Vec<_>, RelationError>>()?;
        let output_hashes: Vec<CircuitVar> =
            outputs.iter().map(|output| output.hash.clone()).collect();
        let private_tx_hash = poseidon(&[
            hash_chain4(&inputs)?,
            hash_chain4(&output_hashes)?,
            hash_chain4(&vec![zero(); IN])?,
            self.tx_context.private_tx_blinding()?,
        ])?;
        let public_hash = self.public.hash(&private_tx_hash)?;
        Ok(CheckedTransaction {
            tx_context: self.tx_context.clone(),
            inputs,
            outputs,
            private_tx_hash,
            public_hash,
        })
    }

    fn record(&mut self, error: RelationError) {
        self.error.get_or_insert(error);
    }
}

fn padded(
    kind: &'static str,
    mut hashes: Vec<CircuitVar>,
    slots: usize,
) -> Result<Vec<CircuitVar>, RelationError> {
    if hashes.len() > slots {
        return Err(RelationError::Slot {
            kind,
            slot: slots,
            problem: "is outside the transaction",
        });
    }
    hashes.resize(slots, zero());
    Ok(hashes)
}
