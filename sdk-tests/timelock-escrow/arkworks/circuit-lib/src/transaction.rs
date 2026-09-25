use zolana_interface::UTXO_DOMAIN;
use zolana_program::{
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};

use crate::{
    constant, poseidon, utxo::Output, zero, Allocator, CircuitVar, DataHash, DataUtxo,
    OutputTokenUtxo, ProofInput, RelationError, TokenUtxo, Utxo,
};

#[derive(Clone, Debug)]
pub struct TxContext {
    pub first_nullifier: CircuitVar,
    pub blinding_seed: CircuitVar,
    pub output_tree_id: CircuitVar,
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
}

impl ProofInput for TxContext {
    type Circuit = TxContext;

    fn instantiate(&self, allocator: &Allocator) -> Result<TxContext, RelationError> {
        Ok(Self {
            first_nullifier: self.first_nullifier.instantiate(allocator)?,
            blinding_seed: self.blinding_seed.instantiate(allocator)?,
            output_tree_id: self.output_tree_id.instantiate(allocator)?,
        })
    }
}

pub trait PublicInputs {
    fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError>;
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
            Err(error) => {
                self.error.get_or_insert(error);
            }
        }
        self
    }

    pub fn with_output_token_utxo(mut self, output: OutputTokenUtxo) -> Self {
        self.outputs.push(output.output());
        self
    }

    pub fn with_data_utxo<S: DataHash>(mut self, utxo: DataUtxo<S>) -> Self {
        if let Some(input_hash) = utxo.input_hash() {
            self.inputs.push(input_hash);
        }
        match utxo.output() {
            Ok(Some(output)) => self.outputs.push(output),
            Ok(None) => {}
            Err(error) => {
                self.error.get_or_insert(error);
            }
        }
        self
    }

    pub fn check(self) -> Result<CircuitVar, RelationError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.inputs.is_empty() {
            return Err(RelationError::Violated(
                "a transaction spends at least one input",
            ));
        }
        let inputs = padded("input", self.inputs, IN)?;
        let output_blinding_seed = self.tx_context.output_blinding_seed()?;
        let output_hashes = self
            .outputs
            .into_iter()
            .enumerate()
            .map(|(slot, output)| {
                Utxo {
                    domain: constant(u64::from(UTXO_DOMAIN)),
                    owner: output.owner,
                    asset: output.asset,
                    amount: output.amount,
                    blinding: self
                        .tx_context
                        .output_blinding(&output_blinding_seed, slot)?,
                    data_hash: output.data_hash,
                    ring_data_hash: zero(),
                    ring_program_id: zero(),
                    tree_id: self.tx_context.output_tree_id.clone(),
                }
                .hash()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = padded("output", output_hashes, OUT)?;
        let private_tx_hash = poseidon(&[
            hash_chain4(&inputs)?,
            hash_chain4(&outputs)?,
            hash_chain4(&vec![zero(); IN])?,
            self.tx_context.private_tx_blinding()?,
        ])?;
        self.public.hash(&private_tx_hash)
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

pub fn hash_chain4(values: &[CircuitVar]) -> Result<CircuitVar, RelationError> {
    let Some((first, rest)) = values.split_first() else {
        return Ok(zero());
    };
    let mut chain = first.clone();
    for group in rest.chunks(3) {
        let mut block = vec![chain];
        block.extend(group.iter().cloned());
        block.resize(4, zero());
        chain = poseidon(&block)?;
    }
    Ok(chain)
}
