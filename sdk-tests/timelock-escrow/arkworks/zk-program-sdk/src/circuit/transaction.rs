use ark_r1cs_std::R1CSVar;
use zolana_interface::UTXO_DOMAIN;
use zolana_program::{
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};

use super::{
    constant, nonzero_hash_chain, poseidon,
    utxo::{Output, SpentInput},
    zero, Assert, Bool, CircuitVar, DataUtxo, OutputTokenUtxo, PublicTransfer, TokenUtxo, Utxo,
    UtxoData,
};
use crate::RelationError;

#[derive(Clone, Debug)]
pub struct TxContext {
    pub blinding_seed: CircuitVar,
    pub output_tree_id: CircuitVar,
    pub uses_output_tree_id: Bool,
}

impl TxContext {
    fn output_tree_id(&self, first: &SpentInput) -> Result<CircuitVar, RelationError> {
        self.uses_output_tree_id
            .or(&first.has_latest_tree_id)
            .var()
            .assert_equal(
                &constant(1u64),
                "the first input reports no latest tree and the transaction sets no output tree",
            )?;
        Ok(self
            .uses_output_tree_id
            .select(&self.output_tree_id, &first.latest_tree_id))
    }

    fn is_native(&self) -> bool {
        self.blinding_seed.is_constant()
    }
}

fn private_tx_blinding(
    first_nullifier: &CircuitVar,
    blinding_seed: &CircuitVar,
) -> Result<CircuitVar, RelationError> {
    poseidon(&[
        constant(u64::from(DOMAIN_PRIVATE_TX_BLINDING_V1)),
        first_nullifier.clone(),
        blinding_seed.clone(),
    ])
}

fn output_blinding_seed(
    first_nullifier: &CircuitVar,
    blinding_seed: &CircuitVar,
) -> Result<CircuitVar, RelationError> {
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
) -> Result<CircuitVar, RelationError> {
    let slot = u64::try_from(slot).map_err(|_| RelationError::Slot {
        kind: "output",
        slot,
        problem: "is outside the transaction",
    })?;
    poseidon(&[
        constant(u64::from(DOMAIN_TRANSACT_OUTPUT_BLINDING_V1)),
        first_nullifier.clone(),
        output_blinding_seed.clone(),
        constant(slot),
    ])
}

pub trait PublicInputs {
    fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError>;
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
    pub(crate) blinding_seed: CircuitVar,
    pub(crate) first_nullifier: CircuitVar,
    pub(crate) output_tree_id: CircuitVar,
    pub(crate) inputs: Vec<CircuitVar>,
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
    inputs: Vec<SpentInput>,
    outputs: Vec<Output>,
    public_transfers: Vec<PublicTransfer>,
    error: Option<RelationError>,
}

impl<'a, P: PublicInputs> ConfidentialTransaction<'a, P> {
    pub fn new(tx_context: &'a TxContext, public: &'a P) -> Self {
        Self {
            tx_context,
            public,
            inputs: Vec::new(),
            outputs: Vec::new(),
            public_transfers: Vec::new(),
            error: None,
        }
    }

    pub fn with_token_utxos<const N: usize>(mut self, token: TokenUtxo<N>) -> Self {
        self.inputs.extend(token.spent_inputs().iter().cloned());
        self.public_transfers
            .extend(token.public_transfers().iter().cloned());
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
        if let Some(spent) = utxo.spent_input() {
            self.inputs.push(spent);
        }
        self.public_transfers
            .extend(utxo.public_transfers().iter().cloned());
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
        let first = self.inputs.first().ok_or(RelationError::Violated(
            "a transaction spends at least one input",
        ))?;
        let first_nullifier = first.nullifier.clone();
        let output_tree_id = self.tx_context.output_tree_id(first)?;
        let blinding_seed = self.tx_context.blinding_seed.clone();
        let output_blinding_seed = output_blinding_seed(&first_nullifier, &blinding_seed)?;
        let outputs = self
            .outputs
            .into_iter()
            .enumerate()
            .map(|(slot, output)| {
                let blinding = output_blinding(&first_nullifier, &output_blinding_seed, slot)?;
                let hash = Utxo {
                    domain: constant(u64::from(UTXO_DOMAIN)),
                    owner: output.owner.clone(),
                    asset: output.asset.clone(),
                    amount: output.amount.clone(),
                    blinding,
                    data_hash: output.data_hash.clone(),
                    ring_data_hash: zero(),
                    ring_program_id: zero(),
                    tree_id: output_tree_id.clone(),
                    ..Utxo::default()
                }
                .hash()?;
                Ok(CheckedOutput { output, hash })
            })
            .collect::<Result<Vec<_>, RelationError>>()?;
        let input_hashes: Vec<CircuitVar> =
            self.inputs.iter().map(|input| input.hash.clone()).collect();
        let output_hashes: Vec<CircuitVar> =
            outputs.iter().map(|output| output.hash.clone()).collect();
        let private_tx_hash = poseidon(&[
            nonzero_hash_chain(&input_hashes)?,
            nonzero_hash_chain(&output_hashes)?,
            nonzero_hash_chain(&[])?,
            private_tx_blinding(&first_nullifier, &blinding_seed)?,
        ])?;
        let transaction_hash = transaction_hash(&private_tx_hash, &self.public_transfers)?;
        let public_hash = self.public.hash(&transaction_hash)?;
        Ok(CheckedTransaction {
            blinding_seed,
            first_nullifier,
            output_tree_id,
            inputs: input_hashes,
            outputs,
            public_transfers: self.public_transfers,
            private_tx_hash,
            transaction_hash,
            public_hash,
        })
    }

    fn record(&mut self, error: RelationError) {
        self.error.get_or_insert(error);
    }
}

fn transaction_hash(
    private_tx_hash: &CircuitVar,
    public_transfers: &[PublicTransfer],
) -> Result<CircuitVar, RelationError> {
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
