use zolana_interface::UTXO_DOMAIN;
use zolana_program::{
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};

use super::utxo::{Output, SpentInput};
use crate::{
    circuit::{
        builtins::field::var::system_of, constant, labels::Scope, nonzero_hash_chain, poseidon,
        zero, Assert, Bool, CircuitVar, DataHash, DataUtxo, PublicTransfer, TokenUtxo, Uint,
        UniqueDataUtxo, Utxo, UtxoData,
    },
    CircuitError, CircuitErrorKind,
};

#[derive(Clone, Debug)]
pub struct TxContext {
    pub blinding_seed: CircuitVar,
    pub output_tree_id: Uint<16>,
    pub uses_output_tree_id: Bool,
}

impl TxContext {
    #[track_caller]
    fn output_tree_id(&self, first: &SpentInput) -> Result<CircuitVar, CircuitError> {
        self.uses_output_tree_id
            .or(&first.has_latest_tree_id)
            .var()
            .assert_equal(
                &constant(1u64),
                "the first input reports no latest tree and the transaction sets no output tree",
            )?;
        Ok(self
            .uses_output_tree_id
            .select(&self.output_tree_id.var(), &first.latest_tree_id))
    }

    fn is_native(&self) -> bool {
        self.blinding_seed.is_constant()
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
    pub(crate) addresses: Vec<CircuitVar>,
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
    inputs: Vec<SpentInput>, // Consider rename to Utxo
    addresses: Vec<CircuitVar>,
    outputs: Vec<Output>, // Consider rename to NewUtxo
    public_transfers: Vec<PublicTransfer>,
    transferred: CircuitVar,
    error: Option<CircuitError>,
}

impl<'a, P: PublicInputs> ConfidentialTransaction<'a, P> {
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
        }
    }

    #[track_caller]
    pub fn with_token_utxos(mut self, token: TokenUtxo) -> Self {
        self.inputs.extend(token.spent_inputs().iter().cloned());
        self.public_transfers
            .extend(token.public_transfers().iter().cloned());
        self.transferred = self.transferred.plus(token.transferred());
        match token.change() {
            Ok(Some(change)) => self.outputs.push(change),
            Ok(None) => {}
            Err(error) => self.record(error),
        }
        self
    }

    #[track_caller]
    pub fn with_data_utxo<S: UtxoData>(mut self, utxo: DataUtxo<S>) -> Self {
        self.add_data_utxo(&utxo, || utxo.utxo_data().map(Some));
        self
    }

    #[track_caller]
    pub fn with_unique_data_utxo<S: UtxoData>(mut self, utxo: UniqueDataUtxo<S>) -> Self {
        self.addresses.extend(utxo.created_address());
        self.add_data_utxo(utxo.data_utxo(), || utxo.utxo_data());
        self
    }

    #[track_caller]
    fn add_data_utxo<S: DataHash>(
        &mut self,
        utxo: &DataUtxo<S>,
        data: impl FnOnce() -> Result<Option<Vec<u8>>, CircuitError>,
    ) {
        self.inputs.extend(utxo.spent_input());
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
            .chain(self.inputs)
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
            .collect::<Result<Vec<_>, CircuitError>>()?;
        let input_hashes: Vec<CircuitVar> = inputs.iter().map(|input| input.hash.clone()).collect();
        let output_hashes: Vec<CircuitVar> =
            outputs.iter().map(|output| output.hash.clone()).collect();
        let private_tx_hash = poseidon(&[
            nonzero_hash_chain(&input_hashes)?,
            nonzero_hash_chain(&output_hashes)?,
            nonzero_hash_chain(&self.addresses)?,
            private_tx_blinding(&first_nullifier, &blinding_seed)?,
        ])?;
        let transaction_hash = transaction_hash(&private_tx_hash, &self.public_transfers)?;
        let public_hash = self.public.hash(&transaction_hash)?;
        Ok(CheckedTransaction {
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

fn address_slot(address: &CircuitVar) -> SpentInput {
    SpentInput {
        hash: zero(),
        nullifier: address.clone(),
        latest_tree_id: zero(),
        has_latest_tree_id: Bool::constant(false),
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
