use solana_address::Address;
use zolana_transaction::{
    instructions::transact::{ConfidentialTransaction, SppProofInputs, SPP_SUPPORTED_SHAPES},
    keys::ShieldedKeys,
};

use crate::{
    circuit::{CheckedTransaction, Circuit},
    conversion::{to_bytes, Allocator, FromCircuit, ProofInput, Records},
    RelationError,
};

pub trait ZkProgram: ProofInput<Circuit: Circuit> + Clone + Sized {
    fn create_proof_inputs_and_encrypt(
        self,
        shielded_keys: &impl ShieldedKeys,
        payer: Address,
        expiry_unix_ts: u64,
    ) -> Result<(Self, SppProofInputs), RelationError> {
        let allocator = Allocator::native();
        let checked = self.instantiate(&allocator)?.circuit()?;
        let records = allocator.into_records();
        let spp_proof_inputs = SppTransactionBuilder {
            checked: &checked,
            records: &records,
            payer,
            expiry_unix_ts,
        }
        .encrypt(shielded_keys)?;
        Ok((self, spp_proof_inputs))
    }
}

pub(super) struct SppTransactionBuilder<'a> {
    pub(super) checked: &'a CheckedTransaction,
    pub(super) records: &'a Records,
    payer: Address,
    expiry_unix_ts: u64,
}

impl SppTransactionBuilder<'_> {
    fn encrypt(self, shielded_keys: &impl ShieldedKeys) -> Result<SppProofInputs, RelationError> {
        let tx_context = &self.checked.tx_context;
        let sender = shielded_keys.address().map_err(RelationError::spp)?;
        if sender.owner_hash().map_err(RelationError::spp)? != to_bytes(&tx_context.sender)? {
            return Err(RelationError::Violated(
                "the keys are not the transaction's sender",
            ));
        }
        let first_nullifier = to_bytes(&tx_context.first_nullifier)?;
        let blinding_seed = to_bytes(&tx_context.blinding_seed)?;
        let output_tree_id = u16::from_circuit(&tx_context.output_tree_id)
            .map_err(|_| RelationError::Conversion("the output tree id does not fit in u16"))?;
        let inputs = self.input_utxos(&first_nullifier)?;
        let outputs = self.output_utxos()?;
        let shape = SPP_SUPPORTED_SHAPES
            .into_iter()
            .find(|shape| shape.n_inputs() == inputs.len() && shape.n_outputs() == outputs.len())
            .ok_or(RelationError::Violated(
                "the transaction's shape is not one the SPP supports",
            ))?;
        let mut transaction = ConfidentialTransaction::new(inputs, self.payer)
            .and_then(|transaction| transaction.with_blinding_seed(blinding_seed))
            .and_then(|transaction| transaction.with_output_tree_id(output_tree_id))
            .map_err(RelationError::spp)?;
        for output in outputs {
            transaction
                .add_output_utxo(output)
                .map_err(RelationError::spp)?;
        }
        transaction
            .pad_utxos(shape, &sender)
            .map_err(RelationError::spp)?;
        let mut spp_proof_inputs = transaction
            .encrypt(shielded_keys)
            .map_err(RelationError::spp)?;
        spp_proof_inputs.external_data.expiry_unix_ts = self.expiry_unix_ts;
        self.check_hashes(&spp_proof_inputs)?;
        Ok(spp_proof_inputs)
    }

    fn check_hashes(&self, spp_proof_inputs: &SppProofInputs) -> Result<(), RelationError> {
        for (slot, (output, checked)) in spp_proof_inputs
            .output_utxos
            .iter()
            .zip(&self.checked.outputs)
            .enumerate()
        {
            if output
                .hash(spp_proof_inputs.output_tree_id)
                .map_err(RelationError::spp)?
                != to_bytes(&checked.hash)?
            {
                return Err(RelationError::Slot {
                    kind: "output",
                    slot,
                    problem: "does not match the circuit's output hash",
                });
            }
        }
        if spp_proof_inputs
            .private_tx_hash_without_external_data()
            .map_err(RelationError::spp)?
            != to_bytes(&self.checked.private_tx_hash)?
        {
            return Err(RelationError::Violated(
                "the SPP transaction does not match the circuit's private transaction hash",
            ));
        }
        Ok(())
    }
}
