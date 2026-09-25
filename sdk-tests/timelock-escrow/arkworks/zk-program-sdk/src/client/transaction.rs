use solana_address::Address;
use zolana_transaction::{
    instructions::transact::{canonical_shape, ConfidentialTransaction, SppProofInputs},
    keys::ShieldedKeys,
};

use crate::{
    circuit::{CheckedTransaction, Circuit},
    conversion::{to_bytes, Allocator, FromCircuit, Placeholder, ProofInput, Records},
    program::{transaction_hash, PublicTransfer},
    prover::ArkworksCircuit,
    RelationError,
};

pub trait ZkProgram: ProofInput<Circuit: Circuit> + Placeholder {
    fn check_constraints(&self) -> Result<usize, RelationError> {
        ArkworksCircuit::new(self)?.check_constraints()
    }

    fn create_proof_inputs_and_encrypt(
        &self,
        shielded_keys: &impl ShieldedKeys,
        payer: Address,
        expiry_unix_ts: u64,
    ) -> Result<SppProofInputs, RelationError> {
        let allocator = Allocator::native();
        let checked = self.instantiate(&allocator)?.circuit()?;
        let records = allocator.into_records();
        SppTransactionBuilder {
            checked: &checked,
            records: &records,
            payer,
            expiry_unix_ts,
        }
        .encrypt(shielded_keys)
    }
}

impl<T: ProofInput<Circuit: Circuit> + Placeholder> ZkProgram for T {}

pub(super) struct SppTransactionBuilder<'a> {
    pub(super) checked: &'a CheckedTransaction,
    pub(super) records: &'a Records,
    payer: Address,
    expiry_unix_ts: u64,
}

impl SppTransactionBuilder<'_> {
    fn encrypt(self, shielded_keys: &impl ShieldedKeys) -> Result<SppProofInputs, RelationError> {
        let sender = shielded_keys.address().map_err(RelationError::spp)?;
        let first_nullifier = to_bytes(&self.checked.first_nullifier)?;
        let blinding_seed = to_bytes(&self.checked.blinding_seed)?;
        let output_tree_id = u16::from_circuit(&self.checked.output_tree_id)
            .map_err(|_| RelationError::Conversion("the output tree id does not fit in u16"))?;
        let inputs = self.input_utxos(&first_nullifier)?;
        let outputs = self.output_utxos(&sender)?;
        let shape = canonical_shape(inputs.len(), outputs.len()).map_err(RelationError::spp)?;
        let mut transaction = ConfidentialTransaction::new(inputs, self.payer)
            .and_then(|transaction| transaction.with_blinding_seed(blinding_seed))
            .and_then(|transaction| transaction.with_output_tree_id(output_tree_id))
            .map_err(RelationError::spp)?;
        for output in outputs {
            transaction
                .add_output_utxo(output)
                .map_err(RelationError::spp)?;
        }
        for transfer in self.public_transfers()? {
            transaction
                .settle(
                    transfer.asset,
                    transfer.is_deposit,
                    transfer.amount,
                    transfer.target,
                )
                .map_err(RelationError::spp)?;
        }
        transaction
            .pad_utxos_with_empty_outputs(shape, &sender)
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
        let private_tx_hash = spp_proof_inputs
            .padding_independent_private_tx_hash()
            .map_err(RelationError::spp)?;
        if private_tx_hash != to_bytes(&self.checked.private_tx_hash)? {
            return Err(RelationError::Violated(
                "the SPP transaction does not match the circuit's private transaction hash",
            ));
        }
        let public_transfers: Vec<PublicTransfer> = spp_proof_inputs
            .external_data
            .interface_transfers
            .iter()
            .copied()
            .map(PublicTransfer::from)
            .collect();
        if transaction_hash(&private_tx_hash, &public_transfers)?
            != to_bytes(&self.checked.transaction_hash)?
        {
            return Err(RelationError::Violated(
                "the SPP transaction's public transfers do not match the circuit's",
            ));
        }
        Ok(())
    }
}
