use solana_address::Address;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::instructions::transact::{
    canonical_shape, ConfidentialTransaction, FinalizedTransaction,
};
#[cfg(feature = "encrypt")]
use zolana_transaction::{instructions::transact::SppProofInputs, keys::ShieldedKeys};

use crate::{
    circuit::{value, CheckedTransaction, Circuit},
    conversion::{field_bytes, to_bytes, Allocator, FromCircuit, Placeholder, ProofInput, Records},
    program::{transaction_hash, PublicTransfer},
    prover::{ArkworksCircuit, ProofInputs},
    RelationError,
};

pub trait ZkProgram: ProofInput<Circuit: Circuit> + Placeholder {
    fn check_constraints(&self) -> Result<usize, RelationError> {
        ArkworksCircuit::new(self)?.check_constraints()
    }

    #[cfg(feature = "setup")]
    fn export_r1cs() -> Result<Vec<u8>, RelationError> {
        let placeholder = Self::placeholder()?;
        ArkworksCircuit::for_setup(&placeholder).matrices()?.r1cs()
    }

    fn proof_inputs(&self) -> Result<ProofInputs, RelationError> {
        ArkworksCircuit::new(self)?.proof_inputs()
    }

    fn export_assignment(&self) -> Result<Vec<u8>, RelationError> {
        self.proof_inputs()?.to_bytes()
    }

    fn create_finalized_transaction(
        &self,
        sender: &ShieldedAddress,
        payer: Address,
    ) -> Result<FinalizedTransaction, RelationError> {
        Ok(finalize(self, sender, payer)?.1)
    }

    fn create_program_transaction(
        &self,
        sender: &ShieldedAddress,
        payer: Address,
    ) -> Result<ProgramTransaction, RelationError> {
        let (checked, finalized) = finalize(self, sender, payer)?;
        let public_hash = value(checked.public_hash())?;
        Ok(ProgramTransaction {
            finalized,
            proof_inputs: ArkworksCircuit::with_public_hash(self, public_hash).proof_inputs()?,
            public_hash: field_bytes(&public_hash),
        })
    }

    #[cfg(feature = "encrypt")]
    fn create_proof_inputs_and_encrypt(
        &self,
        shielded_keys: &impl ShieldedKeys,
        payer: Address,
        expiry_unix_ts: u64,
    ) -> Result<SppProofInputs, RelationError> {
        let sender = shielded_keys.address().map_err(RelationError::spp)?;
        let mut spp_proof_inputs = self
            .create_finalized_transaction(&sender, payer)?
            .encrypt(shielded_keys)
            .map_err(RelationError::spp)?;
        spp_proof_inputs.external_data.expiry_unix_ts = expiry_unix_ts;
        Ok(spp_proof_inputs)
    }
}

impl<T: ProofInput<Circuit: Circuit> + Placeholder> ZkProgram for T {}

#[derive(Clone)]
pub struct ProgramTransaction {
    pub finalized: FinalizedTransaction,
    pub proof_inputs: ProofInputs,
    pub public_hash: [u8; 32],
}

fn finalize<P: ZkProgram>(
    program: &P,
    sender: &ShieldedAddress,
    payer: Address,
) -> Result<(CheckedTransaction, FinalizedTransaction), RelationError> {
    let allocator = Allocator::native();
    let checked = program.instantiate(&allocator)?.circuit()?;
    let records = allocator.into_records();
    let finalized = SppTransactionBuilder {
        checked: &checked,
        records: &records,
        payer,
    }
    .build(sender)?;
    Ok((checked, finalized))
}

pub(super) struct SppTransactionBuilder<'a> {
    pub(super) checked: &'a CheckedTransaction,
    pub(super) records: &'a Records,
    payer: Address,
}

impl SppTransactionBuilder<'_> {
    fn build(self, sender: &ShieldedAddress) -> Result<FinalizedTransaction, RelationError> {
        let first_nullifier = to_bytes(&self.checked.first_nullifier)?;
        let blinding_seed = to_bytes(&self.checked.blinding_seed)?;
        let output_tree_id = u16::from_circuit(&self.checked.output_tree_id)
            .map_err(|_| RelationError::Conversion("the output tree id does not fit in u16"))?;
        let inputs = self.input_utxos(&first_nullifier)?;
        let outputs = self.output_utxos(sender)?;
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
            .pad_utxos_with_empty_outputs(shape, sender)
            .map_err(RelationError::spp)?;
        let finalized = transaction.finalize(sender).map_err(RelationError::spp)?;
        self.check_hashes(&finalized)?;
        Ok(finalized)
    }

    fn check_hashes(&self, finalized: &FinalizedTransaction) -> Result<(), RelationError> {
        let output_hashes = finalized.output_hashes().map_err(RelationError::spp)?;
        for (slot, (output_hash, checked)) in
            output_hashes.iter().zip(&self.checked.outputs).enumerate()
        {
            if *output_hash != to_bytes(&checked.hash)? {
                return Err(RelationError::Slot {
                    kind: "output",
                    slot,
                    problem: "does not match the circuit's output hash",
                });
            }
        }
        let private_tx_hash = finalized
            .padding_independent_private_tx_hash()
            .map_err(RelationError::spp)?;
        if private_tx_hash != to_bytes(&self.checked.private_tx_hash)? {
            return Err(RelationError::Violated(
                "the SPP transaction does not match the circuit's private transaction hash",
            ));
        }
        let public_transfers: Vec<PublicTransfer> = finalized
            .interface_transfers()
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
