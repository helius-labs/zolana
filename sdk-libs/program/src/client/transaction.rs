use solana_address::Address;
use zolana_instruction::{transaction_hash, PublicTransfer};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::instructions::transact::{
    canonical_shape, ConfidentialTransaction, FinalizedTransaction,
};
#[cfg(feature = "encrypt")]
use zolana_transaction::{instructions::transact::SppProofInputs, keys::ShieldedKeys};

use super::transfer::public_transfer;
use crate::{
    circuit::{value, CheckedTransaction, Circuit},
    conversion::{field_bytes, to_bytes, u16_value, Allocator, Placeholder, ProofInput, Records},
    prover::{ArkworksCircuit, ProofInputs},
    ClientError, ClientErrorKind, ProverError, SlotKind,
};

pub trait ZkProgram: ProofInput<Circuit: Circuit> + Placeholder + 'static {
    fn check_constraints(&self) -> Result<usize, ProverError> {
        ArkworksCircuit::new(self)?.check_constraints(&Self::placeholder()?)
    }

    #[cfg(feature = "setup")]
    fn export_r1cs() -> Result<Vec<u8>, ProverError> {
        let placeholder = Self::placeholder()?;
        ArkworksCircuit::for_setup(&placeholder).matrices()?.r1cs()
    }

    #[cfg(feature = "setup")]
    fn export_picus_r1cs() -> Result<Vec<u8>, ProverError> {
        let placeholder = Self::placeholder()?;
        ArkworksCircuit::for_setup(&placeholder)
            .matrices()?
            .picus_r1cs()
    }

    fn proof_inputs(&self) -> Result<ProofInputs, ProverError> {
        Ok(ArkworksCircuit::new(self)?.proof_inputs()?)
    }

    fn export_assignment(&self) -> Result<Vec<u8>, ProverError> {
        self.proof_inputs()?.to_bytes()
    }

    fn create_finalized_transaction(
        &self,
        sender: &ShieldedAddress,
        payer: Address,
    ) -> Result<FinalizedTransaction, ClientError> {
        Ok(finalize(self, sender, payer)?.1)
    }

    fn create_program_transaction(
        &self,
        sender: &ShieldedAddress,
        payer: Address,
    ) -> Result<ProgramTransaction, ClientError> {
        let (checked, finalized) = finalize(self, sender, payer)?;
        let public_hash = value(checked.public_hash())?;
        Ok(ProgramTransaction {
            finalized,
            proof_inputs: ArkworksCircuit::with_public_hash(self, public_hash.into())
                .proof_inputs()?,
            public_hash: field_bytes(&public_hash),
        })
    }

    #[cfg(feature = "encrypt")]
    fn create_proof_inputs_and_encrypt(
        &self,
        sender: &ShieldedAddress,
        payer: Address,
    ) -> Result<SppProofInputs, ClientError> {
        Ok(self
            .create_finalized_transaction(sender, payer)?
            .encrypt()
            .map_err(ClientErrorKind::Transaction)?)
    }

    #[cfg(feature = "encrypt")]
    fn create_proof_inputs_and_encrypt_with_keys(
        &self,
        shielded_keys: &impl ShieldedKeys,
        payer: Address,
        expiry_unix_ts: u64,
    ) -> Result<SppProofInputs, ClientError> {
        let sender = shielded_keys
            .address()
            .map_err(ClientErrorKind::Transaction)?;
        let mut spp_proof_inputs = self
            .create_finalized_transaction(&sender, payer)?
            .encrypt_with_keys(shielded_keys)
            .map_err(ClientErrorKind::Transaction)?;
        spp_proof_inputs.external_data.expiry_unix_ts = expiry_unix_ts;
        Ok(spp_proof_inputs)
    }
}

impl<T: ProofInput<Circuit: Circuit> + Placeholder + 'static> ZkProgram for T {}

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
) -> Result<(CheckedTransaction, FinalizedTransaction), ClientError> {
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
    fn build(self, sender: &ShieldedAddress) -> Result<FinalizedTransaction, ClientError> {
        if !self.checked.addresses.is_empty() {
            return Err(ClientErrorKind::UnsupportedAddressCreation.into());
        }
        let first_nullifier = to_bytes(&self.checked.first_nullifier)?;
        let blinding_seed = to_bytes(&self.checked.blinding_seed)?;
        let output_tree_id = u16_value(&self.checked.output_tree_id)?;
        let inputs = self.input_utxos(&first_nullifier)?;
        let outputs = self.output_utxos(sender)?;
        let shape =
            canonical_shape(inputs.len(), outputs.len()).map_err(ClientErrorKind::Transaction)?;
        let mut transaction = ConfidentialTransaction::new(inputs, self.payer)
            .and_then(|transaction| transaction.with_blinding_seed(blinding_seed))
            .and_then(|transaction| transaction.with_output_tree_id(output_tree_id))
            .map_err(ClientErrorKind::Transaction)?;
        for output in outputs {
            match output {
                Some(output) => transaction.add_output_utxo(output),
                None => transaction.add_empty_output_utxo(),
            }
            .map_err(ClientErrorKind::Transaction)?;
        }
        for transfer in self.public_transfers()? {
            transaction
                .settle(
                    transfer.asset,
                    transfer.is_deposit,
                    transfer.amount,
                    transfer.target,
                )
                .map_err(ClientErrorKind::Transaction)?;
        }
        transaction
            .pad_utxos_with_empty_outputs(shape, sender)
            .map_err(ClientErrorKind::Transaction)?;
        let finalized = transaction
            .finalize(sender)
            .map_err(ClientErrorKind::Transaction)?;
        self.check_hashes(&finalized)?;
        Ok(finalized)
    }

    fn check_hashes(&self, finalized: &FinalizedTransaction) -> Result<(), ClientError> {
        let output_hashes = finalized
            .output_hashes()
            .map_err(ClientErrorKind::Transaction)?;
        for (slot, (output_hash, checked)) in
            output_hashes.iter().zip(&self.checked.outputs).enumerate()
        {
            if *output_hash != to_bytes(&checked.hash)? {
                return Err(ClientErrorKind::Slot {
                    kind: SlotKind::Output,
                    index: slot,
                    problem: "does not match the circuit's output hash",
                }
                .into());
            }
        }
        let private_tx_hash = finalized
            .padding_independent_private_tx_hash()
            .map_err(ClientErrorKind::Transaction)?;
        if private_tx_hash != to_bytes(&self.checked.private_tx_hash)? {
            return Err(ClientErrorKind::TransactionMismatch(
                "the built transaction does not match the circuit's private transaction hash",
            )
            .into());
        }
        let public_transfers: Vec<PublicTransfer> = finalized
            .interface_transfers()
            .iter()
            .copied()
            .map(public_transfer)
            .collect();
        if transaction_hash(&private_tx_hash, &public_transfers)?
            != to_bytes(&self.checked.transaction_hash)?
        {
            return Err(ClientErrorKind::TransactionMismatch(
                "the built transaction's public transfers do not match the circuit's",
            )
            .into());
        }
        Ok(())
    }
}
