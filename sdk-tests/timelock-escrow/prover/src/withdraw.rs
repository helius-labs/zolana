use std::collections::HashMap;

use zolana_transaction::ProofInputUtxo;

use crate::{
    bytes_to_decimal_string, ffi,
    proof::{negate_and_compress_proof, ProofError, TimelockProof},
    utxo::utxo_witness_entries,
    CircuitId, EscrowTermsProofInput,
};

#[derive(Debug, Clone)]
pub struct WithdrawProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub terms: EscrowTermsProofInput,
    pub owner_pk_field: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub escrow_utxo: ProofInputUtxo,
    pub source_output: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
}

impl WithdrawProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let scalars: [(&str, [u8; 32]); 5] = [
            ("Public_PublicInputHash", self.public_input_hash),
            ("Public_PrivateTxHash", self.private_tx_hash),
            ("OwnerPkField", self.owner_pk_field),
            ("NullifierPk", self.nullifier_pk),
            ("ExternalDataHash", self.external_data_hash),
        ];
        let mut map = HashMap::new();
        for (key, value) in scalars.iter() {
            map.insert(key.to_string(), vec![bytes_to_decimal_string(value)]);
        }
        for (key, value) in self
            .terms
            .witness_entries("Terms")
            .into_iter()
            .chain(utxo_witness_entries(&self.escrow_utxo, "EscrowUtxo"))
            .chain(utxo_witness_entries(&self.source_output, "SourceOutput"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<TimelockProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::Withdraw, &self.witness())?)
    }
}
