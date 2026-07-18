use std::collections::HashMap;

use zolana_transaction::ProofInputUtxo;

use crate::{
    bytes_to_decimal_string, ffi,
    proof::{negate_and_compress_proof, ProofError, TimelockProof},
    utxo::utxo_witness_entries,
    CircuitId, EscrowTermsProofInput,
};

#[derive(Debug, Clone)]
pub struct EscrowProofInputs {
    pub private_tx_hash: [u8; 32],
    pub terms: EscrowTermsProofInput,
    pub escrow_utxo: ProofInputUtxo,
    pub change: ProofInputUtxo,
    pub source_input_hash: [u8; 32],
    pub external_data_hash: [u8; 32],
}

impl EscrowProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let scalars: [(&str, [u8; 32]); 3] = [
            ("PrivateTxHash", self.private_tx_hash),
            ("SourceInputHash", self.source_input_hash),
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
            .chain(utxo_witness_entries(&self.change, "Change"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<TimelockProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::Escrow, &self.witness())?)
    }
}
