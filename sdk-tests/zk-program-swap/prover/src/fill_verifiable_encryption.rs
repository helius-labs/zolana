use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string, ffi,
    proof::{negate_and_compress_proof_with_commitment, OrderProof, ProofError},
    CircuitId, OrderTermsFieldElements, UtxoFieldElements,
};

pub const FILL_ENC_KDF_DOMAIN: u64 = 0x5357_4150_4649_4c4c;

#[derive(Debug, Clone)]
pub struct FillVerifiableEncryptionProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub order: OrderTermsFieldElements,
    pub taker_nullifier_pk: [u8; 32],
    pub escrow: UtxoFieldElements,
    pub taker_in: UtxoFieldElements,
    pub source_output: UtxoFieldElements,
    pub destination_output: UtxoFieldElements,
    pub external_data_hash: [u8; 32],
}

impl FillVerifiableEncryptionProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let scalars: [(&str, [u8; 32]); 4] = [
            ("Public_PublicInputHash", self.public_input_hash),
            ("Public_PrivateTxHash", self.private_tx_hash),
            ("Core_ExternalDataHash", self.external_data_hash),
            ("TakerNullifierPk", self.taker_nullifier_pk),
        ];
        let mut map = HashMap::new();
        for (key, value) in scalars.iter() {
            map.insert(key.to_string(), vec![bytes_to_decimal_string(value)]);
        }
        for (key, value) in self
            .order
            .witness_entries("Core_Order")
            .into_iter()
            .chain(self.escrow.witness_entries("Core_Escrow"))
            .chain(self.taker_in.witness_entries("Core_TakerIn"))
            .chain(self.source_output.witness_entries("Core_SourceOutput"))
            .chain(
                self.destination_output
                    .witness_entries("Core_DestinationOutput"),
            )
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof_with_commitment(&ffi::prove(
            CircuitId::FillVerifiableEncryption,
            &self.witness(),
        )?)
    }
}
