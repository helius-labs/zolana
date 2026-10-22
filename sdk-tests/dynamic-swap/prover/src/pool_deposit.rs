use std::collections::HashMap;

use zolana_gnark_ffi_prover::{decimal, utxo_proof_inputs, ProofInputMap};

use crate::{CircuitId, OrderProof, ProofInputUtxo, PROVER};

/// Proof inputs for the `pool_deposit` circuit: 1-in (the depositor's source
/// note) / 1-out (pool note). SPP proves the transaction at IN1_OUT2 with a
/// compact second output, which leaves the private transaction hash unchanged.
/// The source holds exactly the public `amount` of the destination asset and
/// is not a pool note; the pool note holds and books all of it.
#[derive(Debug, Clone)]
pub struct PoolDepositProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    /// The pool_authority PDA's owner-hash (`PoolAuthorityOwnerHash`), bound
    /// to the pool note.
    pub pool_authority_owner_hash: [u8; 32],
    /// The pair's destination-asset commitment (`DestinationAsset`).
    pub destination_asset: [u8; 32],
    /// The public deposited amount.
    pub amount: u64,
    pub source_in: ProofInputUtxo,
    pub pool_out: ProofInputUtxo,
    pub private_tx_blinding: [u8; 32],
}

impl PoolDepositProofInputs {
    fn witness(&self) -> ProofInputMap {
        let mut map = HashMap::new();
        map.insert(
            "Public_PublicInputHash".to_string(),
            vec![decimal(&self.public_input_hash)],
        );
        map.insert(
            "Public_PrivateTxHash".to_string(),
            vec![decimal(&self.private_tx_hash)],
        );
        map.insert(
            "Public_PoolAuthorityOwnerHash".to_string(),
            vec![decimal(&self.pool_authority_owner_hash)],
        );
        map.insert(
            "Public_DestinationAsset".to_string(),
            vec![decimal(&self.destination_asset)],
        );
        map.insert("Public_Amount".to_string(), vec![self.amount.to_string()]);
        map.insert(
            "PrivateTxBlinding".to_string(),
            vec![decimal(&self.private_tx_blinding)],
        );
        for (key, value) in utxo_proof_inputs(&self.source_in, "SourceIn")
            .into_iter()
            .chain(utxo_proof_inputs(&self.pool_out, "PoolOut"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> zolana_gnark_ffi_prover::Result<OrderProof> {
        Ok(PROVER
            .prove(CircuitId::PoolDeposit, &self.witness())?
            .compress()?
            .into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use zolana_gnark_ffi_prover::utxo_proof_input_keys;

    fn sample() -> PoolDepositProofInputs {
        PoolDepositProofInputs {
            public_input_hash: [1; 32],
            private_tx_hash: [2; 32],
            pool_authority_owner_hash: [3; 32],
            destination_asset: [4; 32],
            amount: 25,
            source_in: ProofInputUtxo::default(),
            pool_out: ProofInputUtxo::default(),
            private_tx_blinding: [9; 32],
        }
    }

    #[test]
    fn witness_key_set_matches_circuit_fields() {
        let witness = sample().witness();
        let keys: HashSet<&str> = witness.keys().map(String::as_str).collect();

        let mut expected: Vec<String> = vec![
            "Public_PublicInputHash".to_string(),
            "Public_PrivateTxHash".to_string(),
            "Public_PoolAuthorityOwnerHash".to_string(),
            "Public_DestinationAsset".to_string(),
            "Public_Amount".to_string(),
            "PrivateTxBlinding".to_string(),
        ];
        for prefix in ["SourceIn", "PoolOut"] {
            expected.extend(utxo_proof_input_keys(prefix));
        }

        let expected: HashSet<&str> = expected.iter().map(String::as_str).collect();
        assert_eq!(keys, expected);
    }
}
