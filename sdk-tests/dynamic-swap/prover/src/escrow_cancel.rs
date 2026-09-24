use std::collections::HashMap;

use zolana_gnark_ffi_prover::{decimal, utxo_proof_inputs, ProofInputMap};

use crate::{CircuitId, OrderProof, ProofInputUtxo, PROVER};

/// Proof inputs for the `escrow_cancel` circuit: 1-in (order) / 1-out (refund),
/// the exact IN1_OUT1 shape. The full order amount returns, in the source
/// asset, to the recipient committed as the order UTXO's data hash; the refund
/// blinding derives from the order blinding and the first nullifier. The
/// expiry gate is program-side, so the circuit carries no notion of time.
#[derive(Debug, Clone)]
pub struct EscrowCancelProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    /// SPP input 0's nullifier, which the program reads from the transact
    /// data; every output blinding and the private transaction blinding
    /// derive from it and the order opening.
    pub first_nullifier: [u8; 32],
    /// The order-input UTXO's own hash -- the escrow account's on-chain
    /// `Escrow.order_utxo_hash`, asserted equal in-circuit to `Hash(order_in)`.
    pub order_in_hash: [u8; 32],
    pub order_amount: u64,
    pub recipient_owner_hash: [u8; 32],
    pub min_price: u64,
    pub order_in: ProofInputUtxo,
    pub refund_out: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
}

impl EscrowCancelProofInputs {
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
            "Public_FirstNullifier".to_string(),
            vec![decimal(&self.first_nullifier)],
        );
        map.insert(
            "Public_OrderInHash".to_string(),
            vec![decimal(&self.order_in_hash)],
        );
        map.insert(
            "OrderAmount".to_string(),
            vec![self.order_amount.to_string()],
        );
        map.insert(
            "RecipientOwnerHash".to_string(),
            vec![decimal(&self.recipient_owner_hash)],
        );
        map.insert("MinPrice".to_string(), vec![self.min_price.to_string()]);
        map.insert(
            "ExternalDataHash".to_string(),
            vec![decimal(&self.external_data_hash)],
        );
        map.insert(
            "PrivateTxBlinding".to_string(),
            vec![decimal(&self.private_tx_blinding)],
        );
        for (key, value) in utxo_proof_inputs(&self.order_in, "OrderIn")
            .into_iter()
            .chain(utxo_proof_inputs(&self.refund_out, "RefundOut"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> zolana_gnark_ffi_prover::Result<OrderProof> {
        Ok(PROVER
            .prove(CircuitId::EscrowCancel, &self.witness())?
            .compress()?
            .into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use zolana_gnark_ffi_prover::utxo_proof_input_keys;

    fn sample() -> EscrowCancelProofInputs {
        EscrowCancelProofInputs {
            public_input_hash: [1; 32],
            private_tx_hash: [2; 32],
            first_nullifier: [10; 32],
            order_in_hash: [3; 32],
            order_amount: 50,
            recipient_owner_hash: [9; 32],
            min_price: 80,
            order_in: ProofInputUtxo::default(),
            refund_out: ProofInputUtxo::default(),
            external_data_hash: [4; 32],
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
            "Public_FirstNullifier".to_string(),
            "Public_OrderInHash".to_string(),
            "OrderAmount".to_string(),
            "RecipientOwnerHash".to_string(),
            "MinPrice".to_string(),
            "ExternalDataHash".to_string(),
            "PrivateTxBlinding".to_string(),
        ];
        for prefix in ["OrderIn", "RefundOut"] {
            expected.extend(utxo_proof_input_keys(prefix));
        }

        let expected: HashSet<&str> = expected.iter().map(String::as_str).collect();
        assert_eq!(keys, expected);
    }
}
