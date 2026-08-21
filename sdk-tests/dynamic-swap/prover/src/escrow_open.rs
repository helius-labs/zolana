use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string,
    ffi::{self, CircuitId},
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    ProofInputUtxo,
};

/// Proof inputs for the `escrow_open` circuit (`create_escrow`): 1-in (source) /
/// 2-out (order, taker_change), the exact supported IN1_OUT2 shape with no
/// padding. Taker-only: the maker's liquidity is reserved program-side and
/// enters at settle time, so there is no funding input and no maker change; the
/// circuit proves the order amount and private minimum are within pair policy,
/// and caps the payout at the public window's coverage price so the fixed
/// reservation always covers the order. The live price is program-side only.
#[derive(Debug, Clone)]
pub struct EscrowOpenProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    /// The escrow_authority PDA's owner-hash (`EscrowAuthorityOwnerHash`),
    /// bound to `OrderOut.Owner`.
    pub escrow_authority_owner_hash: [u8; 32],
    /// The pair's source-asset commitment (`SourceAsset`), bound to
    /// `SourceIn.Asset`.
    pub source_asset: [u8; 32],
    pub public_price_floor: u64,
    pub price_tolerance: u64,
    pub min_order_amount: u64,
    /// The pair's immutable `max_order_size` (`MaxOrderSize`), capping owed.
    pub max_order_size: u64,
    pub order_amount: u64,
    pub min_price: u64,
    pub source_in: ProofInputUtxo,
    pub order_out: ProofInputUtxo,
    pub taker_change: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
}

impl EscrowOpenProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let mut map = HashMap::new();
        map.insert(
            "Public_PublicInputHash".to_string(),
            vec![bytes_to_decimal_string(&self.public_input_hash)],
        );
        map.insert(
            "Public_PrivateTxHash".to_string(),
            vec![bytes_to_decimal_string(&self.private_tx_hash)],
        );
        map.insert(
            "Public_EscrowAuthorityOwnerHash".to_string(),
            vec![bytes_to_decimal_string(&self.escrow_authority_owner_hash)],
        );
        map.insert(
            "Public_SourceAsset".to_string(),
            vec![bytes_to_decimal_string(&self.source_asset)],
        );
        map.insert(
            "Public_PublicPriceFloor".to_string(),
            vec![self.public_price_floor.to_string()],
        );
        map.insert(
            "Public_PriceTolerance".to_string(),
            vec![self.price_tolerance.to_string()],
        );
        map.insert(
            "Public_MinOrderAmount".to_string(),
            vec![self.min_order_amount.to_string()],
        );
        map.insert(
            "Public_MaxOrderSize".to_string(),
            vec![self.max_order_size.to_string()],
        );
        map.insert(
            "OrderAmount".to_string(),
            vec![self.order_amount.to_string()],
        );
        map.insert("MinPrice".to_string(), vec![self.min_price.to_string()]);
        map.insert(
            "ExternalDataHash".to_string(),
            vec![bytes_to_decimal_string(&self.external_data_hash)],
        );
        for (key, value) in utxo_witness_entries(&self.source_in, "SourceIn")
            .into_iter()
            .chain(utxo_witness_entries(&self.order_out, "OrderOut"))
            .chain(utxo_witness_entries(&self.taker_change, "TakerChange"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::EscrowOpen, &self.witness())?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn sample() -> EscrowOpenProofInputs {
        EscrowOpenProofInputs {
            public_input_hash: [1; 32],
            private_tx_hash: [2; 32],
            escrow_authority_owner_hash: [6; 32],
            source_asset: [7; 32],
            public_price_floor: 80,
            price_tolerance: 10,
            min_order_amount: 1,
            max_order_size: 100,
            order_amount: 50,
            min_price: 85,
            source_in: ProofInputUtxo::default(),
            order_out: ProofInputUtxo::default(),
            taker_change: ProofInputUtxo::default(),
            external_data_hash: [5; 32],
        }
    }

    #[test]
    fn witness_key_set_matches_circuit_fields() {
        let witness = sample().witness();
        let keys: HashSet<&str> = witness.keys().map(String::as_str).collect();

        let mut expected: Vec<String> = vec![
            "Public_PublicInputHash".to_string(),
            "Public_PrivateTxHash".to_string(),
            "Public_EscrowAuthorityOwnerHash".to_string(),
            "Public_SourceAsset".to_string(),
            "Public_PublicPriceFloor".to_string(),
            "Public_PriceTolerance".to_string(),
            "Public_MinOrderAmount".to_string(),
            "Public_MaxOrderSize".to_string(),
            "OrderAmount".to_string(),
            "MinPrice".to_string(),
            "ExternalDataHash".to_string(),
        ];
        for prefix in ["SourceIn", "OrderOut", "TakerChange"] {
            for suffix in [
                "Domain",
                "Owner",
                "Asset",
                "Amount",
                "Blinding",
                "DataHash",
                "RingDataHash",
                "RingProgramID",
            ] {
                expected.push(format!("{prefix}_{suffix}"));
            }
        }

        let expected: HashSet<&str> = expected.iter().map(String::as_str).collect();
        assert_eq!(keys, expected);
    }
}
