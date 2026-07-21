use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string,
    ffi::{self, CircuitId},
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    ProofInputUtxo,
};

/// Proof inputs for the `escrow_open` circuit (`create_escrow`): 2-in (source,
/// maker_funding) / 3-out (order, reservation, maker_change), the exact supported
/// IN2_OUT3 shape with no padding. No source change output: the source UTXO must
/// match `order_amount` exactly. `order_amount` is the one private witness shared
/// across the order UTXO, the reservation size (`order_amount * max_price`), and
/// the maker-change decrement.
#[derive(Debug, Clone)]
pub struct EscrowOpenProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub max_price: u64,
    pub created_at: u64,
    /// The escrow_authority PDA's owner-hash (`EscrowAuthorityOwnerHash`),
    /// bound to `OrderOut.Owner`.
    pub escrow_authority_owner_hash: [u8; 32],
    /// The pair's source-asset commitment (`SourceAsset`), bound to
    /// `SourceIn.Asset`.
    pub source_asset: [u8; 32],
    /// The pair's destination-asset commitment (`DestinationAsset`), bound to
    /// `MakerFunding.Asset`.
    pub destination_asset: [u8; 32],
    pub order_amount: u64,
    pub source_in: ProofInputUtxo,
    pub maker_funding: ProofInputUtxo,
    pub order_out: ProofInputUtxo,
    pub reservation_out: ProofInputUtxo,
    pub maker_change: ProofInputUtxo,
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
        map.insert("MaxPrice".to_string(), vec![self.max_price.to_string()]);
        map.insert(
            "Public_CreatedAt".to_string(),
            vec![self.created_at.to_string()],
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
            "Public_DestinationAsset".to_string(),
            vec![bytes_to_decimal_string(&self.destination_asset)],
        );
        map.insert(
            "OrderAmount".to_string(),
            vec![self.order_amount.to_string()],
        );
        map.insert(
            "ExternalDataHash".to_string(),
            vec![bytes_to_decimal_string(&self.external_data_hash)],
        );
        for (key, value) in utxo_witness_entries(&self.source_in, "SourceIn")
            .into_iter()
            .chain(utxo_witness_entries(&self.maker_funding, "MakerFunding"))
            .chain(utxo_witness_entries(&self.order_out, "OrderOut"))
            .chain(utxo_witness_entries(
                &self.reservation_out,
                "ReservationOut",
            ))
            .chain(utxo_witness_entries(&self.maker_change, "MakerChange"))
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
            max_price: 100,
            created_at: 1_700_000_000,
            escrow_authority_owner_hash: [6; 32],
            source_asset: [7; 32],
            destination_asset: [8; 32],
            order_amount: 50,
            source_in: ProofInputUtxo::default(),
            maker_funding: ProofInputUtxo::default(),
            order_out: ProofInputUtxo::default(),
            reservation_out: ProofInputUtxo::default(),
            maker_change: ProofInputUtxo::default(),
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
            "MaxPrice".to_string(),
            "Public_CreatedAt".to_string(),
            "Public_EscrowAuthorityOwnerHash".to_string(),
            "Public_SourceAsset".to_string(),
            "Public_DestinationAsset".to_string(),
            "OrderAmount".to_string(),
            "ExternalDataHash".to_string(),
        ];
        for prefix in [
            "SourceIn",
            "MakerFunding",
            "OrderOut",
            "ReservationOut",
            "MakerChange",
        ] {
            for suffix in [
                "Domain",
                "Owner",
                "Asset",
                "Amount",
                "Blinding",
                "DataHash",
                "ZoneDataHash",
                "ZoneProgramID",
            ] {
                expected.push(format!("{prefix}_{suffix}"));
            }
        }

        let expected: HashSet<&str> = expected.iter().map(String::as_str).collect();
        assert_eq!(keys, expected);
    }
}
