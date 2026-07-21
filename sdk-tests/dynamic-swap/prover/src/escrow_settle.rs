use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string,
    ffi::{self, CircuitId},
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    ProofInputUtxo,
};

/// Per-output-slot domains folded into the settle output-blinding derivation
/// (`Poseidon(order_blinding, reservation_blinding, domain)`). These MUST stay
/// byte-for-byte in sync with the Go copies in
/// `prover/circuits/escrow_settle/escrow_settle.go`.
pub const RECIPIENT_BLINDING_DOMAIN: u64 = 0x5345_5452_4543_4950; // "SETRECIP"
pub const MAKER_COUNTER_BLINDING_DOMAIN: u64 = 0x5345_544D_4B43_5452; // "SETMKCTR"
pub const MAKER_SOURCE_BLINDING_DOMAIN: u64 = 0x5345_544D_4B53_5243; // "SETMKSRC"

/// Proof inputs for the `escrow_settle` circuit -- the single circuit `settle`
/// uses for both outcomes (settle and price-refund). Exact 2-in (order,
/// reservation) / 3-out (recipient, maker_counter, maker_source), no padding.
/// `max_price` and `created_at` are PRIVATE witnesses (bound to the order UTXO's
/// data hash), not public inputs -- keeping `max_price` private is what hides the
/// settle-vs-refund outcome. `execution_price` stays public (it is the public
/// pair price snapshot the escrow was priced at).
#[derive(Debug, Clone)]
pub struct EscrowSettleProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub execution_price: u64,
    /// Private witness, re-opened from the order UTXO's data hash in-circuit.
    pub max_price: u64,
    /// Private witness (the order's `created_at`), the third preimage of the
    /// order UTXO's data hash `Poseidon(recipient_owner_hash, max_price, created_at)`.
    pub created_at: u64,
    /// The order-input UTXO's own hash -- the escrow account's current
    /// on-chain `Escrow.escrow_utxo_hash`, asserted equal in-circuit to
    /// `Hash(order_in)`.
    pub order_in_hash: [u8; 32],
    /// The reservation-input UTXO's own hash -- `Escrow.reservation_utxo_hash`.
    pub reservation_in_hash: [u8; 32],
    /// Private witness: the taker's owner-hash (the source UTXO's owner that
    /// `escrow_open` committed into the order UTXO's DataHash), re-opened here and
    /// bound to `RecipientOut.Owner`. Pinned by the public `OrderInHash`.
    pub recipient_owner_hash: [u8; 32],
    /// Owner-hash bound to `MakerCounter.Owner`/`MakerSource.Owner` --
    /// `Pair.authority_owner_hash`.
    pub authority_owner_hash: [u8; 32],
    pub order_amount: u64,
    pub order_in: ProofInputUtxo,
    pub reservation_in: ProofInputUtxo,
    pub recipient_out: ProofInputUtxo,
    pub maker_counter: ProofInputUtxo,
    pub maker_source: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
}

impl EscrowSettleProofInputs {
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
            "Public_ExecutionPrice".to_string(),
            vec![self.execution_price.to_string()],
        );
        map.insert(
            "Public_OrderInHash".to_string(),
            vec![bytes_to_decimal_string(&self.order_in_hash)],
        );
        map.insert(
            "Public_ReservationInHash".to_string(),
            vec![bytes_to_decimal_string(&self.reservation_in_hash)],
        );
        map.insert(
            "Public_AuthorityOwnerHash".to_string(),
            vec![bytes_to_decimal_string(&self.authority_owner_hash)],
        );
        // Private witness (bound to the order UTXO's DataHash, pinned by the public
        // OrderInHash), so its key carries no `Public_` prefix.
        map.insert(
            "RecipientOwnerHash".to_string(),
            vec![bytes_to_decimal_string(&self.recipient_owner_hash)],
        );
        map.insert("MaxPrice".to_string(), vec![self.max_price.to_string()]);
        map.insert("CreatedAt".to_string(), vec![self.created_at.to_string()]);
        map.insert(
            "OrderAmount".to_string(),
            vec![self.order_amount.to_string()],
        );
        map.insert(
            "ExternalDataHash".to_string(),
            vec![bytes_to_decimal_string(&self.external_data_hash)],
        );
        for (key, value) in utxo_witness_entries(&self.order_in, "OrderIn")
            .into_iter()
            .chain(utxo_witness_entries(&self.reservation_in, "ReservationIn"))
            .chain(utxo_witness_entries(&self.recipient_out, "RecipientOut"))
            .chain(utxo_witness_entries(&self.maker_counter, "MakerCounter"))
            .chain(utxo_witness_entries(&self.maker_source, "MakerSource"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::EscrowSettle, &self.witness())?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn sample() -> EscrowSettleProofInputs {
        EscrowSettleProofInputs {
            public_input_hash: [1; 32],
            private_tx_hash: [2; 32],
            execution_price: 90,
            max_price: 100,
            created_at: 1_700_000_000,
            order_in_hash: [3; 32],
            reservation_in_hash: [4; 32],
            recipient_owner_hash: [6; 32],
            authority_owner_hash: [7; 32],
            order_amount: 50,
            order_in: ProofInputUtxo::default(),
            reservation_in: ProofInputUtxo::default(),
            recipient_out: ProofInputUtxo::default(),
            maker_counter: ProofInputUtxo::default(),
            maker_source: ProofInputUtxo::default(),
            external_data_hash: [8; 32],
        }
    }

    #[test]
    fn witness_key_set_matches_circuit_fields() {
        let witness = sample().witness();
        let keys: HashSet<&str> = witness.keys().map(String::as_str).collect();

        let mut expected: Vec<String> = vec![
            "Public_PublicInputHash".to_string(),
            "Public_PrivateTxHash".to_string(),
            "Public_ExecutionPrice".to_string(),
            "Public_OrderInHash".to_string(),
            "Public_ReservationInHash".to_string(),
            "Public_AuthorityOwnerHash".to_string(),
            "RecipientOwnerHash".to_string(),
            "MaxPrice".to_string(),
            "CreatedAt".to_string(),
            "OrderAmount".to_string(),
            "ExternalDataHash".to_string(),
        ];
        for prefix in [
            "OrderIn",
            "ReservationIn",
            "RecipientOut",
            "MakerCounter",
            "MakerSource",
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
