use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string,
    ffi::{self, CircuitId},
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    ProofInputUtxo,
};

/// Per-output-slot domains folded into the settle output-blinding derivation
/// (`Poseidon(blinding, domain)`). These MUST stay byte-for-byte in sync with
/// the Go copies in `prover/circuits/escrow_settle/escrow_settle.go`. The
/// recipient output derives from the order blinding (the taker precomputes its
/// payout note at creation); the funder outputs derive from the funding
/// blinding.
pub const RECIPIENT_BLINDING_DOMAIN: u64 = 0x5354_4C52_4543_4950; // "STLRECIP"
pub const FUNDER_CHANGE_BLINDING_DOMAIN: u64 = 0x5354_4C46_4E43_4847; // "STLFNCHG"
pub const FUNDER_RECEIPT_BLINDING_DOMAIN: u64 = 0x5354_4C46_4E52_4350; // "STLFNRCP"

/// The cancel refund output's blinding domain (`Poseidon(order_blinding,
/// domain)`), distinct from the settle recipient domain deriving from the same
/// order blinding. MUST stay byte-for-byte in sync with the Go copy in
/// `prover/circuits/escrow_cancel/escrow_cancel.go`.
pub const CANCEL_REFUND_BLINDING_DOMAIN: u64 = 0x434E_4C52_4546_4E44; // "CNLREFND"

/// Proof inputs for the `escrow_settle` circuit: 2-in (order, maker funding) /
/// 3-out (recipient payout, funder change, funder receipt), the exact IN2_OUT3
/// shape, no padding. There is no refund branch: an escrow can only exist at an
/// acceptable price, so settle always pays `order_amount * execution_price` of
/// the destination asset to the recipient committed as the order UTXO's data
/// hash. `execution_price` is public (the escrow account's stored price); the
/// recipient owner-hash stays private, re-opened from `OrderIn.DataHash` which
/// the public `OrderInHash` pins.
#[derive(Debug, Clone)]
pub struct EscrowSettleProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub execution_price: u64,
    /// The order-input UTXO's own hash -- the escrow account's on-chain
    /// `Escrow.order_utxo_hash`, asserted equal in-circuit to `Hash(order_in)`.
    pub order_in_hash: [u8; 32],
    /// The pair's destination-asset commitment (`DestinationAsset`), bound to
    /// `MakerFunding.Asset`.
    pub destination_asset: [u8; 32],
    pub order_amount: u64,
    pub order_in: ProofInputUtxo,
    pub maker_funding: ProofInputUtxo,
    pub recipient_out: ProofInputUtxo,
    pub funder_change: ProofInputUtxo,
    pub funder_receipt: ProofInputUtxo,
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
        for (key, value) in utxo_witness_entries(&self.order_in, "OrderIn")
            .into_iter()
            .chain(utxo_witness_entries(&self.maker_funding, "MakerFunding"))
            .chain(utxo_witness_entries(&self.recipient_out, "RecipientOut"))
            .chain(utxo_witness_entries(&self.funder_change, "FunderChange"))
            .chain(utxo_witness_entries(&self.funder_receipt, "FunderReceipt"))
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
            order_in_hash: [3; 32],
            destination_asset: [4; 32],
            order_amount: 50,
            order_in: ProofInputUtxo::default(),
            maker_funding: ProofInputUtxo::default(),
            recipient_out: ProofInputUtxo::default(),
            funder_change: ProofInputUtxo::default(),
            funder_receipt: ProofInputUtxo::default(),
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
            "Public_DestinationAsset".to_string(),
            "OrderAmount".to_string(),
            "ExternalDataHash".to_string(),
        ];
        for prefix in [
            "OrderIn",
            "MakerFunding",
            "RecipientOut",
            "FunderChange",
            "FunderReceipt",
        ] {
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
