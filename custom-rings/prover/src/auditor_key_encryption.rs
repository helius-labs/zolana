//! Proof inputs for the `auditor_key_encryption` circuit.

use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string, ffi,
    proof::{negate_and_compress_proof_with_commitment, AuditProof, ProofError},
    CircuitId,
};

/// Everything the circuit witnesses, already reduced to bytes.
///
/// A pure container: the sdk owns the hashing, the key derivation and the
/// encryption that produce these values, and `public_input_hash` must be the
/// chain the program recomputes. Nothing here validates that it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditorKeyEncryptionProofInputs {
    /// The single public input: the pinned eight-element hash chain.
    pub public_input_hash: [u8; 32],
    /// Pass-through chain element 1.
    pub private_tx_hash: [u8; 32],
    /// The AES plaintext, big-endian, and the scalar behind chain elements 2/3.
    pub tx_viewing_sk: [u8; 32],
    /// The ephemeral ECDH scalar, big-endian; its public key is elements 6/7.
    pub eph_sk: [u8; 32],
    /// The auditor key as uncompressed SEC1 `0x04 || x || y`.
    pub auditor_pk: [u8; 65],
}

impl AuditorKeyEncryptionProofInputs {
    /// Encodes the witness the way `circuits/witness/witness.go` expects: the
    /// keys are the circuit struct's field names, a `frontend.Variable` field
    /// carries one decimal value, and a `[N]frontend.Variable` field carries
    /// exactly N decimal byte values in witnessed (big-endian) order.
    fn witness(&self) -> ffi::WitnessMap {
        let mut map = HashMap::with_capacity(5);
        for (key, value) in [
            ("PublicInputHash", &self.public_input_hash),
            ("PrivateTxHash", &self.private_tx_hash),
        ] {
            map.insert(key.to_string(), vec![bytes_to_decimal_string(value)]);
        }
        for (key, bytes) in [
            ("TxViewingSk", self.tx_viewing_sk.as_slice()),
            ("EphSk", self.eph_sk.as_slice()),
            ("AuditorPk", self.auditor_pk.as_slice()),
        ] {
            map.insert(
                key.to_string(),
                bytes.iter().map(|byte| byte.to_string()).collect(),
            );
        }
        map
    }

    pub fn prove(&self) -> Result<AuditProof, ProofError> {
        negate_and_compress_proof_with_commitment(&ffi::prove(
            CircuitId::AuditorKeyEncryption,
            &self.witness(),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> AuditorKeyEncryptionProofInputs {
        let mut public_input_hash = [0u8; 32];
        public_input_hash.iter_mut().for_each(|b| *b = 0xff);
        let mut auditor_pk = [0u8; 65];
        if let Some(prefix) = auditor_pk.first_mut() {
            *prefix = 4;
        }
        if let Some(last) = auditor_pk.last_mut() {
            *last = 255;
        }
        AuditorKeyEncryptionProofInputs {
            public_input_hash,
            private_tx_hash: [1u8; 32],
            tx_viewing_sk: [2u8; 32],
            eph_sk: [3u8; 32],
            auditor_pk,
        }
    }

    #[test]
    fn witness_matches_the_circuit_fields() {
        let witness = inputs().witness();

        let mut keys: Vec<&str> = witness.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "AuditorPk",
                "EphSk",
                "PrivateTxHash",
                "PublicInputHash",
                "TxViewingSk"
            ]
        );

        let lengths: Vec<(&str, usize)> = [
            "PublicInputHash",
            "PrivateTxHash",
            "TxViewingSk",
            "EphSk",
            "AuditorPk",
        ]
        .into_iter()
        .map(|key| {
            let len = witness
                .get(key)
                .unwrap_or_else(|| panic!("witness is missing {key}"))
                .len();
            (key, len)
        })
        .collect();
        assert_eq!(
            lengths,
            vec![
                ("PublicInputHash", 1),
                ("PrivateTxHash", 1),
                ("TxViewingSk", 32),
                ("EphSk", 32),
                ("AuditorPk", 65),
            ]
        );
    }

    #[test]
    fn scalars_are_one_decimal_field_element_and_arrays_are_decimal_bytes() {
        let witness = inputs().witness();

        assert_eq!(
            witness.get("PublicInputHash").map(Vec::as_slice),
            Some(
                [
                    "115792089237316195423570985008687907853269984665640564039457584007913129639935"
                        .to_string()
                ]
                .as_slice()
            )
        );
        let auditor_pk = witness
            .get("AuditorPk")
            .expect("witness is missing AuditorPk");
        assert_eq!(auditor_pk.first().map(String::as_str), Some("4"));
        assert_eq!(auditor_pk.last().map(String::as_str), Some("255"));
        assert_eq!(
            witness.get("EphSk").and_then(|values| values.first()),
            Some(&"3".to_string())
        );
    }
}
