use serde::{ser::SerializeStruct, Serialize, Serializer};
use std::fmt::Write;
use zeroize::Zeroizing;
use zolana_event::MAX_RING_DEPOSIT_AUDIT_SLOTS;

use crate::{prover::ProveRequest, ClientError};

pub struct RingDepositProofRequest<'a> {
    pub public_input_hash: &'a [u8; 32],
    pub context_hash: &'a [u8; 32],
    pub count: u8,
    pub owner_hashes: &'a [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    pub blindings: &'a [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    pub ephemeral_sk: &'a [u8; 32],
    pub auditor_pk: &'a [u8; 65],
}

struct Hex<'a>(&'a [u8]);

impl Serialize for Hex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut encoded = Zeroizing::new(String::from("0x"));
        for byte in self.0 {
            write!(&mut *encoded, "{byte:02x}").map_err(serde::ser::Error::custom)?;
        }
        serializer.serialize_str(&encoded)
    }
}

impl Serialize for RingDepositProofRequest<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("RingDepositProofRequest", 8)?;
        state.serialize_field("circuitType", "custom-ring-deposit")?;
        state.serialize_field("publicInputHash", &Hex(self.public_input_hash))?;
        state.serialize_field("contextHash", &Hex(self.context_hash))?;
        state.serialize_field("count", &self.count)?;
        state.serialize_field(
            "ownerHashes",
            &self.owner_hashes.each_ref().map(|value| Hex(value)),
        )?;
        state.serialize_field(
            "blindings",
            &self.blindings.each_ref().map(|value| Hex(value)),
        )?;
        state.serialize_field("ephSk", &Hex(self.ephemeral_sk))?;
        state.serialize_field("auditorPk", &Hex(self.auditor_pk))?;
        state.end()
    }
}

impl ProveRequest for RingDepositProofRequest<'_> {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        let count = usize::from(self.count);
        if !(1..=MAX_RING_DEPOSIT_AUDIT_SLOTS).contains(&count) {
            return Err(ClientError::Prover(
                "deposit count must be between one and eight".into(),
            ));
        }
        if self.owner_hashes[count..]
            .iter()
            .chain(&self.blindings[count..])
            .any(|value| *value != [0; 32])
        {
            return Err(ClientError::Prover(
                "unused deposit openings must be zero".into(),
            ));
        }
        serde_json::to_string(self)
            .map(Zeroizing::new)
            .map_err(|error| ClientError::Prover(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_uses_fixed_slots_and_canonical_json_names() {
        let mut owners = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        owners[0][31] = 2;
        let blindings = owners;
        let request = RingDepositProofRequest {
            public_input_hash: &[0; 32],
            context_hash: &[1; 32],
            count: 1,
            owner_hashes: &owners,
            blindings: &blindings,
            ephemeral_sk: &[3; 32],
            auditor_pk: &[4; 65],
        };
        let body = request.body().unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["circuitType"], "custom-ring-deposit");
        assert_eq!(json["count"], 1);
        assert_eq!(json["ownerHashes"].as_array().unwrap().len(), 8);
        assert_eq!(json["ownerHashes"][0], format!("0x{:064x}", 2));
        assert_eq!(json["blindings"][7], format!("0x{:064x}", 0));
        assert_eq!(json["auditorPk"].as_str().unwrap().len(), 132);
        let mut invalid = owners;
        invalid[7][0] = 1;
        assert!(RingDepositProofRequest {
            owner_hashes: &invalid,
            ..request
        }
        .body()
        .is_err());
    }
}
