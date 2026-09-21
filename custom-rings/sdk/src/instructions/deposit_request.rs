use custom_ring_interface::MAX_RING_DEPOSIT_AUDIT_SLOTS;
use serde::{ser::SerializeStruct, Serialize, Serializer};
use zeroize::Zeroizing;

use super::transact::request::{json_body, SecretHex};
use zolana_client::{prover::ProveRequest, ClientError};

pub struct RingDepositProofRequest<'a> {
    pub public_input_hash: &'a [u8; 32],
    pub context_hash: &'a [u8; 32],
    pub count: u8,
    pub owner_hashes: &'a [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    pub blindings: &'a [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    pub ephemeral_sk: &'a [u8; 32],
    pub auditor_pk: &'a [u8; 65],
}

impl Serialize for RingDepositProofRequest<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("RingDepositProofRequest", 8)?;
        state.serialize_field("circuitType", "custom-ring-deposit")?;
        state.serialize_field("publicInputHash", &SecretHex::new(self.public_input_hash))?;
        state.serialize_field("contextHash", &SecretHex::new(self.context_hash))?;
        state.serialize_field("count", &self.count)?;
        state.serialize_field(
            "ownerHashes",
            &self
                .owner_hashes
                .each_ref()
                .map(|value| SecretHex::new(value)),
        )?;
        state.serialize_field(
            "blindings",
            &self.blindings.each_ref().map(|value| SecretHex::new(value)),
        )?;
        state.serialize_field("ephSk", &SecretHex::new(self.ephemeral_sk))?;
        state.serialize_field("auditorPk", &SecretHex::new(self.auditor_pk))?;
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
        json_body(self)
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
