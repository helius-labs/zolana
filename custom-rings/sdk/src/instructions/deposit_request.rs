use custom_ring_interface::MAX_RING_DEPOSIT_AUDIT_SLOTS;
use serde::{ser::SerializeStruct, Serialize, Serializer};
use zeroize::Zeroizing;

use super::transact::{
    registry_key_json,
    request::{json_body, SecretHex},
};
use crate::escrow::RegistryKeyOpening;
use zolana_client::{prover::ProveRequest, ClientError};

pub struct RingDepositProofRequest<'a> {
    pub public_input_hash: &'a [u8; 32],
    pub context_hash: &'a [u8; 32],
    pub count: u8,
    pub owner_pk_hashes: &'a [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    pub nullifier_pks: &'a [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    pub blindings: &'a [[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    /// `None` with escrow off and in padding.
    pub keys: &'a [Option<RegistryKeyOpening>; MAX_RING_DEPOSIT_AUDIT_SLOTS],
    /// `None` with escrow off.
    pub key_registry_root: Option<&'a [u8; 32]>,
    pub ephemeral_sk: &'a [u8; 32],
    pub auditor_pk: &'a [u8; 65],
}

impl Serialize for RingDepositProofRequest<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let fields = |values: &[[u8; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS]| {
            values.each_ref().map(|value| SecretHex::new(value))
        };
        let mut state = serializer.serialize_struct("RingDepositProofRequest", 12)?;
        state.serialize_field("circuitType", "custom-ring-deposit")?;
        state.serialize_field("publicInputHash", &SecretHex::new(self.public_input_hash))?;
        state.serialize_field("contextHash", &SecretHex::new(self.context_hash))?;
        state.serialize_field("count", &self.count)?;
        state.serialize_field("ownerPkHashes", &fields(self.owner_pk_hashes))?;
        state.serialize_field("nullifierPks", &fields(self.nullifier_pks))?;
        state.serialize_field("blindings", &fields(self.blindings))?;
        state.serialize_field(
            "keys",
            &self
                .keys
                .each_ref()
                .map(|key| key.as_ref().map(registry_key_json)),
        )?;
        state.serialize_field("ephSk", &SecretHex::new(self.ephemeral_sk))?;
        state.serialize_field("auditorPk", &SecretHex::new(self.auditor_pk))?;
        state.serialize_field("keyEscrow", &self.key_registry_root.is_some())?;
        state.serialize_field(
            "keyRegistryRoot",
            &SecretHex::new(self.key_registry_root.unwrap_or(&[0; 32])),
        )?;
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
        if self.owner_pk_hashes[count..]
            .iter()
            .chain(&self.nullifier_pks[count..])
            .chain(&self.blindings[count..])
            .any(|value| *value != [0; 32])
            || self.keys[count..].iter().any(Option::is_some)
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

    fn key() -> RegistryKeyOpening {
        RegistryKeyOpening {
            next: [5; 32],
            ct_hash: [6; 32],
            index: 3,
            path: [[7; 32]; custom_ring_interface::KEY_REGISTRY_HEIGHT],
        }
    }

    #[test]
    fn request_uses_fixed_slots_and_canonical_json_names() {
        let mut owners = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        owners[0][31] = 2;
        let nullifier_pks = owners;
        let blindings = owners;
        let mut keys = [None; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        keys[0] = Some(key());
        let request = RingDepositProofRequest {
            public_input_hash: &[0; 32],
            context_hash: &[1; 32],
            count: 1,
            owner_pk_hashes: &owners,
            nullifier_pks: &nullifier_pks,
            blindings: &blindings,
            keys: &keys,
            key_registry_root: Some(&[9; 32]),
            ephemeral_sk: &[3; 32],
            auditor_pk: &[4; 65],
        };
        let body = request.body().unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["circuitType"], "custom-ring-deposit");
        assert_eq!(json["count"], 1);
        assert_eq!(json["ownerPkHashes"].as_array().unwrap().len(), 8);
        assert_eq!(json["ownerPkHashes"][0], format!("0x{:064x}", 2));
        assert_eq!(json["nullifierPks"][0], format!("0x{:064x}", 2));
        assert_eq!(json["blindings"][7], format!("0x{:064x}", 0));
        assert_eq!(json["keys"].as_array().unwrap().len(), 8);
        assert_eq!(json["keys"][0]["index"], 3);
        assert_eq!(
            json["keys"][0]["path"].as_array().unwrap().len(),
            custom_ring_interface::KEY_REGISTRY_HEIGHT
        );
        assert!(json["keys"][1].is_null());
        assert_eq!(json["keyEscrow"], true);
        assert_eq!(json["keyRegistryRoot"], format!("0x{}", "09".repeat(32)));
        assert_eq!(json["auditorPk"].as_str().unwrap().len(), 132);

        let mut padded = owners;
        padded[7][0] = 1;
        let unused = |request: RingDepositProofRequest<'_>| {
            matches!(
                request.body(),
                Err(ClientError::Prover(message)) if message == "unused deposit openings must be zero"
            )
        };
        assert!(unused(RingDepositProofRequest {
            owner_pk_hashes: &padded,
            ..request
        }));
        let mut padded_keys = keys;
        padded_keys[7] = Some(key());
        assert!(unused(RingDepositProofRequest {
            keys: &padded_keys,
            ..request
        }));
    }

    #[test]
    fn escrow_off_sends_a_zero_root() {
        let slots = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        let body = RingDepositProofRequest {
            public_input_hash: &[0; 32],
            context_hash: &[1; 32],
            count: 1,
            owner_pk_hashes: &slots,
            nullifier_pks: &slots,
            blindings: &slots,
            keys: &[None; MAX_RING_DEPOSIT_AUDIT_SLOTS],
            key_registry_root: None,
            ephemeral_sk: &[3; 32],
            auditor_pk: &[4; 65],
        }
        .body()
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["keyEscrow"], false);
        assert_eq!(json["keyRegistryRoot"], format!("0x{}", "00".repeat(32)));
    }
}
