use serde::Serialize;
use zeroize::Zeroizing;

use super::{
    decode_field, decode_resolution, invalid, invalid_resolution, policy::SecretJson,
    IndexedRegistry, Request,
};
use crate::{
    prover::{Delivery, ExpectedProvingKey, Proof, ProveRequest},
    ClientError,
};

pub struct IndexedDepositRequest {
    body: Zeroizing<String>,
    key: ExpectedProvingKey,
    public_input_hash: [u8; 32],
}

impl IndexedDepositRequest {
    pub fn new(
        request: &impl ProveRequest,
        registry: IndexedRegistry,
    ) -> Result<Self, ClientError> {
        let body = request.body()?;
        if body.len() > 1 << 20 {
            return Err(invalid());
        }
        let mut prepared = SecretJson(serde_json::from_str(&body).map_err(|_| invalid())?);
        let value = prepared.as_object_mut().ok_or_else(invalid)?;
        if value.get("circuitType").and_then(serde_json::Value::as_str)
            != Some("custom-ring-deposit")
            || value.get("keyEscrow").and_then(serde_json::Value::as_bool) != Some(true)
            || registry.next_index == 0
            || registry.next_index > 1 << 40
            || decode_field(
                value
                    .get("keyRegistryRoot")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?
                != registry.root
        {
            return Err(invalid());
        }
        value.remove("keys");
        let public_input = value
            .get("publicInputHash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?
            .to_owned();
        let public_input_hash = decode_field(&public_input).map_err(|_| invalid())?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Envelope<'a> {
            circuit_type: &'static str,
            prepared: &'a serde_json::Value,
            public_inputs: [&'a str; 1],
            registry: IndexedRegistry,
        }
        let body = serde_json::to_string(&Envelope {
            circuit_type: "custom-ring-deposit",
            prepared: &prepared.0,
            public_inputs: [&public_input],
            registry,
        })
        .map_err(|_| invalid())?;
        Ok(Self {
            body: Zeroizing::new(body),
            key: request.proving_key()?,
            public_input_hash,
        })
    }
}

impl Request for IndexedDepositRequest {
    type Output = Proof;

    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        Ok(self.body.clone())
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        Ok(self.key.clone())
    }

    fn delivery(&self) -> Option<Delivery> {
        Some(Delivery::InResponse)
    }

    fn finish(&self, proof: Proof, resolution: serde_json::Value) -> Result<Proof, ClientError> {
        let resolution = decode_resolution(resolution)?;
        resolution.check_trees([])?;
        if resolution.public_input_hash != self.public_input_hash {
            return Err(invalid_resolution());
        }
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};
    use solana_address::Address;

    use super::*;

    struct Deposit(Value);

    impl ProveRequest for Deposit {
        fn body(&self) -> Result<Zeroizing<String>, ClientError> {
            Ok(Zeroizing::new(self.0.to_string()))
        }

        fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
            Ok(ExpectedProvingKey {
                name: "deposit.key".into(),
                sha256: [0; 32],
            })
        }
    }

    fn request() -> IndexedDepositRequest {
        let mut root = [0; 32];
        root[31] = 9;
        IndexedDepositRequest::new(
            &Deposit(json!({
                "circuitType": "custom-ring-deposit",
                "keyEscrow": true,
                "keyRegistryRoot": "0x9",
                "publicInputHash": "0x5",
                "keys": [{"path": []}],
            })),
            IndexedRegistry {
                ring_program_id: Address::new_from_array([3; 32]),
                root,
                next_index: 2,
            },
        )
        .unwrap()
    }

    fn finish(resolution: Value) -> Result<Proof, ClientError> {
        let proof = Proof {
            a: [0; 64],
            b: [0; 128],
            c: [0; 64],
            commitment: None,
        };
        request().finish(proof, resolution)
    }

    #[test]
    fn the_body_leaves_key_openings_to_the_prover() {
        let body: Value = serde_json::from_str(&request().body().unwrap()).unwrap();
        assert!(body["prepared"].get("keys").is_none());
        assert_eq!(body["publicInputs"], json!(["0x5"]));
        assert_eq!(body["prepared"]["keyRegistryRoot"], "0x9");
    }

    #[test]
    fn the_resolution_binds_no_trees_and_the_statement() {
        assert!(finish(json!({"trees": [], "publicInputHash": "0x5"})).is_ok());
        assert!(finish(json!({"trees": [], "publicInputHash": "0x6"})).is_err());
        let tree = json!({"tree": zolana_interface::pda::tree(3).to_string(), "id": 3,
            "utxoRoot": "0x1", "nullifierRoot": "0x2", "utxoRootIndex": 0, "nullifierRootIndex": 0});
        assert!(finish(json!({"trees": [tree], "publicInputHash": "0x5"})).is_err());
    }
}
