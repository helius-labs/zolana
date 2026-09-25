use serde::Serialize;
use zeroize::Zeroizing;

use super::{decode_field, invalid, policy::SecretJson, IndexedRegistry, ProofDataSource};
use crate::{
    prover::{Delivery, ExpectedProvingKey, ProveRequest},
    ClientError,
};

pub struct IndexedDepositRequest {
    body: Zeroizing<String>,
    key: ExpectedProvingKey,
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
            )? != registry.root
        {
            return Err(invalid());
        }
        value.remove("keys");
        let public_input = value
            .get("publicInputHash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?
            .to_owned();
        decode_field(&public_input)?;
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
        })
    }
}

impl ProveRequest for IndexedDepositRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        Ok(self.body.clone())
    }
    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        Ok(self.key.clone())
    }
    fn delivery(&self) -> Delivery {
        Delivery::InResponse
    }
    fn proof_data_source(&self) -> ProofDataSource {
        ProofDataSource::Prover
    }
}
