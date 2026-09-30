//! One request per circuit this crate proves: the body in the prover's wire
//! format and what a backend needs to prove it. The
//! [`ProverExt`](super::ProverExt) trait, [`AsyncProverClient`](super::AsyncProverClient) and
//! [`ZolanaClient`](crate::ZolanaClient) all build their requests here, so each
//! circuit is described once.

use zeroize::Zeroizing;

use crate::{
    error::ClientError,
    prover::{
        client::{Delivery, ProveRequest},
        inputs::{BatchAddressAppendInputs, MergeInputs, TransferInputs, TransferP256Inputs},
        json::{
            to_json, to_json_batch_address_append, to_json_merge, to_json_merge_ring,
            to_json_p256_ring, to_json_ring, to_json_ring_authority,
        },
        proving_key::ExpectedProvingKey,
    },
};

/// A request whose body is already encoded, so an encoding error surfaces
/// before any backend sees it.
pub(crate) struct CircuitRequest {
    body: Zeroizing<String>,
    proving_key: ExpectedProvingKey,
    delivery: Delivery,
}

impl ProveRequest for CircuitRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        Ok(self.body.clone())
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        Ok(self.proving_key.clone())
    }

    fn delivery(&self) -> Delivery {
        self.delivery
    }
}

/// Transfer-shaped proofs are fast enough to ask for in the response.
fn in_response(body: String, proving_key: ExpectedProvingKey) -> CircuitRequest {
    CircuitRequest {
        body: Zeroizing::new(body),
        proving_key,
        delivery: Delivery::InResponse,
    }
}

pub(crate) fn transfer(inputs: &TransferInputs) -> Result<CircuitRequest, ClientError> {
    let key = ExpectedProvingKey::transfer_confidential(inputs.inputs.len(), inputs.outputs.len())?;
    Ok(in_response(to_json(inputs)?, key))
}

pub(crate) fn transfer_ring(inputs: &TransferInputs) -> Result<CircuitRequest, ClientError> {
    let key = ExpectedProvingKey::transfer_ring(inputs.inputs.len(), inputs.outputs.len())?;
    Ok(in_response(to_json_ring(inputs)?, key))
}

pub(crate) fn ring_authority(inputs: &TransferInputs) -> Result<CircuitRequest, ClientError> {
    let key =
        ExpectedProvingKey::transfer_ring_authority(inputs.inputs.len(), inputs.outputs.len())?;
    Ok(in_response(to_json_ring_authority(inputs)?, key))
}

pub(crate) fn transfer_p256_ring(
    inputs: &TransferP256Inputs,
) -> Result<CircuitRequest, ClientError> {
    let key = ExpectedProvingKey::transfer_p256_ring(inputs.inputs.len(), inputs.outputs.len())?;
    Ok(in_response(to_json_p256_ring(inputs)?, key))
}

pub(crate) fn merge(inputs: &MergeInputs) -> Result<CircuitRequest, ClientError> {
    let key = ExpectedProvingKey::merge(inputs.inputs.len())?;
    Ok(in_response(to_json_merge(inputs), key))
}

pub(crate) fn merge_ring(inputs: &MergeInputs) -> Result<CircuitRequest, ClientError> {
    let key = ExpectedProvingKey::merge_ring(inputs.inputs.len())?;
    Ok(in_response(to_json_merge_ring(inputs), key))
}

/// A batch proof runs far longer than a connection should be held open, so it
/// always queues.
pub(crate) fn batch_address_append(
    inputs: &BatchAddressAppendInputs,
) -> Result<CircuitRequest, ClientError> {
    Ok(CircuitRequest {
        body: Zeroizing::new(to_json_batch_address_append(inputs)),
        proving_key: ExpectedProvingKey::batch_address_append(
            inputs.tree_height,
            inputs.batch_size,
        )?,
        delivery: Delivery::Queued,
    })
}
