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
        inputs::{BatchAddressAppendInputs, MergeInputs, TransferInputs},
        json::{
            to_json, to_json_batch_address_append, to_json_merge, to_json_merge_ring, to_json_ring,
            to_json_ring_authority,
        },
        proving_key::ExpectedProvingKey,
    },
};

/// A request whose body is already encoded, so an encoding error surfaces
/// before any backend sees it.
pub struct CircuitRequest {
    body: Zeroizing<String>,
    proving_key: ExpectedProvingKey,
    delivery: Delivery,
}

impl CircuitRequest {
    /// Encodes `request` now, so the copy outlives it.
    pub fn of(request: &(impl ProveRequest + ?Sized)) -> Result<Self, ClientError> {
        Ok(Self {
            body: request.body()?,
            proving_key: request.proving_key()?,
            delivery: request.delivery(),
        })
    }
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

pub fn transfer(inputs: &TransferInputs) -> Result<CircuitRequest, ClientError> {
    let key = ExpectedProvingKey::transfer_confidential(inputs.inputs.len(), inputs.outputs.len())?;
    Ok(in_response(to_json(inputs)?, key))
}

pub fn transfer_ring(inputs: &TransferInputs) -> Result<CircuitRequest, ClientError> {
    let key = ExpectedProvingKey::transfer_ring(inputs.inputs.len(), inputs.outputs.len())?;
    Ok(in_response(to_json_ring(inputs)?, key))
}

pub fn ring_authority(inputs: &TransferInputs) -> Result<CircuitRequest, ClientError> {
    let key =
        ExpectedProvingKey::transfer_ring_authority(inputs.inputs.len(), inputs.outputs.len())?;
    Ok(in_response(to_json_ring_authority(inputs)?, key))
}

pub(crate) fn merge(inputs: &MergeInputs) -> Result<CircuitRequest, ClientError> {
    validate_merge_state(inputs)?;
    let key = ExpectedProvingKey::merge(inputs.inputs.len())?;
    Ok(in_response(to_json_merge(inputs), key))
}

pub fn merge_ring(inputs: &MergeInputs) -> Result<CircuitRequest, ClientError> {
    validate_merge_state(inputs)?;
    let key = ExpectedProvingKey::merge_ring(inputs.inputs.len())?;
    Ok(in_response(to_json_merge_ring(inputs), key))
}

/// Raw numeric requests carry the same merge state obligation as wallet plans.
fn validate_merge_state(inputs: &MergeInputs) -> Result<(), ClientError> {
    use zolana_transaction::{instructions::merge::merge_ring_data_hash, TransactionError};
    let ring = super::field::right_align_slice(&inputs.ring_program_id.to_bytes_be())?;
    let published_hash =
        super::field::right_align_slice(&inputs.output_ring_data_hash.to_bytes_be())?;
    if [inputs.output.utxo.asset, ring, published_hash]
        .iter()
        .any(|field| !zolana_hasher::primitives::is_canonical_bn254_scalar_be(field))
    {
        return Err(TransactionError::NonCanonicalField.into());
    }
    if inputs.output.utxo.asset == [0; 32] {
        return Err(TransactionError::ZeroMergeAsset.into());
    }
    let output_hash = inputs.output.utxo.ring_data_hash;
    if num_bigint::BigUint::from_bytes_be(&output_hash) != inputs.output_ring_data_hash
        || (inputs.ring_program_id == num_bigint::BigUint::ZERO && output_hash != [0; 32])
    {
        return Err(TransactionError::MergeOutputRingDataMismatch.into());
    }
    let dummy = zolana_hasher::primitives::right_align(
        &zolana_transaction::utxo::DUMMY_DOMAIN.to_be_bytes(),
    );
    merge_ring_data_hash(
        inputs
            .inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| input.utxo.domain != dummy)
            .map(|(index, input)| (index, Some(input.utxo.ring_data_hash))),
        Some(output_hash),
    )?;
    Ok(())
}

/// A batch proof runs far longer than a connection should be held open, so it
/// always queues.
pub fn batch_address_append(
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
