use serde::Serialize;
use zolana_interface::verifying_keys::InnerCircuitKind;

use crate::prover::{
    json::{hex64, proof_json, ProofJson},
    proof::Proof,
};

/// One proof to batch, with the public input the shielded pool recomputes for
/// it.
#[derive(Debug, Clone)]
pub struct AggregateLeg {
    pub proof: Proof,
    pub public_input_hash: [u8; 32],
}

/// Inputs for one aggregate proof request.
#[derive(Debug, Clone)]
pub struct AggregateInputs {
    pub inner: InnerCircuitKind,
    pub num_inputs: u8,
    pub num_outputs: u8,
    pub legs: Vec<AggregateLeg>,
}

#[derive(Debug, Serialize)]
struct LegJson {
    proof: ProofJson,
    #[serde(rename = "publicInputHash")]
    public_input_hash: String,
}

#[derive(Debug, Serialize)]
struct AggregateParamsJson {
    #[serde(rename = "circuitType")]
    circuit_type: &'static str,
    #[serde(rename = "innerCircuitType")]
    inner_circuit_type: &'static str,
    #[serde(rename = "nInputs")]
    n_inputs: u8,
    #[serde(rename = "nOutputs")]
    n_outputs: u8,
    legs: Vec<LegJson>,
}

/// The prover names rails by the same strings its key files use.
fn inner_circuit_type(inner: InnerCircuitKind) -> &'static str {
    match inner {
        InnerCircuitKind::ConfidentialEddsa => "transfer-confidential",
        InnerCircuitKind::RingEddsa => "transfer-ring",
        InnerCircuitKind::RingAuthority => "transfer-ring-authority",
        InnerCircuitKind::RingP256 => "transfer-p256-ring",
    }
}

pub(crate) fn to_json_aggregate(inputs: &AggregateInputs) -> String {
    let params = AggregateParamsJson {
        circuit_type: "aggregate",
        inner_circuit_type: inner_circuit_type(inputs.inner),
        n_inputs: inputs.num_inputs,
        n_outputs: inputs.num_outputs,
        legs: inputs
            .legs
            .iter()
            .map(|leg| LegJson {
                proof: proof_json(&leg.proof),
                public_input_hash: hex64(&leg.public_input_hash),
            })
            .collect(),
    };
    serde_json::to_string(&params).expect("aggregate request serialization is infallible")
}
