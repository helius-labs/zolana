//! Fold several zone spends of one account into one proof.
//!
//! The zone circuit has a key for `(1,1)` and `(2,2)` only, so three UTXOs
//! cannot be spent together. Each leg keeps its own transaction and settles
//! through its own SPP `ring_transact`. The fold proves every leg spends the
//! same account and pays the same recipient, so the run is one operation.
//!
//! A leg carries no proposal. A proposal commits to one recipient amount, so a
//! folded run under one would settle it once per leg.

use serde::Serialize;

use crate::prover::{
    error::SquadsProverError,
    fold::{leg_json, LegJson},
    proof::gnark_json_to_transact_bytes,
    server::send_prove_request,
    shared_viewing_key::hash_chain,
    zone::{ZoneProofInputs, ZoneProofResult},
};

/// Leg shapes with a fold key, as `(n_inputs, n_outputs)`. MUST mirror the
pub use zolana_squads_interface::circuits::ZONE_FOLD_SUPPORTED_SHAPES;

/// Leg counts with a fold key. MUST mirror the program's
pub use zolana_squads_interface::circuits::ZONE_FOLD_SUPPORTED_LEGS;

/// Positions in a transfer leg's public-input chain. Mirrors the index
/// constants in `prover/server/circuits/squads/zone_fold/fold.go`.
const PRIVATE_TX_HASH: usize = 0;
const PUBLIC_AMOUNT: usize = 1;
const SENDER_ACCOUNT: usize = 2;
const SENDER_CIPHERTEXT: usize = 3;
const TX_VIEWING_PK_LO: usize = 4;
const TX_VIEWING_PK_HI: usize = 5;
const RECIPIENT_ACCOUNT: usize = 6;
const RECIPIENT_CIPHERTEXT: usize = 7;
const TRANSFER_PREIMAGE_LEN: usize = 9;

/// The proved legs of a folded spend together with the fold proof. The caller
/// settles each leg result through SPP. The zone verifies the fold proof once.
pub struct ZoneFoldProofResult {
    pub legs: Vec<ZoneProofResult>,
    /// The public input the zone recomputes: the shared sender and recipient
    /// once, then every leg's own fields in leg order.
    pub public_input_hash: [u8; 32],
    /// The 192-byte compressed Groth16 proof of the fold.
    pub proof: [u8; 192],
}

#[derive(Serialize)]
struct FoldRequestJson {
    #[serde(rename = "circuitType")]
    circuit_type: &'static str,
    #[serde(rename = "nInputs")]
    n_inputs: u32,
    #[serde(rename = "nOutputs")]
    n_outputs: u32,
    legs: Vec<LegJson>,
}

/// Prove each leg, then fold them.
///
/// Every leg must be the same supported shape, spend the same sender account,
/// pay the same recipient, and carry no proposal. The first three are checked
/// here so the caller sees which leg is wrong rather than an unsatisfiable
/// constraint system. The program trusts only the circuit.
pub fn prove_zone_fold(
    legs: Vec<ZoneProofInputs>,
    server_address: &str,
) -> Result<ZoneFoldProofResult, SquadsProverError> {
    if !u8::try_from(legs.len()).is_ok_and(|legs| ZONE_FOLD_SUPPORTED_LEGS.contains(&legs)) {
        return Err(SquadsProverError::UnsupportedLegCount(legs.len()));
    }
    let (n_inputs, n_outputs) = match legs.first() {
        Some(leg) => (leg.inputs.len(), leg.outputs.len()),
        None => return Err(SquadsProverError::UnsupportedLegCount(0)),
    };
    // Narrow before the allowlist check, or a count whose low byte is supported
    // would pass the guard.
    let shape = match (u8::try_from(n_inputs), u8::try_from(n_outputs)) {
        (Ok(inputs), Ok(outputs)) => (inputs, outputs),
        _ => return Err(SquadsProverError::UnsupportedShape(n_inputs, n_outputs)),
    };
    if !ZONE_FOLD_SUPPORTED_SHAPES.contains(&shape) {
        return Err(SquadsProverError::UnsupportedShape(n_inputs, n_outputs));
    }
    for leg in &legs {
        if leg.inputs.len() != n_inputs || leg.outputs.len() != n_outputs {
            return Err(SquadsProverError::UnsupportedShape(
                leg.inputs.len(),
                leg.outputs.len(),
            ));
        }
        if leg.proposal.is_some() {
            return Err(SquadsProverError::FoldedProposal);
        }
    }

    let mut proved = Vec::with_capacity(legs.len());
    let mut requests = Vec::with_capacity(legs.len());
    for leg in legs {
        let result = leg.prove(server_address)?;
        if result.public_input_chain.len() != TRANSFER_PREIMAGE_LEN {
            return Err(SquadsProverError::UnsupportedShape(n_inputs, n_outputs));
        }
        requests.push(leg_json(
            &result.recursion_proof,
            &result.public_input_chain,
        ));
        proved.push(result);
    }

    let first = proved
        .first()
        .ok_or(SquadsProverError::UnsupportedLegCount(0))?;
    let sender = first.public_input_chain[SENDER_ACCOUNT];
    let recipient = first.public_input_chain[RECIPIENT_ACCOUNT];
    for (index, leg) in proved.iter().enumerate() {
        if leg.public_input_chain[SENDER_ACCOUNT] != sender {
            return Err(SquadsProverError::FoldedSenderMismatch(index));
        }
        if leg.public_input_chain[RECIPIENT_ACCOUNT] != recipient {
            return Err(SquadsProverError::FoldedRecipientMismatch(index));
        }
    }

    let mut chain = vec![sender, recipient];
    for leg in &proved {
        chain.push(leg.public_input_chain[PRIVATE_TX_HASH]);
        chain.push(leg.public_input_chain[PUBLIC_AMOUNT]);
        chain.push(leg.public_input_chain[SENDER_CIPHERTEXT]);
        chain.push(leg.public_input_chain[TX_VIEWING_PK_LO]);
        chain.push(leg.public_input_chain[TX_VIEWING_PK_HI]);
        chain.push(leg.public_input_chain[RECIPIENT_CIPHERTEXT]);
    }
    let public_input_hash = hash_chain(&chain)?;

    let request = serde_json::to_string(&FoldRequestJson {
        circuit_type: "squads-zone-fold",
        n_inputs: n_inputs as u32,
        n_outputs: n_outputs as u32,
        legs: requests,
    })
    .map_err(|e| SquadsProverError::RequestSerialize(format!("{e}")))?;
    let proof_json = send_prove_request(server_address, &request)?;
    let proof = gnark_json_to_transact_bytes(&proof_json)?;

    Ok(ZoneFoldProofResult {
        legs: proved,
        public_input_hash,
        proof,
    })
}
