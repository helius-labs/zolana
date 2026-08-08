//! Shared request plumbing for the two squads folds.
//!
//! A fold request carries, per leg, the proof as gnark produced it and the
//! preimage its public input chains. The prover rebuilds the leg's public
//! witness from that preimage, so the two can never drift.

use serde::Serialize;

use zolana_client::prover::hex64;

use crate::prover::proof::RecursionProof;

#[derive(Debug, Serialize)]
pub(crate) struct ProofJson {
    ar: [String; 2],
    bs: [[String; 2]; 2],
    krs: [String; 2],
    proof_commitment: [String; 2],
    proof_commitment_pok: [String; 2],
}

#[derive(Debug, Serialize)]
pub(crate) struct LegJson {
    pub(crate) proof: ProofJson,
    pub(crate) preimage: Vec<String>,
}

/// The leg fields as hex, in the order the leg circuit chained them.
pub(crate) fn preimage_json(fields: &[[u8; 32]]) -> Vec<String> {
    fields.iter().map(|field| hex64(field)).collect()
}

/// `A` is sent exactly as the prover produced it. The on-chain form negates it
/// for the pairing check. The recursive verifier does not negate, so feeding it
/// the on-chain bytes fails deep inside the fold with no useful message.
pub(crate) fn leg_json(proof: &RecursionProof, preimage: &[[u8; 32]]) -> LegJson {
    LegJson {
        proof: ProofJson {
            ar: [hex64(&proof.a[..32]), hex64(&proof.a[32..])],
            bs: [
                [hex64(&proof.b[..32]), hex64(&proof.b[32..64])],
                [hex64(&proof.b[64..96]), hex64(&proof.b[96..])],
            ],
            krs: [hex64(&proof.c[..32]), hex64(&proof.c[32..])],
            proof_commitment: [
                hex64(&proof.commitment[..32]),
                hex64(&proof.commitment[32..]),
            ],
            proof_commitment_pok: [
                hex64(&proof.commitment_pok[..32]),
                hex64(&proof.commitment_pok[32..]),
            ],
        },
        preimage: preimage_json(preimage),
    }
}
