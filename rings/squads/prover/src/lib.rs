//! In-process prover for the squads ring and key encryption circuits, on the
//! shared `zolana-gnark-ffi-prover`. The Go circuits live in `circuits/`; the
//! proof input structs here only encode the witness and prove. With the
//! `test-server` feature, proofs go through the test prover server so test
//! processes share its loaded proving keys.

#[cfg(feature = "test-server")]
pub mod client;
pub mod key_encryption;
pub mod ring;
#[cfg(feature = "test-server")]
pub mod server_protocol;

pub use key_encryption::{KeyEncryptionProofInputs, KEY_ENCRYPTION_SUPPORTED_KEYS};
pub use ring::{
    ProposalProofInput, RecipientProofInput, RingProofInputs, RingUtxoProofInput, SenderProofInput,
    RING_SUPPORTED_SHAPES,
};
use zolana_gnark_ffi_prover::{CompressedProof, ProofInputMap};

/// `[a(32) || b(64) || c(32) || commitment(32) || commitment_pok(32)]`, with
/// `a` negated and every point compressed.
pub type SquadsProof = [u8; 192];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitId {
    Ring1x1,
    Ring2x2,
    KeyEncryption1,
    KeyEncryption2,
    KeyEncryption3,
}

impl zolana_gnark_ffi_prover::Circuit for CircuitId {
    const ALL: &'static [Self] = &[
        Self::Ring1x1,
        Self::Ring2x2,
        Self::KeyEncryption1,
        Self::KeyEncryption2,
        Self::KeyEncryption3,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Ring1x1 => "ring_1_1",
            Self::Ring2x2 => "ring_2_2",
            Self::KeyEncryption1 => "key_encryption_1",
            Self::KeyEncryption2 => "key_encryption_2",
            Self::KeyEncryption3 => "key_encryption_3",
        }
    }
}

pub static PROVER: zolana_gnark_ffi_prover::Prover<CircuitId> =
    zolana_gnark_ffi_prover::prover!(concat!(env!("CARGO_MANIFEST_DIR"), "/../build/gnark"));

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Prover(#[from] zolana_gnark_ffi_prover::Error),
    #[error("unsupported ring shape: {0} inputs, {1} outputs")]
    UnsupportedShape(usize, usize),
    #[error("unsupported key encryption key count: {0}")]
    UnsupportedKeyCount(usize),
    #[error("test prover server: {0}")]
    Server(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Prove `inputs` against `circuit`: through the test prover server when the
/// `test-server` feature is on and one is reachable, in process otherwise.
pub fn prove(circuit: CircuitId, inputs: &ProofInputMap) -> Result<SquadsProof> {
    #[cfg(feature = "test-server")]
    if let Some(proof) = client::try_prove_via_server(circuit, inputs) {
        return proof;
    }
    prove_in_process(circuit, inputs)
}

/// Prove with this process's Go archive, never through the test server.
pub fn prove_in_process(circuit: CircuitId, inputs: &ProofInputMap) -> Result<SquadsProof> {
    proof_bytes(PROVER.prove(circuit, inputs)?.compress()?)
}

fn proof_bytes(proof: CompressedProof) -> Result<SquadsProof> {
    let (commitment, commitment_pok) = proof
        .commitment
        .ok_or(zolana_gnark_ffi_prover::Error::MissingCommitment)?;
    let mut out = [0u8; 192];
    let (a, rest) = out.split_at_mut(32);
    a.copy_from_slice(&proof.proof_a);
    let (b, rest) = rest.split_at_mut(64);
    b.copy_from_slice(&proof.proof_b);
    let (c, rest) = rest.split_at_mut(32);
    c.copy_from_slice(&proof.proof_c);
    let (commitment_out, commitment_pok_out) = rest.split_at_mut(32);
    commitment_out.copy_from_slice(&commitment);
    commitment_pok_out.copy_from_slice(&commitment_pok);
    Ok(out)
}
