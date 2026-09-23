pub mod cancel;
pub mod make;
pub mod order_terms;
pub mod proof;
pub mod take;
pub mod take_verifiable_encryption;

pub use cancel::CancelProofInputs;
pub use make::MakeProofInputs;
pub use order_terms::{OrderTermsProofInput, TAKE_MODE_DERIVED, TAKE_MODE_VERIFIABLE};
pub use proof::OrderProof;
pub use take::TakeProofInputs;
pub use take_verifiable_encryption::{TakeVerifiableEncryptionProofInputs, TAKE_ENC_KDF_DOMAIN};
pub use zolana_client::ProofInputUtxo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitId {
    Make,
    Cancel,
    Take,
    TakeVerifiableEncryption,
}

impl zolana_gnark_prover::Circuit for CircuitId {
    const ALL: &'static [Self] = &[
        Self::Make,
        Self::Cancel,
        Self::Take,
        Self::TakeVerifiableEncryption,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Make => "make",
            Self::Cancel => "cancel",
            Self::Take => "take",
            Self::TakeVerifiableEncryption => "take_verifiable_encryption",
        }
    }
}

pub static PROVER: zolana_gnark_prover::Prover<CircuitId> = zolana_gnark_prover::prover!();
