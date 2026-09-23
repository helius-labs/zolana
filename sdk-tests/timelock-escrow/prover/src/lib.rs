pub mod escrow;
pub mod escrow_terms;
pub mod proof;
pub mod withdraw;

pub use escrow::EscrowProofInputs;
pub use escrow_terms::EscrowTermsProofInput;
pub use proof::TimelockProof;
pub use withdraw::WithdrawProofInputs;
pub use zolana_client::ProofInputUtxo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitId {
    Escrow,
    Withdraw,
}

impl zolana_gnark_prover::Circuit for CircuitId {
    const ALL: &'static [Self] = &[Self::Escrow, Self::Withdraw];

    fn name(self) -> &'static str {
        match self {
            Self::Escrow => "escrow",
            Self::Withdraw => "withdraw",
        }
    }
}

pub static PROVER: zolana_gnark_prover::Prover<CircuitId> = zolana_gnark_prover::prover!();
