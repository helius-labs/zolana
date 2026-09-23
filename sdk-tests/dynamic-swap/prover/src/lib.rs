pub mod escrow_open;
pub mod escrow_settle;
pub mod proof;

pub use escrow_open::EscrowOpenProofInputs;
pub use escrow_settle::EscrowSettleProofInputs;
pub use proof::OrderProof;
pub use zolana_client::ProofInputUtxo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitId {
    EscrowOpen,
    EscrowSettle,
}

impl zolana_gnark_ffi_prover::Circuit for CircuitId {
    const ALL: &'static [Self] = &[Self::EscrowOpen, Self::EscrowSettle];

    fn name(self) -> &'static str {
        match self {
            Self::EscrowOpen => "escrow_open",
            Self::EscrowSettle => "escrow_settle",
        }
    }
}

pub static PROVER: zolana_gnark_ffi_prover::Prover<CircuitId> =
    zolana_gnark_ffi_prover::prover!(concat!(env!("CARGO_MANIFEST_DIR"), "/../build/gnark"));
