pub mod escrow_cancel;
pub mod escrow_open;
pub mod pool_rebalance;
pub mod pool_settle;
pub mod pool_withdraw;
pub mod proof;

pub use escrow_cancel::EscrowCancelProofInputs;
pub use escrow_open::EscrowOpenProofInputs;
pub use pool_rebalance::{PoolRebalanceProofInputs, REBALANCE_INPUT_SLOTS, REBALANCE_OUTPUT_SLOTS};
pub use pool_settle::PoolSettleProofInputs;
pub use pool_withdraw::PoolWithdrawProofInputs;
pub use proof::OrderProof;
pub use zolana_client::ProofInputUtxo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitId {
    EscrowOpen,
    PoolSettle,
    EscrowCancel,
    PoolWithdraw,
    PoolRebalance,
}

impl zolana_gnark_ffi_prover::Circuit for CircuitId {
    const ALL: &'static [Self] = &[
        Self::EscrowOpen,
        Self::PoolSettle,
        Self::EscrowCancel,
        Self::PoolWithdraw,
        Self::PoolRebalance,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::EscrowOpen => "escrow_open",
            Self::PoolSettle => "pool_settle",
            Self::EscrowCancel => "escrow_cancel",
            Self::PoolWithdraw => "pool_withdraw",
            Self::PoolRebalance => "pool_rebalance",
        }
    }
}

pub static PROVER: zolana_gnark_ffi_prover::Prover<CircuitId> =
    zolana_gnark_ffi_prover::prover!(concat!(env!("CARGO_MANIFEST_DIR"), "/../build/gnark"));
