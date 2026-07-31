//! Ring-authority proof case data.

/// Selects the witness builder for a proof case.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// One real zero-value Solana-owned ring input + dummy padding (shape sweep).
    #[default]
    ShapeSweep,
    /// Two real nonzero Solana-owned ring inputs consolidated into one real
    /// ring-owned output, plus dummy padding.
    MultiReal,
    /// One real P256-owned ring input + dummy padding (pubkey-agnostic rail).
    P256Input,
    /// One Solana-owned and one P256-owned real input + dummy padding.
    MixedOwners,
    /// Built through `PreparedRingAuthority` -> `RingAuthorityWitness` ->
    /// `RingAuthorityProver` (the transaction-crate input boundary).
    Boundary,
}

#[derive(Debug, Default)]
pub(crate) struct Plan {
    pub n_inputs: usize,
    pub n_outputs: usize,
    pub mode: Mode,
}

#[derive(Debug, Default)]
pub struct RingAuthorityHarness {
    pub(crate) plan: Plan,
}
