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
    /// One real independent Ed25519 ring input + dummy padding (pubkey-agnostic rail).
    IndependentInput,
    /// One Solana-owned and one independent Ed25519 real input + dummy padding.
    MixedOwners,
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
