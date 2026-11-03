//! Ring-transfer proof case data.

/// Selects the witness builder for a proof case.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// One real zero-value Solana-owned ring input + dummy padding, dummy outputs;
    /// verified against the eddsa-rail `transfer_ring_<shape>` vk (vanilla Groth16).
    #[default]
    Eddsa,
    /// Two real nonzero Solana-owned ring inputs consolidated into one real
    /// ring-owned recipient output (+ dummy padding) at shape 3x3 — exercises
    /// multiple real inputs, a real recipient, and value conservation on the eddsa
    /// rail.
    EddsaMultiReal,
    /// A hidden ring spend and a hidden address slot on the anonymous rail.
    AnonymousWithAddress,
}

#[derive(Debug, Default)]
pub(crate) struct Plan {
    pub n_inputs: usize,
    pub n_outputs: usize,
    pub mode: Mode,
}

#[derive(Debug, Default)]
pub struct RingTransferHarness {
    pub(crate) plan: Plan,
}
