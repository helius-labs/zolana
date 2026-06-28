//! Cucumber world for the zone-authority functional tests. The plan records the
//! circuit shape and which scenario builder to run; the `Then` step builds the
//! zone-authority transfer, proves it on the prover server, and verifies the proof.

/// Selects which witness the `Then` step builds. Each maps to one builder in
/// `steps.rs`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// One real zero-value Solana-owned zone input + dummy padding (shape sweep).
    #[default]
    ShapeSweep,
    /// Two real nonzero Solana-owned zone inputs consolidated into one real
    /// zone-owned output, plus dummy padding.
    MultiReal,
    /// One real P256-owned zone input + dummy padding (pubkey-agnostic rail).
    P256Input,
    /// One Solana-owned and one P256-owned real input + dummy padding.
    MixedOwners,
    /// Built through `PreparedZoneAuthority` -> `ZoneAuthorityWitness` ->
    /// `ZoneAuthorityProver` (the transaction-crate input boundary).
    Boundary,
}

#[derive(Debug, Default)]
pub(crate) struct Plan {
    pub n_inputs: usize,
    pub n_outputs: usize,
    pub mode: Mode,
}

#[derive(Debug, Default, cucumber::World)]
pub struct ZoneAuthorityWorld {
    pub(crate) plan: Plan,
}
