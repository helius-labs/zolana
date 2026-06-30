//! Cucumber world for the zone-transfer functional tests. The plan records the
//! circuit shape, the owner rail, and which scenario builder to run; the `Then` step
//! builds the zone transfer, proves it on the prover server, and verifies the proof.

/// Selects which witness the `Then` step builds. Each maps to one builder in
/// `steps.rs`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// One real zero-value Solana-owned zone input + dummy padding, dummy outputs;
    /// verified against the eddsa-rail `transfer_zone_<shape>` vk (vanilla Groth16).
    #[default]
    Eddsa,
    /// One real P256-owned zone input + dummy padding, dummy outputs; verified
    /// against the P256-rail `transfer_p256_zone_<shape>` vk (Groth16 with a BSB22
    /// commitment).
    P256,
    /// Two real nonzero Solana-owned zone inputs consolidated into one real
    /// zone-owned recipient output (+ dummy padding) at shape 3x3 — exercises
    /// multiple real inputs, a real recipient, and value conservation on the eddsa
    /// rail.
    EddsaMultiReal,
    /// Same as [`Mode::EddsaMultiReal`] on the P256 rail: two real inputs sharing one
    /// P256 owner (the shared signature) into one real recipient output.
    P256MultiReal,
}

#[derive(Debug, Default)]
pub(crate) struct Plan {
    pub n_inputs: usize,
    pub n_outputs: usize,
    pub mode: Mode,
}

#[derive(Debug, Default, cucumber::World)]
pub struct ZoneTransferWorld {
    pub(crate) plan: Plan,
}
