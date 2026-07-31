//! Cucumber world for the zone-transfer functional tests. The plan records the
//! circuit shape and which scenario builder to run; the `Then` step builds the
//! zone transfer, proves it on the prover server, and verifies the proof.

/// Selects which witness the `Then` step builds. Each maps to one builder in
/// `steps.rs`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// One real zero-value Solana-owned zone input + dummy padding, dummy outputs;
    /// verified against the eddsa-rail `transfer_zone_<shape>` vk (vanilla Groth16).
    #[default]
    Eddsa,
    /// Two real nonzero Solana-owned zone inputs consolidated into one real
    /// zone-owned recipient output (+ dummy padding) at shape 3x3 — exercises
    /// multiple real inputs, a real recipient, and value conservation on the eddsa
    /// rail.
    EddsaMultiReal,
    /// One P256-owned zone input plus dummy padding, proved by the Go server and
    /// verified against the committed transfer_p256_zone VK.
    P256,
    /// One P256 and one ed25519 real input in the same custom-zone proof.
    P256Mixed,
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
