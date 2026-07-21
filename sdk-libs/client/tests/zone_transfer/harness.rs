//! Zone-transfer proof case data.

/// Selects the witness builder for a proof case.
// TODO(pr164-port): PR164 removed the P256 rail (`ZoneTransferP256Prover` and the
// `transfer_p256_zone_*` verifying keys are gone), so the `P256` / `P256MultiReal`
// modes from the original suite were dropped.
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

#[derive(Debug, Default)]
pub struct ZoneTransferHarness {
    pub(crate) plan: Plan,
}
