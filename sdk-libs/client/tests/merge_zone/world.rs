//! Cucumber world for the merge-zone functional tests. The plan only records how
//! many real inputs to consolidate and the owner rail; the `Then` step builds the
//! merge-zone, proves it on the prover server, and verifies the proof.

#[derive(Debug, Default)]
pub(crate) struct MergeZonePlan {
    pub real_inputs: usize,
    /// True selects the Solana (ed25519) owner rail; false the P256 rail.
    pub eddsa: bool,
}

#[derive(Debug, Default, cucumber::World)]
pub struct MergeZoneWorld {
    pub(crate) plan: MergeZonePlan,
}
