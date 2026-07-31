//! Merge-ring proof case data.

#[derive(Debug, Default)]
pub(crate) struct MergeRingPlan {
    pub real_inputs: usize,
    /// True selects the Solana (ed25519) owner rail; false the P256 rail.
    pub eddsa: bool,
}

#[derive(Debug, Default)]
pub struct MergeRingHarness {
    pub(crate) plan: MergeRingPlan,
}
