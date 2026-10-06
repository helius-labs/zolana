//! Merge proof case data.

#[derive(Debug, Default)]
pub(crate) struct MergePlan {
    pub real_inputs: usize,
    /// True selects the Solana (ed25519) owner rail; false the P256 rail.
    pub eddsa: bool,
}

#[derive(Debug, Default)]
pub struct MergeHarness {
    pub(crate) plan: MergePlan,
}
