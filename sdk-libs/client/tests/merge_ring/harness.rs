//! Merge-ring proof case data.

#[derive(Debug, Default)]
pub(crate) struct MergeRingPlan {
    pub real_inputs: usize,
}

#[derive(Debug, Default)]
pub struct MergeRingHarness {
    pub(crate) plan: MergeRingPlan,
}
