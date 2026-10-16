//! Merge proof case data.

#[derive(Debug, Default)]
pub(crate) struct MergePlan {
    pub real_inputs: usize,
}

#[derive(Debug, Default)]
pub struct MergeHarness {
    pub(crate) plan: MergePlan,
}
