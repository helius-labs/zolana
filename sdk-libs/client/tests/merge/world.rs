//! Cucumber world for the merge functional tests. The plan only records how many
//! real inputs to consolidate; the `Then` step builds the merge, proves it on the
//! prover server, and verifies the proof.

#[derive(Debug, Default)]
pub(crate) struct MergePlan {
    pub real_inputs: usize,
}

#[derive(Debug, Default, cucumber::World)]
pub struct MergeWorld {
    pub(crate) plan: MergePlan,
}
