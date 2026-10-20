mod harness;
#[path = "../common/input.rs"]
mod input_fixture;
mod proving;

#[path = "../prover_bootstrap.rs"]
mod prover_bootstrap;
#[path = "../test_indexer.rs"]
mod test_indexer;

use harness::{MergeHarness, MergePlan};
use zolana_transaction::instructions::merge::{MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT};

#[test]
#[serial_test::serial]
fn eddsa_merge_proofs_cover_padding_and_wide_shapes() {
    for real_inputs in [
        1,
        2,
        8,
        9,
        23,
        24,
        MERGE_DEFAULT_INPUT_COUNT + 1,
        MAX_MERGE_INPUTS,
    ] {
        MergeHarness {
            plan: MergePlan { real_inputs },
        }
        .prove_and_verify_merge();
    }
}
