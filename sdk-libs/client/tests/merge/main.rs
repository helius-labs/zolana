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
fn p256_merge_proofs_cover_the_narrow_shape_padding_boundaries() {
    for real_inputs in [1, 2, 12, 23, 24] {
        MergeHarness {
            plan: MergePlan {
                real_inputs,
                eddsa: false,
            },
        }
        .prove_and_verify_merge();
    }
}

#[test]
#[serial_test::serial]
fn eddsa_merge_proofs_cover_minimum_middle_and_full_shapes() {
    for real_inputs in [1, 12, 24] {
        MergeHarness {
            plan: MergePlan {
                real_inputs,
                eddsa: true,
            },
        }
        .prove_and_verify_merge();
    }
}

#[test]
#[serial_test::serial]
fn merge_proofs_cover_the_wide_shape() {
    for eddsa in [false, true] {
        for real_inputs in [MERGE_DEFAULT_INPUT_COUNT + 1, MAX_MERGE_INPUTS] {
            MergeHarness {
                plan: MergePlan { real_inputs, eddsa },
            }
            .prove_and_verify_merge();
        }
    }
}
