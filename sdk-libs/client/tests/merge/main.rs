mod harness;
#[path = "../common/input.rs"]
mod input_fixture;
mod proving;

#[path = "../prover_bootstrap.rs"]
mod prover_bootstrap;
#[path = "../test_indexer.rs"]
mod test_indexer;

use harness::{MergeHarness, MergePlan};

#[test]
#[serial_test::serial]
fn p256_merge_proofs_cover_every_real_input_count() {
    for real_inputs in 1..=8 {
        MergeHarness {
            plan: MergePlan {
                real_inputs,
                eddsa: false,
                compact: false,
            },
        }
        .prove_and_verify_merge();
    }
}

#[test]
#[serial_test::serial]
fn eddsa_merge_proofs_cover_minimum_middle_and_full_shapes() {
    for real_inputs in [1, 4, 8] {
        MergeHarness {
            plan: MergePlan {
                real_inputs,
                eddsa: true,
                compact: false,
            },
        }
        .prove_and_verify_merge();
    }
}

#[test]
#[serial_test::serial]
fn merge_proofs_cover_the_wide_shape() {
    for eddsa in [false, true] {
        for real_inputs in [9, 36] {
            MergeHarness {
                plan: MergePlan {
                    real_inputs,
                    eddsa,
                    compact: false,
                },
            }
            .prove_and_verify_merge();
        }
    }
}

#[test]
#[serial_test::serial]
fn compact_merge_proofs_cover_both_shapes() {
    for real_inputs in [3, 9] {
        MergeHarness {
            plan: MergePlan {
                real_inputs,
                eddsa: true,
                compact: true,
            },
        }
        .prove_and_verify_merge();
    }
}
