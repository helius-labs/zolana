mod harness;
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
            },
        }
        .prove_and_verify_merge();
    }
}
