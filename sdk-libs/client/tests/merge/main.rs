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

/// The wide shape, proved and verified against its committed key. 9 real inputs
/// is the first count that cannot fit the 8-input circuit, so it pads to 36 and
/// exercises the shape selection rather than the padding alone.
#[test]
#[serial_test::serial]
fn merge_proofs_cover_the_wide_shape() {
    for real_inputs in [9, 36] {
        MergeHarness {
            plan: MergePlan {
                real_inputs,
                eddsa: false,
            },
        }
        .prove_and_verify_merge();
    }
}
