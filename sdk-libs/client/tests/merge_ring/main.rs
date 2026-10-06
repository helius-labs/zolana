mod harness;
#[path = "../common/input.rs"]
mod input_fixture;
mod proving;

#[path = "../prover_bootstrap.rs"]
mod prover_bootstrap;
#[path = "../test_indexer.rs"]
mod test_indexer;

use harness::{MergeRingHarness, MergeRingPlan};
use zolana_transaction::instructions::merge::{MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT};

#[test]
#[serial_test::serial]
fn p256_merge_ring_proofs_cover_padding() {
    run_owner_rail(false);
}

#[test]
#[serial_test::serial]
fn eddsa_merge_ring_proofs_cover_padding() {
    run_owner_rail(true);
}

fn run_owner_rail(eddsa: bool) {
    for real_inputs in [1, 12, 24] {
        MergeRingHarness {
            plan: MergeRingPlan { real_inputs, eddsa },
        }
        .prove_and_verify_merge_ring();
    }
}

#[test]
#[serial_test::serial]
fn merge_ring_proofs_cover_the_wide_shape() {
    for eddsa in [false, true] {
        for real_inputs in [MERGE_DEFAULT_INPUT_COUNT + 1, MAX_MERGE_INPUTS] {
            MergeRingHarness {
                plan: MergeRingPlan { real_inputs, eddsa },
            }
            .prove_and_verify_merge_ring();
        }
    }
}
