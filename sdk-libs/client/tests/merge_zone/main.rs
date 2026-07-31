mod harness;
mod proving;

#[path = "../prover_bootstrap.rs"]
mod prover_bootstrap;
#[path = "../test_indexer.rs"]
mod test_indexer;

use harness::{MergeRingHarness, MergeRingPlan};

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
    for real_inputs in [1, 4, 8] {
        MergeRingHarness {
            plan: MergeRingPlan { real_inputs, eddsa },
        }
        .prove_and_verify_merge_ring();
    }
}
