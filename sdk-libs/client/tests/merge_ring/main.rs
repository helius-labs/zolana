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

/// The wide shape on the policy-ring rail: 9 real inputs pad to 36, so the
/// proof must verify against merge_ring_36_1 rather than the 8-input key.
#[test]
#[serial_test::serial]
fn merge_ring_proofs_cover_the_wide_shape() {
    for real_inputs in [9, 36] {
        MergeRingHarness {
            plan: MergeRingPlan {
                real_inputs,
                eddsa: false,
            },
        }
        .prove_and_verify_merge_ring();
    }
}
