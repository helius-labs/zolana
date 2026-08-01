mod harness;
mod proving;

#[path = "../prover_bootstrap.rs"]
mod prover_bootstrap;
#[path = "../test_indexer.rs"]
mod test_indexer;

use harness::{Mode, Plan, RingAuthorityHarness};

#[test]
#[serial_test::serial]
fn ring_authority_proofs_cover_shape_sweep() {
    for n in 1..=4 {
        RingAuthorityHarness {
            plan: Plan {
                n_inputs: n,
                n_outputs: n,
                mode: Mode::ShapeSweep,
            },
        }
        .prove_and_verify();
    }
}

#[test]
#[serial_test::serial]
fn ring_authority_proofs_cover_owner_modes_and_prepared_boundary() {
    for (n_inputs, n_outputs, mode) in [
        (3, 3, Mode::MultiReal),
        (1, 1, Mode::P256Input),
        (2, 2, Mode::MixedOwners),
        (2, 2, Mode::Boundary),
    ] {
        RingAuthorityHarness {
            plan: Plan {
                n_inputs,
                n_outputs,
                mode,
            },
        }
        .prove_and_verify();
    }
}
