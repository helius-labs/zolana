mod harness;
mod proving;

#[path = "../prover_bootstrap.rs"]
mod prover_bootstrap;
#[path = "../test_indexer.rs"]
mod test_indexer;

use harness::{Mode, Plan, ZoneTransferHarness};

#[test]
#[serial_test::serial]
fn eddsa_zone_transfer_proofs_cover_all_shapes() {
    run_shape_matrix(Mode::Eddsa);
}

fn run_shape_matrix(mode: Mode) {
    let shapes = [
        (1, 1),
        (1, 2),
        (2, 2),
        (2, 3),
        (3, 3),
        (4, 3),
        (4, 4),
        (5, 3),
        (5, 4),
        (1, 8),
    ];
    for (n_inputs, n_outputs) in shapes {
        ZoneTransferHarness {
            plan: Plan {
                n_inputs,
                n_outputs,
                mode,
            },
        }
        .prove_and_verify();
    }
}

#[test]
#[serial_test::serial]
fn zone_transfer_proofs_cover_real_multi_input_consolidation() {
    for mode in [Mode::EddsaMultiReal] {
        ZoneTransferHarness {
            plan: Plan {
                n_inputs: 3,
                n_outputs: 3,
                mode,
            },
        }
        .prove_and_verify();
    }
}
