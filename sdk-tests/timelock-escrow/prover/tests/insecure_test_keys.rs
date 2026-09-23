use std::{fs, path::Path};

use timelock_escrow_prover::{CircuitId, PROVER};

#[derive(Debug, PartialEq, Eq)]
struct Keys {
    proving_key: Vec<u8>,
    verifying_key: Vec<u8>,
}

fn read_keys(dir: &Path) -> Keys {
    Keys {
        proving_key: fs::read(dir.join("pk.bin")).expect("read pk.bin"),
        verifying_key: fs::read(dir.join("vk.bin")).expect("read vk.bin"),
    }
}

#[test]
fn insecure_test_keys_are_reproducible_and_leave_system_randomness_in_place() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("insecure_test_keys");
    let first = root.join("first");
    let second = root.join("second");
    let system = root.join("system");

    PROVER
        .setup_insecure_test_keys(CircuitId::Withdraw, &first)
        .expect("first insecure setup");
    PROVER
        .setup_insecure_test_keys(CircuitId::Withdraw, &second)
        .expect("second insecure setup");
    PROVER
        .setup(CircuitId::Withdraw, &system)
        .expect("system randomness setup");

    let insecure = read_keys(&first);
    assert_eq!(insecure, read_keys(&second));
    assert_ne!(insecure.verifying_key, read_keys(&system).verifying_key);
}
