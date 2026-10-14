//! Prover request bodies pinned byte for byte. The Go prover decodes the same
//! files strictly in `prover/server/prover/custom_ring/rust_fixture_test.go`.
//! `UPDATE_PROVER_JSON=1` rewrites them.

use std::path::PathBuf;

use zolana_hasher::primitives::right_align;
use zolana_keypair::{P256Pubkey, ViewingKey};

/// The Go circuit tests' scalars: byte `i` is `seed ^ i`, byte 0 forced to 1.
pub(crate) const TX_SK: [u8; 32] = scalar(0x11);
pub(crate) const EPH_SK: [u8; 32] = scalar(0x22);
pub(crate) const AUDITOR_SK: [u8; 32] = scalar(0x33);

const fn scalar(seed: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let mut index = 0;
    while index < 32 {
        bytes[index] = seed ^ index as u8;
        index += 1;
    }
    bytes[0] = 1;
    bytes
}

pub(crate) fn key(secret: [u8; 32]) -> ViewingKey {
    ViewingKey::from_bytes(&secret).expect("canonical scalar")
}

pub(crate) fn auditor() -> P256Pubkey {
    key(AUDITOR_SK).pubkey()
}

/// A field element below the BN254 modulus that differs per `seed`.
pub(crate) fn field(seed: u64) -> [u8; 32] {
    let mut value = right_align(&seed.to_be_bytes());
    value[1] = seed as u8;
    value
}

pub(crate) fn assert_golden(name: &str, body: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/prover-json")
        .join(format!("{name}.json"));
    if std::env::var_os("UPDATE_PROVER_JSON").is_some() {
        std::fs::create_dir_all(path.parent().expect("fixture dir")).expect("fixture dir");
        std::fs::write(&path, body).expect("write fixture");
        return;
    }
    let pinned = std::fs::read_to_string(&path).expect("pinned fixture");
    assert!(
        pinned == body,
        "{name} request drifted from {}",
        path.display()
    );
}
