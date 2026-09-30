//! Shared prover startup for integration-test binaries.

use std::sync::OnceLock;

use zolana_client::{ClientError, ProverLaunch};

pub(crate) fn start_prover() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| launch().expect("start or reuse prover with workspace key cache"));
}

fn launch() -> Result<(), ClientError> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    ProverLaunch::new_with_cli(format!("{root}/target/debug/zolana"))?
        .with_keys_dir(format!("{root}/prover/server/proving-keys"))?
        .spawn()
}
