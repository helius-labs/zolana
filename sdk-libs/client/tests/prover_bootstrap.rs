//! Shared prover startup for integration-test binaries.

use std::sync::OnceLock;

pub(crate) fn start_prover() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        zolana_client::spawn_prover_with_artifacts(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/zolana"),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../prover/server/proving-keys"
            ),
        )
        .expect("start or reuse prover with workspace key cache");
    });
}
