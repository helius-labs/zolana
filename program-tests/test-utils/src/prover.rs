//! Workspace prover startup shared by prover-backed test binaries.

use std::sync::OnceLock;

use crate::localnet::WorkspaceArtifacts;

/// Start the workspace prover once per process, or reuse an already-healthy
/// server so its lazily loaded proving keys stay warm across test binaries.
/// The `zolana` CLI is resolved from `ZOLANA_CLI_BIN` or the workspace debug
/// build, and the prover is pointed at the workspace key cache; missing keys
/// download pinned by the committed lockfile.
///
/// Panics on startup failure. The once-guard is only set on success, so a
/// later caller retries after a transient failure instead of inheriting it.
pub fn spawn_workspace_prover() {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.get().is_some() {
        return;
    }
    let artifacts = WorkspaceArtifacts::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| artifacts.path("target/debug/zolana"));
    zolana_client::spawn_prover_with_artifacts(cli, artifacts.prover_keys_dir())
        .expect("start or reuse the workspace prover");
    let _ = STARTED.set(());
}
