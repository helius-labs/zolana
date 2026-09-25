//! Workspace prover startup shared by prover-backed test binaries.

use std::sync::OnceLock;

use zolana_client::{IndexerRequirement, ProverLaunch};

use crate::localnet::{localnet_indexer_url, WorkspaceArtifacts};

/// Start the workspace prover once per process, or reuse an already-healthy
/// server so its lazily loaded proving keys stay warm across test binaries.
/// The `zolana` CLI is resolved from `ZOLANA_CLI_BIN` or the workspace debug
/// build, and the prover is pointed at the workspace key cache; missing keys
/// download pinned by the committed lockfile. A started prover resolves
/// indexed proofs against this checkout's Photon.
///
/// Panics on startup failure. The once-guard is only set on success, so a
/// later caller retries after a transient failure instead of inheriting it.
pub fn spawn_workspace_prover(indexer: IndexerRequirement) {
    static OPTIONAL: OnceLock<()> = OnceLock::new();
    static REQUIRED: OnceLock<()> = OnceLock::new();
    let started = match indexer {
        IndexerRequirement::Optional => &OPTIONAL,
        IndexerRequirement::Required => &REQUIRED,
    };
    if started.get().is_some() {
        return;
    }
    let artifacts = WorkspaceArtifacts::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| artifacts.path("target/debug/zolana"));
    let photon = localnet_indexer_url();
    ProverLaunch::new_with_cli(cli)
        .and_then(|launch| launch.with_keys_dir(artifacts.prover_keys_dir()))
        .and_then(|launch| launch.with_indexer(photon, indexer).spawn())
        .expect("start or reuse the workspace prover");
    let _ = started.set(());
}
