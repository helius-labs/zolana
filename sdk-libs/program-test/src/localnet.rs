//! A surfpool validator and Photon started through the `zolana` CLI, for tests
//! that run programs end to end against a real indexer.
//!
//! [`FixtureLocalnet`] is the usual entry point: it boots from
//! [`write_test_fixture`](crate::fixture::write_test_fixture), starts the
//! prover and hands back a [`ZolanaClient`]. [`LocalnetValidator`] is the lower
//! level: it boots exactly the programs and account directory it is given.

use std::{
    collections::BTreeSet,
    env,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use solana_pubkey::Pubkey;
use zolana_client::{
    AsyncProverClient, AsyncZolanaIndexer, ProverClient, Rpc, SolanaRpc, ZolanaClient,
    ZolanaIndexer,
};
use zolana_interface::{pda, state::tree::read_tree_id, SHIELDED_POOL_PROGRAM_ID};

use crate::{fixture::write_test_fixture, paths, ProgramTestError};

/// Short slots so each transaction confirms quickly, and a poll interval well
/// under one slot so the client notices.
const FIXTURE_SLOT_TIME: Duration = Duration::from_millis(50);
const FIXTURE_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// A validator and Photon started by `zolana test-env`, without the prover.
pub struct LocalnetValidator {
    pub cli_bin: PathBuf,
    /// The CLI runs from here and writes its service logs under it.
    pub working_dir: PathBuf,
    pub rpc_port: u16,
    pub photon_port: u16,
    /// Account JSON files loaded at boot.
    pub account_dir: PathBuf,
    pub programs: Vec<(Pubkey, PathBuf)>,
    /// Surfpool's slot time, 400ms when unset. A transaction confirms in the
    /// slot after it lands, so on a localnet this is most of its latency.
    pub slot_time: Option<Duration>,
}

pub struct UpgradeableProgram {
    pub address: Pubkey,
    pub path: PathBuf,
    pub authority: Pubkey,
}

impl LocalnetValidator {
    pub fn start(&self) -> Result<(), ProgramTestError> {
        self.start_with_upgradeable_programs(&[])
    }

    pub fn start_with_upgradeable_programs(
        &self,
        upgradeable: &[UpgradeableProgram],
    ) -> Result<(), ProgramTestError> {
        require_file("zolana CLI", &self.cli_bin)?;
        if !self.working_dir.is_dir() {
            return Err(ProgramTestError::Localnet(format!(
                "working directory {} is missing",
                self.working_dir.display()
            )));
        }
        let mut program_ids = BTreeSet::new();
        let loaded = self
            .programs
            .iter()
            .map(|(address, path)| (address, path))
            .chain(
                upgradeable
                    .iter()
                    .map(|program| (&program.address, &program.path)),
            );
        for (address, path) in loaded {
            if !program_ids.insert(*address) {
                return Err(ProgramTestError::Localnet(format!(
                    "program {address} is loaded twice"
                )));
            }
            require_file(&format!("program {address}"), path)?;
        }
        if program_ids.is_empty() {
            return Err(ProgramTestError::Localnet("no programs to load".into()));
        }

        let mut command = Command::new(&self.cli_bin);
        command
            .current_dir(&self.working_dir)
            .args(["test-env", "--local", "--skip-prover"])
            .arg("--rpc-port")
            .arg(self.rpc_port.to_string())
            .arg("--photon-port")
            .arg(self.photon_port.to_string())
            .arg("--account-dir")
            .arg(&self.account_dir);
        for (address, path) in &self.programs {
            command
                .arg("--sbf-program")
                .arg(address.to_string())
                .arg(path);
        }
        for program in upgradeable {
            command
                .arg("--upgradeable-program")
                .arg(program.address.to_string())
                .arg(&program.path)
                .arg(program.authority.to_string());
        }
        if let Some(slot_time) = self.slot_time {
            command
                .arg("--slot-time")
                .arg(slot_time.as_millis().to_string());
        }
        let status = command.status()?;
        if !status.success() {
            return Err(ProgramTestError::Localnet(format!(
                "zolana test-env exited with {status}"
            )));
        }
        Ok(())
    }
}

/// A localnet booted from [`write_test_fixture`] with the prover running, in
/// place of the setup transactions a test would otherwise send.
pub struct FixtureLocalnet {
    pub client: ZolanaClient<SolanaRpc>,
    /// The default tree, `pda::tree(0)`.
    pub tree: Pubkey,
    /// Raw id of `tree`, read from its account.
    pub tree_id: u16,
}

impl FixtureLocalnet {
    /// Boot with the shielded pool and `programs` loaded. `label` names the
    /// per-process account directory.
    ///
    /// Artifacts default to this workspace's builds; `ZOLANA_CLI_BIN` and
    /// `SHIELDED_POOL_PROGRAM_PATH` override the CLI and the pool program.
    /// `ZOLANA_LOCALNET_RPC_PORT` / `ZOLANA_LOCALNET_PHOTON_PORT` and
    /// `ZOLANA_LOCALNET_URL` / `ZOLANA_INDEXER_URL` override the defaults
    /// 8899 and 8784.
    pub fn start(label: &str, programs: Vec<(Pubkey, PathBuf)>) -> Result<Self, ProgramTestError> {
        let spp = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let spp_so = paths::default_program_path();
        let account_dir = env::temp_dir().join(format!("{label}-accounts-{}", std::process::id()));
        write_test_fixture(&spp_so, &account_dir)?;

        let cli_bin = env::var("ZOLANA_CLI_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| paths::workspace_path("target/debug/zolana"));
        let program_ids: Vec<Pubkey> = programs.iter().map(|(address, _)| *address).collect();
        let mut loaded = vec![(spp, spp_so)];
        loaded.extend(programs);
        LocalnetValidator {
            cli_bin: cli_bin.clone(),
            working_dir: paths::workspace_path(""),
            rpc_port: env_port("ZOLANA_LOCALNET_RPC_PORT", 8899)?,
            photon_port: env_port("ZOLANA_LOCALNET_PHOTON_PORT", 8784)?,
            account_dir,
            programs: loaded,
            slot_time: Some(FIXTURE_SLOT_TIME),
        }
        .start()?;
        zolana_client::spawn_prover_with_artifacts(
            &cli_bin,
            paths::workspace_path("prover/server/proving-keys"),
        )?;

        let rpc = SolanaRpc::new(
            env::var("ZOLANA_LOCALNET_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".into()),
        )
        .with_poll_interval(FIXTURE_POLL_INTERVAL);
        let indexer_url =
            env::var("ZOLANA_INDEXER_URL").unwrap_or_else(|_| "http://127.0.0.1:8784".into());
        rpc.assert_executable(&spp)?;
        for program_id in &program_ids {
            rpc.assert_executable(program_id)?;
        }
        let tree = pda::tree(0);
        let tree_id = rpc
            .get_account(tree)?
            .and_then(|account| read_tree_id(&account.data))
            .ok_or_else(|| ProgramTestError::Localnet(format!("default tree {tree} is missing")))?;
        Ok(Self {
            client: ZolanaClient::new(
                rpc,
                ZolanaIndexer::new(indexer_url.clone()),
                ProverClient::default(),
                AsyncZolanaIndexer::new(indexer_url),
                AsyncProverClient::default(),
            ),
            tree,
            tree_id,
        })
    }
}

fn require_file(label: &str, path: &Path) -> Result<(), ProgramTestError> {
    if path.is_file() {
        Ok(())
    } else {
        Err(ProgramTestError::Localnet(format!(
            "{label} is missing at {}; build it first",
            path.display()
        )))
    }
}

fn env_port(name: &str, default: u16) -> Result<u16, ProgramTestError> {
    match env::var(name) {
        Ok(port) => port
            .parse()
            .map_err(|_| ProgramTestError::Localnet(format!("{name}={port} is not a port"))),
        Err(_) => Ok(default),
    }
}
