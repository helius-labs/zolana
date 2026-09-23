//! A surfpool validator and Photon started through the `zolana` CLI, for tests
//! that run programs end to end against a real indexer.
//!
//! [`FixtureLocalnet`] is the usual entry point: it boots from
//! [`write_test_fixture`](crate::fixture::write_test_fixture), starts the
//! prover and hands back a [`ZolanaClient`]. [`LocalnetValidator`] is the lower
//! level: it boots exactly the programs and account directory it is given.
//!
//! Each localnet binds its own [`LocalnetPorts`]. Tests that take distinct
//! [`LocalnetPorts::for_test`] numbers run in parallel; they share one prover.

use std::{
    collections::BTreeSet,
    env,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use solana_address::Address;
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

/// The ports one localnet binds. The validator's WebSocket takes the port
/// above `rpc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalnetPorts {
    pub rpc: u16,
    pub photon: u16,
}

impl LocalnetPorts {
    /// How far apart numbered tests' ports are. Checkout offsets
    /// (`ZOLANA_PORT_OFFSET`) are multiples of 100 below 1000, so every test in
    /// every checkout gets its own ports.
    const TEST_STRIDE: u16 = 1000;

    /// The default ports, RPC 8899 and Photon 8784, each shifted by `offset`.
    pub const fn offset(offset: u16) -> Self {
        Self {
            rpc: 8899 + offset,
            photon: 8784 + offset,
        }
    }

    /// The ports of test number `test` in this checkout: the defaults shifted
    /// by `ZOLANA_PORT_OFFSET` plus `1000 * test`. Tests with distinct numbers
    /// run in parallel.
    pub fn for_test(test: u16) -> Result<Self, ProgramTestError> {
        let checkout = match env::var("ZOLANA_PORT_OFFSET") {
            Ok(offset) if !offset.trim().is_empty() => offset.trim().parse().map_err(|_| {
                ProgramTestError::Localnet(format!(
                    "ZOLANA_PORT_OFFSET={offset} is not a port offset"
                ))
            })?,
            _ => 0,
        };
        test.checked_mul(Self::TEST_STRIDE)
            .and_then(|shift| shift.checked_add(checkout))
            .filter(|offset| offset.checked_add(8900).is_some())
            .map(Self::offset)
            .ok_or_else(|| ProgramTestError::Localnet(format!("test number {test} is too large")))
    }

    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc)
    }

    pub fn photon_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.photon)
    }
}

/// A validator and Photon started by `zolana test-env`, without the prover.
pub struct LocalnetValidator {
    pub cli_bin: PathBuf,
    /// The CLI runs from here.
    pub working_dir: PathBuf,
    pub ports: LocalnetPorts,
    /// Account JSON files loaded at boot.
    pub account_dir: PathBuf,
    /// Where the services write their logs.
    pub log_dir: PathBuf,
    pub programs: Vec<(Address, PathBuf)>,
    /// Surfpool's slot time, 400ms when unset. A transaction confirms in the
    /// slot after it lands, so on a localnet this is most of its latency.
    pub slot_time: Option<Duration>,
}

pub struct UpgradeableProgram {
    pub address: Address,
    pub path: PathBuf,
    pub authority: Address,
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

        let mut command = self.test_env();
        command
            .args(["--local", "--skip-prover"])
            .arg("--account-dir")
            .arg(&self.account_dir)
            .arg("--log-dir")
            .arg(&self.log_dir);
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
        // A start that fails part way, say Photon never comes up, leaves the
        // validator running; stop it so a failed start leaves nothing behind.
        run(command, "start").inspect_err(|_| self.stop_after_failure())
    }

    fn stop_after_failure(&self) {
        if let Err(error) = self.stop() {
            eprintln!("failed to stop the localnet after a failed start: {error}");
        }
    }

    /// Stop the validator and Photon on this localnet's ports.
    pub fn stop(&self) -> Result<(), ProgramTestError> {
        let mut command = self.test_env();
        command.args(["--stop", "--skip-prover"]);
        run(command, "stop")
    }

    fn test_env(&self) -> Command {
        let mut command = Command::new(&self.cli_bin);
        command
            .current_dir(&self.working_dir)
            .arg("test-env")
            .arg("--rpc-port")
            .arg(self.ports.rpc.to_string())
            .arg("--photon-port")
            .arg(self.ports.photon.to_string());
        command
    }
}

fn run(mut command: Command, action: &str) -> Result<(), ProgramTestError> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(ProgramTestError::Localnet(format!(
            "zolana test-env {action} exited with {status}"
        )))
    }
}

/// The binaries, keys and scratch directory a [`FixtureLocalnet`] uses.
#[derive(Clone, Debug)]
pub struct LocalnetPaths {
    pub cli_bin: PathBuf,
    pub shielded_pool_program: PathBuf,
    /// The CLI resolves surfpool and Photon relative to this.
    pub working_dir: PathBuf,
    pub proving_keys_dir: PathBuf,
    /// Parent of each localnet's `<label>-<rpc port>` directory.
    pub scratch_dir: PathBuf,
}

impl LocalnetPaths {
    /// This workspace's builds, with scratch under `target/localnet`.
    /// `ZOLANA_CLI_BIN` and `SHIELDED_POOL_PROGRAM_PATH` override the CLI and
    /// the pool program.
    pub fn workspace() -> Self {
        Self {
            cli_bin: env::var("ZOLANA_CLI_BIN")
                .map(PathBuf::from)
                .unwrap_or_else(|_| paths::workspace_path("target/debug/zolana")),
            shielded_pool_program: paths::default_program_path(),
            working_dir: paths::workspace_path(""),
            proving_keys_dir: paths::workspace_path("prover/server/proving-keys"),
            scratch_dir: paths::workspace_path("target/localnet"),
        }
    }
}

/// A localnet booted from [`write_test_fixture`] with the prover running, in
/// place of the setup transactions a test would otherwise send. Dropping it
/// stops its validator and Photon.
pub struct FixtureLocalnet {
    pub client: ZolanaClient<SolanaRpc>,
    /// The default tree, `pda::tree(0)`.
    pub tree: Address,
    /// Raw id of `tree`, read from its account.
    pub tree_id: u16,
    validator: LocalnetValidator,
}

impl FixtureLocalnet {
    /// Boot on `ports` with the shielded pool and `programs` loaded. The
    /// account and log directories live in `<scratch_dir>/<label>-<rpc port>`,
    /// cleared at every start: disk stays bounded at one directory per port,
    /// and the last run's logs stay behind for debugging.
    pub fn start(
        label: &str,
        ports: LocalnetPorts,
        programs: Vec<(Address, PathBuf)>,
        paths: &LocalnetPaths,
    ) -> Result<Self, ProgramTestError> {
        let spp = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
        let scratch = paths.scratch_dir.join(format!("{label}-{}", ports.rpc));
        if scratch.exists() {
            std::fs::remove_dir_all(&scratch)?;
        }
        let account_dir = scratch.join("accounts");
        write_test_fixture(&paths.shielded_pool_program, &account_dir)?;

        let mut loaded = vec![(spp, paths.shielded_pool_program.clone())];
        loaded.extend(programs);
        let program_ids: Vec<Address> = loaded.iter().map(|(address, _)| *address).collect();
        let validator = LocalnetValidator {
            cli_bin: paths.cli_bin.clone(),
            working_dir: paths.working_dir.clone(),
            ports,
            account_dir,
            log_dir: scratch.join("logs"),
            programs: loaded,
            slot_time: Some(FIXTURE_SLOT_TIME),
        };
        validator.start()?;
        match connect(paths, ports, &program_ids) {
            Ok((client, tree_id)) => Ok(Self {
                client,
                tree: pda::tree(0),
                tree_id,
                validator,
            }),
            Err(error) => {
                validator.stop_after_failure();
                Err(error)
            }
        }
    }
}

/// Start the prover, check that every program loaded and read the default
/// tree's id.
fn connect(
    paths: &LocalnetPaths,
    ports: LocalnetPorts,
    program_ids: &[Address],
) -> Result<(ZolanaClient<SolanaRpc>, u16), ProgramTestError> {
    zolana_client::spawn_prover_with_artifacts(&paths.cli_bin, &paths.proving_keys_dir)?;
    let rpc = SolanaRpc::new(ports.rpc_url()).with_poll_interval(FIXTURE_POLL_INTERVAL);
    for program_id in program_ids {
        rpc.assert_executable(program_id)?;
    }
    let tree = pda::tree(0);
    let tree_id = rpc
        .get_account(tree)?
        .and_then(|account| read_tree_id(&account.data))
        .ok_or_else(|| ProgramTestError::Localnet(format!("default tree {tree} is missing")))?;
    let client = ZolanaClient::new(
        rpc,
        ZolanaIndexer::new(ports.photon_url()),
        ProverClient::default(),
        AsyncZolanaIndexer::new(ports.photon_url()),
        AsyncProverClient::default(),
    );
    Ok((client, tree_id))
}

impl Drop for FixtureLocalnet {
    fn drop(&mut self) {
        if let Err(error) = self.validator.stop() {
            eprintln!("failed to stop the localnet: {error}");
        }
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
