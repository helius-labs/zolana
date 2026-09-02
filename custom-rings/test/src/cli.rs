//! The operator cli driven from a test, over a ring directory the harness writes.

use std::{path::PathBuf, process::Command};

use anyhow::{anyhow, Context, Result};
use solana_address::Address;
use solana_keypair::Keypair;
use zolana_test_utils::localnet::isolated_temp_path;

use crate::shared::{custom_ring_program_id, prover_url, TestEnv};

const RING_CLI: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/debug/zolana-ring"
);

/// The harness payer deploys, `config_authority` holds the config.
pub struct RingProject {
    pub config_authority: Keypair,
    dir: PathBuf,
    program_id: Address,
}

pub struct RingToml<'a> {
    pub env: &'a TestEnv,
    pub ring_rpc: &'a str,
    /// An empty `[policy]` table selects the policy tier.
    pub policy: bool,
}

impl RingProject {
    /// `keys/auditor.key.pub` holds `auditor`, the local key `init` pins.
    pub fn create(env: &TestEnv, auditor: &zolana_keypair::P256Pubkey) -> Result<Self> {
        let dir = PathBuf::from(isolated_temp_path("zolana-ring-cli"));
        let keys = dir.join("keys");
        std::fs::create_dir_all(&keys)?;
        let config_authority = Keypair::new();
        solana_keypair::write_keypair_file(&env.payer, dir.join("upgrade.json"))
            .map_err(|e| anyhow!("write upgrade keypair {e}"))?;
        solana_keypair::write_keypair_file(&config_authority, dir.join("config.json"))
            .map_err(|e| anyhow!("write config keypair {e}"))?;
        std::fs::write(
            keys.join("auditor.key.pub"),
            format!("{}\n", hex::encode(auditor.as_bytes())),
        )?;
        Ok(Self {
            config_authority,
            dir,
            program_id: custom_ring_program_id()?,
        })
    }

    pub fn write_config(&self, toml: RingToml<'_>) -> Result<()> {
        let policy = if toml.policy { "[policy]\n\n" } else { "" };
        std::fs::write(
            self.dir.join("ring.toml"),
            format!(
                "name = \"cli\"\ntarget = \"localnet\"\nprogram_id = \"{}\"\n\
                 authority_keypair = \"{}\"\nconfig_authority_keypair = \"{}\"\n\n{policy}\
                 [localnet]\nrpc = \"{}\"\nindexer = \"{}\"\nprover = \"{}\"\nring_rpc = \"{}\"\n\n\
                 [devnet]\nrpc = \"https://api.devnet.solana.com\"\nindexer = \"http://indexer.invalid\"\n\
                 prover = \"http://prover.invalid\"\nring_rpc = \"http://ring.invalid\"\n",
                self.program_id,
                self.dir.join("upgrade.json").display(),
                self.dir.join("config.json").display(),
                toml.env.rpc_url,
                toml.env.indexer_url,
                prover_url(),
                toml.ring_rpc,
            ),
        )?;
        Ok(())
    }

    /// Stdout and stderr merged.
    pub fn run(&self, args: &[&str]) -> Result<String> {
        let output = Command::new(RING_CLI)
            .arg("--config")
            .arg(self.dir.join("ring.toml"))
            .args(args)
            .output()
            .with_context(|| format!("run zolana-ring {}", args.join(" ")))?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !output.status.success() {
            return Err(anyhow!("zolana-ring {} failed\n{text}", args.join(" ")));
        }
        Ok(text)
    }

    pub fn remove(self) -> Result<()> {
        std::fs::remove_dir_all(self.dir)?;
        Ok(())
    }
}
