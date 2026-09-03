//! The operator cli driven from a test, over a ring directory the harness writes.

use std::{
    path::PathBuf,
    process::{Command, Output},
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use custom_ring_cli::{ListName, SENDER_KEYPAIR_FILE};
use custom_ring_sdk::{CustomRing, ReadEntry};
use solana_address::Address;
use solana_keypair::Keypair;
use zolana_keypair::ShieldedKeypair;
use zolana_ring_policy::{EntryState, ListId, Member};
use zolana_test_utils::{
    localnet::isolated_temp_path, test_validator_asserts::wait_for_merkle_proof,
};

use crate::{
    policy::owner_member,
    shared::{custom_ring_program_id, prover_url, TestEnv},
};

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
    /// A `[policy]` block selects the policy tier.
    pub policy: Option<&'a str>,
}

const INDEXING_TIMEOUT: Duration = Duration::from_secs(90);

pub struct ListWrite<'a> {
    pub env: &'a TestEnv,
    pub entries_tree: Address,
    pub list_id: ListId,
    pub member: ListMember<'a>,
    pub state: EntryState,
}

pub enum ListMember<'a> {
    Owner(&'a ShieldedKeypair),
    Asset(Address),
}

struct ResolvedMember {
    flag: &'static str,
    value: String,
    member: Member,
}

impl RingProject {
    /// Blocks until the indexer serves the written entry and a proof for its leaf.
    pub fn write_list(&self, write: ListWrite<'_>) -> Result<()> {
        let verb = match write.state {
            EntryState::Active => "add",
            EntryState::Cleared => "clear",
        };
        let list = ListName::of(write.list_id)?.to_string();
        let ResolvedMember {
            flag,
            value,
            member,
        } = write.member.resolve()?;
        self.run(&["list", verb, &list, flag, &value])?;
        let indexer = write.env.client.indexer();
        let namespace = CustomRing::new(self.program_id).namespace_pda();
        let deadline = Instant::now() + INDEXING_TIMEOUT;
        let live = loop {
            let read = ReadEntry {
                entries_tree: write.entries_tree,
                namespace,
                list_id: write.list_id,
                member,
            };
            match read.read(indexer) {
                Ok(Some(live)) if live.entry.state == write.state => break live,
                _ if Instant::now() > deadline => {
                    bail!("{:?} {:?} entry not indexed", write.list_id, write.state)
                }
                _ => sleep(Duration::from_millis(500)),
            }
        };
        wait_for_merkle_proof(indexer, write.entries_tree, live.utxo_hash);
        Ok(())
    }
}

impl ListMember<'_> {
    fn resolve(&self) -> Result<ResolvedMember> {
        Ok(match self {
            Self::Owner(owner) => ResolvedMember {
                flag: "--owner",
                value: owner_tag_arg(owner)?,
                member: owner_member(owner)?,
            },
            Self::Asset(mint) => ResolvedMember {
                flag: "--asset",
                value: mint.to_string(),
                member: Member::asset(mint)?,
            },
        })
    }
}

pub fn owner_tag_arg(owner: &ShieldedKeypair) -> Result<String> {
    let tag = owner.signing_pubkey().confidential_view_tag()?;
    Ok(Address::new_from_array(tag).to_string())
}

pub fn merged(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
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
        let policy = toml
            .policy
            .map(|block| format!("{}\n\n", block.trim_end()))
            .unwrap_or_default();
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

    /// Re-pins under the upgrade authority.
    pub fn policy_set(&self, block: &str) -> Result<String> {
        let path = self.dir.join("ring.toml");
        let text = std::fs::read_to_string(&path)?;
        std::fs::write(&path, with_policy_block(&text, block)?)?;
        self.run(&["policy", "set", "--yes"])
    }

    /// Exits non-zero while `ring.toml` and the chain disagree.
    pub fn policy_check(&self) -> Result<Output> {
        self.output(&["policy", "check"])
    }

    pub fn demo_sender(&self) -> Result<ShieldedKeypair> {
        let keypair = solana_keypair::read_keypair_file(self.dir.join(SENDER_KEYPAIR_FILE))
            .map_err(|e| anyhow!("read the demo sender keypair {e}"))?;
        Ok(ShieldedKeypair::from_keypair(&keypair)?)
    }

    pub fn output(&self, args: &[&str]) -> Result<Output> {
        Command::new(RING_CLI)
            .arg("--config")
            .arg(self.dir.join("ring.toml"))
            .args(args)
            .output()
            .with_context(|| format!("run zolana-ring {}", args.join(" ")))
    }

    /// Stdout and stderr merged, a non-zero exit is an error.
    pub fn run(&self, args: &[&str]) -> Result<String> {
        let output = self.output(args)?;
        let text = merged(&output);
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

/// The block spans `[policy]` to `[localnet]`, the layout `write_config` writes.
fn with_policy_block(text: &str, block: &str) -> Result<String> {
    let tail = text
        .find("[localnet]\n")
        .ok_or_else(|| anyhow!("ring.toml has no [localnet] table"))?;
    let head = text
        .find("[policy]")
        .filter(|start| *start < tail)
        .unwrap_or(tail);
    Ok(format!(
        "{}{}\n\n{}",
        &text[..head],
        block.trim_end(),
        &text[tail..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_block_is_swapped_ahead_of_the_cluster_tables() {
        let written = "name = \"x\"\n\n[policy]\n\n[[policy.rules]]\nsubject = \"sender\"\n\
                       forbid = \"frozen\"\n\n[localnet]\nrpc = \"a\"\n\n[devnet]\nrpc = \"b\"\n";
        let block = "[policy]\n\n[policy.sources.localnet]\nblock = \"c\"\n";
        assert_eq!(
            with_policy_block(written, block).expect("replace"),
            "name = \"x\"\n\n[policy]\n\n[policy.sources.localnet]\nblock = \"c\"\n\n\
             [localnet]\nrpc = \"a\"\n\n[devnet]\nrpc = \"b\"\n"
        );
        assert_eq!(
            with_policy_block("name = \"x\"\n\n[localnet]\nrpc = \"a\"\n", "[policy]")
                .expect("insert"),
            "name = \"x\"\n\n[policy]\n\n[localnet]\nrpc = \"a\"\n"
        );
        assert!(with_policy_block("name = \"x\"\n", "[policy]").is_err());
    }
}
