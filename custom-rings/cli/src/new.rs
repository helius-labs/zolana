//! `new`, the ring directory every other command reads.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use solana_keypair::Keypair;
use solana_signer::Signer;
use thiserror::Error;

use crate::{
    config::{expand_tilde, ConfigError, RingConfig, Urls},
    file::{self, FileError},
    line,
    policy::{PolicyError, PolicySpec},
    ui::{self, Ask, AskError, Icon},
    wizard::{LiveCurators, Wizard, WizardError},
    NewArgs, PROGRAM_KEYPAIR_FILE, RING_TOML,
};

pub const DEFAULT_AUTHORITY_KEYPAIR: &str = "~/.config/solana/id.json";

const DEVNET_RPC: &str = "https://api.devnet.solana.com";
const DEVNET_INDEXER: &str = "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com";
const DEVNET_PROVER: &str = "https://d30sgubc9yxiri.cloudfront.net";
const DEVNET_RING_RPC: &str = "https://d1ojzfopdqqs5r.cloudfront.net";
const DEVNET_RING_RPC_PUBKEY: &str = "C8TeRCdueRdXj3y4uFDtNywYThc3qeiH2ZGfcbYZzVSs";

#[derive(Debug, Error)]
pub enum NewError {
    #[error("destination {path} already exists")]
    Exists { path: PathBuf },
    #[error("a name is needed without a terminal, pass it as the argument")]
    NameRequired,
    #[error("nothing written, the preview was not confirmed")]
    Declined,
    #[error(transparent)]
    Wizard(#[from] WizardError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Ask(#[from] AskError),
    #[error(transparent)]
    File(#[from] FileError),
    #[error(transparent)]
    Config(#[from] ConfigError),
}

/// A `ring.toml` or a file holding only its `[policy]` table.
#[derive(Deserialize)]
struct PolicyFile {
    policy: PolicySpec,
}

/// Every answer is taken before anything is written.
pub fn run(args: NewArgs, ask: &mut dyn Ask, catalogue: Option<&str>) -> Result<(), NewError> {
    if args.name.is_none() && !ask.interactive() {
        return Err(NewError::NameRequired);
    }
    if let Some(name) = &args.name {
        refuse_existing(&args.dest.join(name))?;
    }
    let preset = args.policy_from.as_deref().map(read_policy).transpose()?;
    let mut curators = LiveCurators {
        source: catalogue.map(str::to_owned),
    };
    let answers = Wizard {
        ask,
        curators: &mut curators,
        localnet: localnet_defaults(),
        devnet: devnet_defaults(),
    }
    .run(args.name, preset)?;
    let ring_dir = args.dest.join(&answers.name);
    refuse_existing(&ring_dir)?;
    let program = Keypair::new();
    let config = RingConfig {
        name: answers.name,
        target: answers.target,
        program_id: program.pubkey(),
        authority_keypair: PathBuf::from(&args.authority_keypair),
        upgrade_authority_keypair: None,
        config_authority_keypair: None,
        policy: answers.policy,
        localnet: answers.localnet,
        devnet: answers.devnet,
    };
    let rendered = config.render()?;
    ui::heading(Icon::Wizard, "preview");
    print!("{rendered}");
    if !ask.confirm("write the ring directory?", true)? {
        return Err(NewError::Declined);
    }

    file::create_dir_all(&ring_dir.join("keys"))?;
    file::write_keypair(&program, &ring_dir.join(PROGRAM_KEYPAIR_FILE))?;
    file::write(&ring_dir.join(RING_TOML), rendered)?;
    file::write(&ring_dir.join(".gitignore"), "keys/\n.env\n")?;
    ensure_authority(&args.authority_keypair)?;

    ui::heading(Icon::Ring, &config.name);
    line("ring", ring_dir.display());
    line("program id", program.pubkey());
    println!(
        "next, `cd {}` and `zolana-ring localnet` or `zolana-ring devnet`",
        ring_dir.display()
    );
    Ok(())
}

/// Compiled for every cluster before it is taken.
pub(crate) fn read_policy(path: &Path) -> Result<PolicySpec, NewError> {
    let file: PolicyFile = file::parse_toml(path)?;
    file.policy.check()?;
    Ok(file.policy)
}

fn refuse_existing(ring_dir: &Path) -> Result<(), NewError> {
    if ring_dir.exists() {
        return Err(NewError::Exists {
            path: ring_dir.to_path_buf(),
        });
    }
    Ok(())
}

fn localnet_defaults() -> Urls {
    Urls {
        rpc: "http://127.0.0.1:8899".to_owned(),
        indexer: "http://127.0.0.1:8784".to_owned(),
        prover: "http://127.0.0.1:3001".to_owned(),
        ring_rpc: "http://127.0.0.1:8785".to_owned(),
        ring_rpc_pubkey: None,
    }
}

fn devnet_defaults() -> Urls {
    Urls {
        rpc: DEVNET_RPC.to_owned(),
        indexer: DEVNET_INDEXER.to_owned(),
        prover: DEVNET_PROVER.to_owned(),
        ring_rpc: DEVNET_RING_RPC.to_owned(),
        ring_rpc_pubkey: Some(DEVNET_RING_RPC_PUBKEY.to_owned()),
    }
}

/// Only the default path is created, any other missing path is the operator's to mount.
fn ensure_authority(recorded: &str) -> Result<(), NewError> {
    let path = expand_tilde(Path::new(recorded))?;
    if path.is_file() {
        line("authority", file::read_keypair(&path)?.pubkey());
    } else if recorded == DEFAULT_AUTHORITY_KEYPAIR {
        if let Some(parent) = path.parent() {
            file::create_dir_all(parent)?;
        }
        let keypair = Keypair::new();
        file::write_keypair(&keypair, &path)?;
        line(
            "authority",
            format_args!("{} created at {recorded}", keypair.pubkey()),
        );
    } else {
        eprintln!("note: no authority keypair at {recorded}, mount it before `zolana-ring deploy`");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use zolana_ring_policy::{ListId, Rule, RuleTable, Subject};

    use super::*;
    use crate::{
        config::Target,
        ui::{Answer, Defaults, Scripted},
    };

    fn temp(name: &str) -> PathBuf {
        let dest = std::env::temp_dir().join(format!("ring-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        dest
    }

    fn args(name: Option<&str>, dest: &Path, silent: bool) -> NewArgs {
        NewArgs {
            name: name.map(str::to_owned),
            dest: dest.to_path_buf(),
            silent,
            authority_keypair: dest.join("authority.json").to_string_lossy().into_owned(),
            policy_from: None,
        }
    }

    #[test]
    fn a_silent_new_writes_a_loadable_ring_and_refuses_to_overwrite() {
        let dest = temp("new");
        run(args(Some("smoke"), &dest, true), &mut Defaults, None).expect("new");

        let ring_dir = dest.join("smoke");
        let config = RingConfig::load(&ring_dir.join(RING_TOML)).expect("load");
        let program = file::read_keypair(&ring_dir.join(PROGRAM_KEYPAIR_FILE)).expect("keypair");
        assert_eq!(config.program_id, program.pubkey());
        assert_eq!(config.target, Target::Localnet);
        assert_eq!(config.authority_keypair, dest.join("authority.json"));
        assert!(config.policy.is_none());
        assert_eq!(
            config.devnet.ring_rpc_pubkey.as_deref(),
            Some(DEVNET_RING_RPC_PUBKEY)
        );
        assert!(config.localnet.ring_rpc_is_local());
        assert_eq!(
            std::fs::read_to_string(ring_dir.join(".gitignore")).expect("gitignore"),
            "keys/\n.env\n"
        );
        assert!(matches!(
            run(args(Some("smoke"), &dest, true), &mut Defaults, None),
            Err(NewError::Exists { .. })
        ));
        // Refused before the first question, an empty script answers nothing.
        assert!(matches!(
            run(
                args(Some("smoke"), &dest, false),
                &mut Scripted::new([]),
                None
            ),
            Err(NewError::Exists { .. })
        ));
        assert!(matches!(
            run(args(None, &dest, true), &mut Defaults, None),
            Err(NewError::NameRequired)
        ));
        std::fs::remove_dir_all(dest).expect("cleanup");
    }

    #[test]
    fn a_policy_file_is_compiled_and_written_without_policy_questions() {
        let dest = temp("policy-from");
        std::fs::create_dir_all(&dest).expect("dest");
        let policy = dest.join("policy.toml");
        std::fs::write(
            &policy,
            "[policy]\n\n[[policy.rules]]\nsubject = \"sender\"\nforbid = \"frozen\"\n",
        )
        .expect("policy file");
        let mut ask = Scripted::new(
            ["", "", "", "", "", "", "", ""]
                .map(Answer::from)
                .into_iter()
                .chain([Answer::Yes(true), Answer::from("devnet"), Answer::Yes(true)]),
        );
        run(
            NewArgs {
                policy_from: Some(policy.clone()),
                ..args(Some("governed"), &dest, false)
            },
            &mut ask,
            None,
        )
        .expect("new with a policy file");
        assert!(ask.is_drained());
        let config = RingConfig::load(&dest.join("governed").join(RING_TOML)).expect("load");
        assert_eq!(config.target, Target::Devnet);
        let written_policy = config.policy.expect("policy tier");
        assert_eq!(
            written_policy.entries_tree(),
            zolana_interface::pda::tree(0)
        );
        assert!(
            written_policy.entries_tree.is_some(),
            "the default is written explicitly"
        );
        let compiled = written_policy.compile(Target::Devnet).expect("compiles");
        assert_eq!(
            compiled.rules,
            RuleTable::builder()
                .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
                .build()
        );
        let text = std::fs::read_to_string(dest.join("governed").join(RING_TOML)).expect("read");
        assert!(text.contains("# the sender must not be on the frozen list\n[[policy.rules]]"));

        let example =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/own-blocklist/ring.toml");
        run(
            NewArgs {
                policy_from: Some(example),
                ..args(Some("from-example"), &dest, true)
            },
            &mut Defaults,
            None,
        )
        .expect("new from a full ring.toml");
        let config = RingConfig::load(&dest.join("from-example").join(RING_TOML)).expect("load");
        assert_eq!(config.policy.expect("policy tier").rules.len(), 1);

        std::fs::write(
            &policy,
            "[policy]\n\n[[policy.rules]]\nsubject = \"sender\"\nrequire = \"allow\"\nabove = 1\n",
        )
        .expect("policy file");
        assert!(matches!(
            run(
                NewArgs {
                    policy_from: Some(policy),
                    ..args(Some("refused"), &dest, true)
                },
                &mut Defaults,
                None,
            ),
            Err(NewError::Policy(PolicyError::SenderGuard { rule: 0 }))
        ));
        assert!(!dest.join("refused").exists());
        std::fs::remove_dir_all(dest).expect("cleanup");
    }
}
