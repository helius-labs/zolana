//! `new`, the ring directory every other command reads.

use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};

use solana_keypair::Keypair;
use solana_signer::Signer;
use thiserror::Error;

use crate::{
    config::{expand_tilde, ConfigError, RingConfig, Target, Urls},
    file::{self, FileError},
    line, NewArgs, PROGRAM_KEYPAIR_FILE, RING_TOML,
};

pub const DEFAULT_AUTHORITY_KEYPAIR: &str = "~/.config/solana/id.json";

const DEVNET_RPC: &str = "https://api.devnet.solana.com";
const DEVNET_INDEXER: &str = "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com";
const DEVNET_PROVER: &str = "https://d30sgubc9yxiri.cloudfront.net";
const DEVNET_RING_RPC: &str = "https://d1ojzfopdqqs5r.cloudfront.net";
const DEVNET_RING_RPC_PUBKEY: &str = "C8TeRCdueRdXj3y4uFDtNywYThc3qeiH2ZGfcbYZzVSs";

#[derive(Debug, Error)]
pub enum NewError {
    #[error("{name} is not kebab-case, use lowercase letters, digits and dashes")]
    Name { name: String },
    #[error("destination {path} already exists")]
    Exists { path: PathBuf },
    #[error("cannot read the answer")]
    Answer(#[source] io::Error),
    #[error("cannot serialize ring.toml")]
    Toml(#[from] toml::ser::Error),
    #[error(transparent)]
    File(#[from] FileError),
    #[error(transparent)]
    Config(#[from] ConfigError),
}

/// Every answer is taken before anything is written.
pub fn run(args: NewArgs) -> Result<(), NewError> {
    validate_name(&args.name)?;
    let ring_dir = args.dest.join(&args.name);
    if ring_dir.exists() {
        return Err(NewError::Exists { path: ring_dir });
    }
    let prompt = Prompt::new(args.silent);
    let localnet = prompt.urls("localnet", localnet_defaults())?;
    let devnet = prompt.urls("devnet", devnet_defaults())?;
    let program = Keypair::new();
    let config = RingConfig {
        name: args.name.clone(),
        target: Target::Localnet,
        program_id: program.pubkey(),
        authority_keypair: PathBuf::from(&args.authority_keypair),
        upgrade_authority_keypair: None,
        config_authority_keypair: None,
        localnet,
        devnet,
    };

    file::create_dir_all(&ring_dir.join("keys"))?;
    file::write_keypair(&program, &ring_dir.join(PROGRAM_KEYPAIR_FILE))?;
    file::write(&ring_dir.join(RING_TOML), toml::to_string(&config)?)?;
    file::write(&ring_dir.join(".gitignore"), "keys/\n.env\n")?;
    ensure_authority(&args.authority_keypair)?;

    line("ring", ring_dir.display());
    line("program id", program.pubkey());
    println!(
        "next, `cd {}` and `zolana-ring localnet` or `zolana-ring devnet`",
        ring_dir.display()
    );
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

fn validate_name(name: &str) -> Result<(), NewError> {
    let mut chars = name.chars();
    let valid = matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'));
    if !valid {
        return Err(NewError::Name {
            name: name.to_owned(),
        });
    }
    Ok(())
}

/// Without a terminal every question takes its default.
struct Prompt {
    interactive: bool,
}

impl Prompt {
    fn new(silent: bool) -> Self {
        Self {
            interactive: !silent && io::stdin().is_terminal(),
        }
    }

    fn urls(&self, cluster: &str, defaults: Urls) -> Result<Urls, NewError> {
        Ok(Urls {
            rpc: self.ask(&format!("{cluster} Solana RPC URL"), defaults.rpc)?,
            indexer: self.ask(&format!("{cluster} Photon indexer URL"), defaults.indexer)?,
            prover: self.ask(&format!("{cluster} prover URL"), defaults.prover)?,
            ring_rpc: self.ask(&format!("{cluster} ring RPC URL"), defaults.ring_rpc)?,
            ring_rpc_pubkey: match defaults.ring_rpc_pubkey {
                Some(key) => Some(self.ask(
                    &format!("{cluster} ring RPC service pubkey (empty to accept any)"),
                    key,
                )?)
                .filter(|key| !key.is_empty()),
                None => None,
            },
        })
    }

    fn ask(&self, text: &str, default: String) -> Result<String, NewError> {
        if !self.interactive {
            return Ok(default);
        }
        print!("{text} [{default}]: ");
        io::stdout().flush().map_err(NewError::Answer)?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(NewError::Answer)?;
        let answer = answer.trim();
        Ok(if answer.is_empty() {
            default
        } else {
            answer.to_owned()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_kebab_case() {
        for name in ["a", "my-ring", "ring-2"] {
            validate_name(name).expect(name);
        }
        for name in ["", "My-Ring", "9ring", "-ring", "a/b", "a_b", "a b"] {
            assert!(validate_name(name).is_err(), "{name}");
        }
    }

    #[test]
    fn a_silent_new_writes_a_loadable_ring_and_refuses_to_overwrite() {
        let dest = std::env::temp_dir().join(format!("ring-new-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        let authority = dest.join("authority.json");
        let args = || NewArgs {
            name: "smoke".to_owned(),
            dest: dest.clone(),
            silent: true,
            authority_keypair: authority.to_string_lossy().into_owned(),
        };
        run(args()).expect("new");

        let ring_dir = dest.join("smoke");
        let config = RingConfig::load(&ring_dir.join(RING_TOML)).expect("load");
        let program = file::read_keypair(&ring_dir.join(PROGRAM_KEYPAIR_FILE)).expect("keypair");
        assert_eq!(config.program_id, program.pubkey());
        assert_eq!(config.target, Target::Localnet);
        assert_eq!(config.authority_keypair, authority);
        assert_eq!(
            config.devnet.ring_rpc_pubkey.as_deref(),
            Some(DEVNET_RING_RPC_PUBKEY)
        );
        assert!(config.localnet.ring_rpc_is_local());
        assert_eq!(
            std::fs::read_to_string(ring_dir.join(".gitignore")).expect("gitignore"),
            "keys/\n.env\n"
        );
        assert!(matches!(run(args()), Err(NewError::Exists { .. })));
        std::fs::remove_dir_all(dest).expect("cleanup");
    }
}
