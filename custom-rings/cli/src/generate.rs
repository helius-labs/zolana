//! `new`, the wizard behind a generated ring.

use std::{
    fs, io,
    io::IsTerminal,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use solana_keypair::{read_keypair_file, write_keypair_file, Keypair};
use solana_signer::Signer;
use thiserror::Error;

use crate::{
    config::{expand_tilde, ConfigError},
    NewArgs, PROGRAM_KEYPAIR_FILE, RING_TOML,
};

pub const TEMPLATE_GIT: &str = "https://github.com/helius-labs/zolana-ring";
/// A dev build follows the branch, a release pins its tag here.
pub const TEMPLATE_REV: &str = "main";
/// The ring source arrives from here at the revision ring.toml pins.
pub const ZOLANA_GIT: &str = "https://github.com/helius-labs/zolana";
const SOURCE_SUBFOLDER: &str = "custom-rings";
pub const DEFAULT_AUTHORITY_KEYPAIR: &str = "~/.config/solana/id.json";

#[derive(Debug, Error)]
pub enum GenerateError {
    #[error("{name} is not kebab-case, use lowercase letters, digits and dashes")]
    Name { name: String },
    #[error("cargo generate is not installed, run `cargo install cargo-generate --locked`")]
    CargoGenerateMissing,
    #[error("destination {path} already exists")]
    Exists { path: PathBuf },
    #[error("cannot prepare {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot write program keypair {path}, {message}")]
    ProgramKeypair { path: PathBuf, message: String },
    #[error("cannot read authority keypair {path}, {message}")]
    AuthorityKeypair { path: PathBuf, message: String },
    #[error("cannot parse {path}")]
    RingToml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("{path} records no authority_keypair")]
    NoAuthorityRecorded { path: PathBuf },
    #[error("{path} records no 40-hex zolana_revision")]
    NoRevisionRecorded { path: PathBuf },
    #[error("cannot run {tool}")]
    Spawn {
        tool: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{tool} exited with {status}")]
    Failed {
        tool: &'static str,
        status: ExitStatus,
    },
    #[error("cannot resolve template rev {rev} from {origin} to a commit")]
    UnresolvedRev { rev: String, origin: String },
    #[error(transparent)]
    Config(#[from] ConfigError),
}

pub enum TemplateSource {
    Git { url: String, rev: String },
    Path(PathBuf),
}

pub fn run(args: NewArgs) -> Result<(), GenerateError> {
    validate_name(&args.name)?;
    check_cargo_generate()?;
    let ring_dir = args.dest.join(&args.name);
    if ring_dir.exists() {
        return Err(GenerateError::Exists { path: ring_dir });
    }
    let template = TemplateSource::from_args(&args);
    let revision = template.resolve_commit()?;

    // The program keypair decides the deploy address, it exists before the
    // template renders the program id.
    let staging = Staging::create(&args.dest, &args.name)?;
    let staged_keypair = staging.dir.join("program-keypair.json");
    let program_keypair = Keypair::new();
    write_keypair_file(&program_keypair, &staged_keypair).map_err(|error| {
        GenerateError::ProgramKeypair {
            path: staged_keypair.clone(),
            message: error.to_string(),
        }
    })?;
    restrict_mode(&staged_keypair)?;
    let program_id = program_keypair.pubkey();

    let silent = args.silent || !io::stdin().is_terminal();
    let mut command = Command::new("cargo");
    command.arg("generate");
    template.apply(&mut command, &revision);
    command.arg("--destination").arg(&args.dest);
    command.args(["--name", &args.name]);
    if silent {
        command.arg("--silent");
    }
    for define in [
        format!("silent={silent}"),
        format!("program_id={program_id}"),
        format!("default_authority_keypair={}", args.authority_keypair),
    ] {
        command.arg("-d").arg(define);
    }
    if let Some(rev) = &args.zolana_rev {
        command.arg("-d").arg(format!("zolana_revision={rev}"));
    }
    run_tool("cargo generate", &mut command)?;

    // Stage two, the ring source is taken from zolana at the pinned revision.
    let source_rev = recorded_revision(&ring_dir)?;
    let mut source = Command::new("cargo");
    source.current_dir(&ring_dir);
    source.args(["generate", "--git", &args.zolana_git, SOURCE_SUBFOLDER]);
    source.args(["--revision", &source_rev]);
    source.args(["--init", "--vcs", "none", "--silent"]);
    source.args(["--name", &args.name]);
    run_tool("cargo generate (ring source)", &mut source)?;

    let keys_dir = ring_dir.join("keys");
    fs::create_dir_all(&keys_dir).map_err(|source| GenerateError::Io {
        path: keys_dir.clone(),
        source,
    })?;
    let keypair_path = ring_dir.join(PROGRAM_KEYPAIR_FILE);
    fs::rename(&staged_keypair, &keypair_path).map_err(|source| GenerateError::Io {
        path: keypair_path.clone(),
        source,
    })?;
    ensure_authority(&ring_dir)?;
    commit_generated(&ring_dir, &args.name, &program_id.to_string())?;

    println!();
    println!(
        "generated {} for program {program_id}, template {revision}, source {source_rev}",
        ring_dir.display()
    );
    println!();
    println!("next");
    println!("  cd {}", ring_dir.display());
    println!("  zolana-ring devnet      # or localnet, records the target in ring.toml");
    println!("  zolana-ring pipeline    # build, deploy, init, ring rpc, transact");
    println!("fund the authority at https://faucet.solana.com when a devnet step pauses");
    Ok(())
}

impl TemplateSource {
    fn from_args(args: &NewArgs) -> Self {
        match &args.template_path {
            Some(path) => Self::Path(path.clone()),
            None => Self::Git {
                url: args.template_git.clone(),
                rev: args.template_rev.clone(),
            },
        }
    }

    /// The generated ring pins its program dependency by the returned commit.
    pub fn resolve_commit(&self) -> Result<String, GenerateError> {
        match self {
            Self::Path(path) => {
                let output = Command::new("git")
                    .arg("-C")
                    .arg(path)
                    .args(["rev-parse", "HEAD"])
                    .output()
                    .map_err(|source| GenerateError::Spawn {
                        tool: "git",
                        source,
                    })?;
                let commit = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                if !output.status.success() || !is_commit(&commit) {
                    return Err(GenerateError::UnresolvedRev {
                        rev: "HEAD".to_owned(),
                        origin: path.display().to_string(),
                    });
                }
                Ok(commit)
            }
            Self::Git { rev, .. } if is_commit(rev) => Ok(rev.clone()),
            Self::Git { url, rev } => {
                let output = Command::new("git")
                    .args(["ls-remote", url, rev])
                    .output()
                    .map_err(|source| GenerateError::Spawn {
                        tool: "git",
                        source,
                    })?;
                if !output.status.success() {
                    return Err(GenerateError::Failed {
                        tool: "git ls-remote",
                        status: output.status,
                    });
                }
                commit_from_ls_remote(&String::from_utf8_lossy(&output.stdout), rev).ok_or_else(
                    || GenerateError::UnresolvedRev {
                        rev: rev.clone(),
                        origin: url.clone(),
                    },
                )
            }
        }
    }

    /// The resolved commit renders, a branch could advance after resolution.
    fn apply(&self, command: &mut Command, revision: &str) {
        match self {
            Self::Path(path) => {
                command.arg("--path").arg(path);
            }
            Self::Git { url, .. } => {
                command.args(["--git", url]);
                command.args(["--revision", revision]);
            }
        }
    }
}

/// The default path is created on a fresh machine, any other missing path is
/// the operator's secret to mount.
fn ensure_authority(ring_dir: &Path) -> Result<(), GenerateError> {
    let recorded = recorded_authority(ring_dir)?;
    let file = expand_tilde(Path::new(&recorded))?;
    let read = |path: &Path| {
        read_keypair_file(path).map_err(|error| GenerateError::AuthorityKeypair {
            path: path.to_path_buf(),
            message: error.to_string(),
        })
    };
    if file.is_file() {
        println!("authority {} from {recorded}", read(&file)?.pubkey());
    } else if recorded == DEFAULT_AUTHORITY_KEYPAIR {
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent).map_err(|source| GenerateError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let keypair = Keypair::new();
        write_keypair_file(&keypair, &file).map_err(|error| GenerateError::AuthorityKeypair {
            path: file.clone(),
            message: error.to_string(),
        })?;
        restrict_mode(&file)?;
        println!("authority {} created at {recorded}", keypair.pubkey());
    } else {
        eprintln!("note: no authority keypair at {recorded}, mount it before `zolana-ring deploy`");
    }
    Ok(())
}

/// Read the recorded path alone, a full config load would expand `${...}` URL
/// placeholders the operator has not set yet.
fn recorded_authority(ring_dir: &Path) -> Result<String, GenerateError> {
    recorded_key(ring_dir, "authority_keypair")?.ok_or_else(|| GenerateError::NoAuthorityRecorded {
        path: ring_dir.join(RING_TOML),
    })
}

/// The revision stage one rendered, stage two takes the source from it.
fn recorded_revision(ring_dir: &Path) -> Result<String, GenerateError> {
    recorded_key(ring_dir, "zolana_revision")?
        .filter(|revision| is_commit(revision))
        .ok_or_else(|| GenerateError::NoRevisionRecorded {
            path: ring_dir.join(RING_TOML),
        })
}

fn recorded_key(ring_dir: &Path, key: &str) -> Result<Option<String>, GenerateError> {
    let path = ring_dir.join(RING_TOML);
    let text = fs::read_to_string(&path).map_err(|source| GenerateError::Io {
        path: path.clone(),
        source,
    })?;
    let value: toml::Value = toml::from_str(&text).map_err(|source| GenerateError::RingToml {
        path: path.clone(),
        source,
    })?;
    Ok(value
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::to_owned))
}

/// The first commit records the generated ring without keys/ and .env, both ignored.
fn commit_generated(ring_dir: &Path, name: &str, program_id: &str) -> Result<(), GenerateError> {
    if ring_dir.join(".git").exists() {
        run_tool(
            "git checkout",
            git(ring_dir).args(["checkout", "-qB", "main"]),
        )?;
    } else {
        run_tool("git init", git(ring_dir).args(["init", "-q", "-b", "main"]))?;
    }
    run_tool("git add", git(ring_dir).args(["add", "-A"]))?;
    let mut commit = git(ring_dir);
    // A machine with no git identity, a CI runner, cannot author a commit.
    if !git_config_is_set(ring_dir, "user.name") || !git_config_is_set(ring_dir, "user.email") {
        commit.args([
            "-c",
            "user.name=ring wizard",
            "-c",
            "user.email=ring-wizard@invalid",
        ]);
    }
    commit.args([
        "commit",
        "-q",
        "-m",
        &format!("ring: generate {name} for program {program_id}"),
    ]);
    run_tool("git commit", &mut commit)
}

fn git(dir: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(dir);
    command
}

fn git_config_is_set(dir: &Path, key: &str) -> bool {
    git(dir)
        .args(["config", key])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run_tool(tool: &'static str, command: &mut Command) -> Result<(), GenerateError> {
    let status = command
        .status()
        .map_err(|source| GenerateError::Spawn { tool, source })?;
    if !status.success() {
        return Err(GenerateError::Failed { tool, status });
    }
    Ok(())
}

fn check_cargo_generate() -> Result<(), GenerateError> {
    let output = Command::new("cargo")
        .args(["generate", "--version"])
        .output()
        .map_err(|source| GenerateError::Spawn {
            tool: "cargo",
            source,
        })?;
    if !output.status.success() {
        return Err(GenerateError::CargoGenerateMissing);
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), GenerateError> {
    let mut chars = name.chars();
    let valid = matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'));
    if !valid {
        return Err(GenerateError::Name {
            name: name.to_owned(),
        });
    }
    Ok(())
}

fn commit_from_ls_remote(output: &str, rev: &str) -> Option<String> {
    let find = |wanted: &str| {
        output.lines().find_map(|line| {
            let (commit, name) = line.split_once('\t')?;
            (name == wanted && is_commit(commit)).then(|| commit.to_owned())
        })
    };
    [
        format!("refs/heads/{rev}"),
        // The peeled entry of an annotated tag names the commit itself.
        format!("refs/tags/{rev}^{{}}"),
        format!("refs/tags/{rev}"),
        rev.to_owned(),
    ]
    .iter()
    .find_map(|wanted| find(wanted))
}

fn is_commit(rev: &str) -> bool {
    rev.len() == 40
        && rev
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Staged next to the ring, never in a system temp dir, removed on drop.
struct Staging {
    dir: PathBuf,
}

impl Staging {
    fn create(dest: &Path, name: &str) -> Result<Self, GenerateError> {
        let dir = dest.join(format!(".{name}.keys"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).map_err(|source| GenerateError::Io {
            path: dir.clone(),
            source,
        })?;
        Ok(Self { dir })
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(unix)]
fn restrict_mode(path: &Path) -> Result<(), GenerateError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        GenerateError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn restrict_mode(_path: &Path) -> Result<(), GenerateError> {
    Ok(())
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
    fn only_forty_lowercase_hex_is_a_commit() {
        assert!(is_commit(&"a1".repeat(20)));
        assert!(!is_commit(&"A1".repeat(20)));
        assert!(!is_commit(&"a1".repeat(19)));
        assert!(!is_commit("main"));
    }

    #[test]
    fn ls_remote_resolution_prefers_heads_then_peeled_tags() {
        let head = "a".repeat(40);
        let tag = "b".repeat(40);
        let peeled = "c".repeat(40);
        let output = format!(
            "{head}\trefs/heads/main\n{tag}\trefs/tags/main\n{tag}\trefs/tags/v1\n{peeled}\trefs/tags/v1^{{}}\n{head}\tHEAD\n"
        );
        assert_eq!(commit_from_ls_remote(&output, "main"), Some(head.clone()));
        assert_eq!(commit_from_ls_remote(&output, "v1"), Some(peeled));
        assert_eq!(commit_from_ls_remote(&output, "HEAD"), Some(head));
        assert_eq!(commit_from_ls_remote(&output, "missing"), None);
    }

    #[test]
    fn a_forty_hex_rev_resolves_without_git() {
        let rev = "d".repeat(40);
        let source = TemplateSource::Git {
            url: "https://invalid.invalid/repo".to_owned(),
            rev: rev.clone(),
        };
        assert_eq!(source.resolve_commit().expect("pinned"), rev);
    }
}
