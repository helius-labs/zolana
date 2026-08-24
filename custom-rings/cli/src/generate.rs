//! `new`, the wizard behind a generated ring.

use std::{
    fs, io,
    io::IsTerminal,
    path::{Path, PathBuf},
    process::Command,
};

use solana_keypair::Keypair;
use solana_signer::Signer;
use thiserror::Error;

use crate::{
    config::{expand_tilde, ConfigError},
    file::{self, FileError},
    tool::{ToolError, CARGO_GENERATE, GIT},
    NewArgs, PROGRAM_KEYPAIR_FILE, RING_TOML,
};

pub const TEMPLATE_GIT: &str = "https://github.com/helius-labs/zolana-ring";
/// A dev build follows the branch, a release pins its tag here.
pub const TEMPLATE_REV: &str = "main";
/// The ring source arrives from here at the revision ring.toml pins.
pub const ZOLANA_GIT: &str = "https://github.com/helius-labs/zolana";
const SOURCE_SUBFOLDER: &str = "custom-rings";
/// Seeds the ring resolution with the versions zolana builds with.
const WORKSPACE_LOCK: &str = include_str!("../../../Cargo.lock");
pub const DEFAULT_AUTHORITY_KEYPAIR: &str = "~/.config/solana/id.json";

#[derive(Debug, Error)]
pub enum GenerateError {
    #[error("{name} is not kebab-case, use lowercase letters, digits and dashes")]
    Name { name: String },
    #[error("destination {path} already exists")]
    Exists { path: PathBuf },
    #[error("{path} records no authority_keypair")]
    NoAuthorityRecorded { path: PathBuf },
    #[error("{path} records no 40-hex zolana_revision")]
    NoRevisionRecorded { path: PathBuf },
    #[error("cannot resolve template rev {rev} from {origin} to a commit")]
    UnresolvedRev { rev: String, origin: String },
    #[error(transparent)]
    File(#[from] FileError),
    #[error(transparent)]
    Tool(#[from] ToolError),
    #[error(transparent)]
    Config(#[from] ConfigError),
}

pub enum TemplateSource {
    Git { url: String, rev: String },
    Path(PathBuf),
}

pub fn run(args: NewArgs) -> Result<(), GenerateError> {
    validate_name(&args.name)?;
    CARGO_GENERATE.require(Command::new("cargo").args(["generate", "--version"]))?;
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
    file::write_keypair(&program_keypair, &staged_keypair)?;
    let program_id = program_keypair.pubkey();

    render_template(&args, &template, &revision, &program_id.to_string())?;
    let source_rev = copy_ring_source(&args, &ring_dir)?;
    write_lockfile(&ring_dir)?;
    place_program_keypair(&ring_dir, &staged_keypair)?;
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
                let captured = GIT.named("git rev-parse").capture(
                    Command::new("git")
                        .arg("-C")
                        .arg(path)
                        .args(["rev-parse", "HEAD"]),
                );
                match captured {
                    Ok(commit) if is_commit(&commit) => Ok(commit),
                    Ok(_) | Err(ToolError::Failed { .. }) => Err(GenerateError::UnresolvedRev {
                        rev: "HEAD".to_owned(),
                        origin: path.display().to_string(),
                    }),
                    Err(error) => Err(error.into()),
                }
            }
            Self::Git { rev, .. } if is_commit(rev) => Ok(rev.clone()),
            Self::Git { url, rev } => {
                let listed = GIT
                    .named("git ls-remote")
                    .capture(Command::new("git").args(["ls-remote", url, rev]))?;
                commit_from_ls_remote(&listed, rev).ok_or_else(|| GenerateError::UnresolvedRev {
                    rev: rev.clone(),
                    origin: url.clone(),
                })
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

fn render_template(
    args: &NewArgs,
    template: &TemplateSource,
    revision: &str,
    program_id: &str,
) -> Result<(), GenerateError> {
    crate::line("template", format_args!("rendering at {revision}"));
    let silent = args.silent || !io::stdin().is_terminal();
    let mut command = Command::new("cargo");
    command.arg("generate");
    template.apply(&mut command, revision);
    command.arg("--destination").arg(&args.dest);
    // A ring inside a workspace must never be appended to it as a member.
    command.args(["--name", &args.name, "--no-workspace"]);
    if silent {
        command.arg("--silent");
    }
    for define in [
        format!("program_id={program_id}"),
        format!("authority_keypair={}", args.authority_keypair),
    ] {
        command.arg("-d").arg(define);
    }
    command
        .arg("-d")
        .arg(format!("zolana_git={}", args.zolana_git));
    if let Some(rev) = &args.zolana_rev {
        command.arg("-d").arg(format!("zolana_revision={rev}"));
    }
    Ok(CARGO_GENERATE.run(&mut command)?)
}

fn copy_ring_source(args: &NewArgs, ring_dir: &Path) -> Result<String, GenerateError> {
    let source_rev = recorded_revision(ring_dir)?;
    crate::line(
        "source",
        format_args!("copying program, sdk and test from zolana {source_rev}"),
    );
    let mut source = Command::new("cargo");
    source.current_dir(ring_dir);
    source.args(["generate", "--git", &args.zolana_git, SOURCE_SUBFOLDER]);
    source.args(["--revision", &source_rev]);
    source.args(["--init", "--no-workspace", "--silent"]);
    source.args(["--name", &args.name]);
    // Never prompts, its per-file narration only buries the line above.
    CARGO_GENERATE
        .named("cargo generate (ring source)")
        .run_captured(&mut source)?;
    Ok(source_rev)
}

/// Hints only, cargo prunes them to the ring's graph.
fn write_lockfile(ring_dir: &Path) -> Result<(), GenerateError> {
    Ok(file::write(&ring_dir.join("Cargo.lock"), WORKSPACE_LOCK)?)
}

fn place_program_keypair(ring_dir: &Path, staged: &Path) -> Result<(), GenerateError> {
    file::create_dir_all(&ring_dir.join("keys"))?;
    Ok(file::rename(staged, &ring_dir.join(PROGRAM_KEYPAIR_FILE))?)
}

/// The default path is created on a fresh machine, any other missing path is
/// the operator's secret to mount.
fn ensure_authority(ring_dir: &Path) -> Result<(), GenerateError> {
    let recorded = recorded_authority(ring_dir)?;
    let path = expand_tilde(Path::new(&recorded))?;
    if path.is_file() {
        println!(
            "authority {} from {recorded}",
            file::read_keypair(&path)?.pubkey()
        );
    } else if recorded == DEFAULT_AUTHORITY_KEYPAIR {
        if let Some(parent) = path.parent() {
            file::create_dir_all(parent)?;
        }
        let keypair = Keypair::new();
        file::write_keypair(&keypair, &path)?;
        println!("authority {} created at {recorded}", keypair.pubkey());
    } else {
        eprintln!("note: no authority keypair at {recorded}, mount it before `zolana-ring deploy`");
    }
    Ok(())
}

/// Read raw, unexpanded `${...}` URL placeholders stay untouched.
fn recorded_authority(ring_dir: &Path) -> Result<String, GenerateError> {
    recorded_key(ring_dir, "authority_keypair")?.ok_or_else(|| GenerateError::NoAuthorityRecorded {
        path: ring_dir.join(RING_TOML),
    })
}

fn recorded_revision(ring_dir: &Path) -> Result<String, GenerateError> {
    recorded_key(ring_dir, "zolana_revision")?
        .filter(|revision| is_commit(revision))
        .ok_or_else(|| GenerateError::NoRevisionRecorded {
            path: ring_dir.join(RING_TOML),
        })
}

fn recorded_key(ring_dir: &Path, key: &str) -> Result<Option<String>, GenerateError> {
    let value: toml::Value = file::parse_toml(&ring_dir.join(RING_TOML))?;
    Ok(value
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::to_owned))
}

/// The first commit records the generated ring without keys/ and .env, both ignored.
fn commit_generated(ring_dir: &Path, name: &str, program_id: &str) -> Result<(), GenerateError> {
    if ring_dir.join(".git").exists() {
        GIT.named("git checkout")
            .run(git(ring_dir).args(["checkout", "-qB", "main"]))?;
    } else {
        GIT.named("git init")
            .run(git(ring_dir).args(["init", "-q", "-b", "main"]))?;
    }
    GIT.named("git add")
        .run(git(ring_dir).args(["add", "-A"]))?;
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
    Ok(GIT.named("git commit").run(&mut commit)?)
}

fn git(dir: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(dir);
    command
}

fn git_config_is_set(dir: &Path, key: &str) -> bool {
    GIT.capture(git(dir).args(["config", key])).is_ok()
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
        file::create_dir_all(&dir)?;
        Ok(Self { dir })
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
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
