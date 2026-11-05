//! Builds, signs and verifies a network's signed TEE prover policy.
//!
//!   tee-policy build  <network>.json --manifest <release.json> [--version N] [--expires-in-days 90] [--freshness-key K]...
//!   tee-policy sign   <network>.json --key alias/zolana-tee-policy-signer-1
//!   tee-policy verify <network>.json [--previous <file>] [--min-days-left 14]
//!   tee-policy verify-served <file or https URL> [--min-hours-left 24]
//!   tee-policy check-release --manifest <release.json> --generation tee-N <prover URL>...
//!
//! Keys are KMS key ids, ARNs or aliases; nothing here holds a private key.

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context, Result};
use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use clap::{Parser, Subcommand};
use spr_prover_tee::{SignedPart, MAX_SIGNED_POLICY_BYTES};
use spr_tee_policy::{
    kms::{kms_public_key, KmsSigner},
    manifest,
    release::{self, MAX_RELEASE_DAYS},
    release_check,
};

/// The keys live in eu-north-1 unless AWS_REGION says otherwise.
const DEFAULT_REGION: &str = "eu-north-1";
const MAX_AGE_SECS: u64 = 600;

#[derive(Parser)]
#[command(about = "Builds, signs and verifies the signed TEE prover policy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Writes an unsigned release part for the network the file is named after.
    Build {
        file: PathBuf,
        /// The zolana-infra release manifest whose serving generations it approves.
        #[arg(long)]
        manifest: PathBuf,
        /// Defaults to one above the file's current version, else 1.
        #[arg(long)]
        version: Option<u64>,
        #[arg(long, default_value_t = MAX_RELEASE_DAYS)]
        expires_in_days: u64,
        /// A KMS key or a lowercase hex key; repeat for several. Defaults to
        /// alias/zolana-tee-policy-freshness-<network>.
        #[arg(long = "freshness-key")]
        freshness_keys: Vec<String>,
    },
    /// Adds one KMS release signer's signature.
    Sign {
        file: PathBuf,
        #[arg(long)]
        key: String,
    },
    /// Verifies a release part against the release keys the SDK pins.
    Verify {
        file: PathBuf,
        /// The release part this one replaces; the version must be above it.
        #[arg(long)]
        previous: Option<PathBuf>,
        #[arg(long, default_value_t = 14)]
        min_days_left: u64,
    },
    /// Verifies the file clients download, as they do.
    VerifyServed {
        source: String,
        #[arg(long, default_value_t = 24)]
        min_hours_left: u64,
    },
    /// Attests every backend of a generation before its release part is
    /// relied on: each must attest under the generation's PCRs through the
    /// SDK's prover client, pass an encrypted proving-key check and refuse a
    /// plaintext proof request; all must hold one key.
    CheckRelease {
        /// The zolana-infra release manifest that records the generation.
        #[arg(long)]
        manifest: PathBuf,
        /// The generation, such as tee-4.
        #[arg(long)]
        generation: String,
        /// One URL per backend: each region's URL of this generation, such
        /// as the `staging_urls` of the environment while it is not active.
        #[arg(required = true)]
        urls: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    match Cli::parse().command {
        Command::Build {
            file,
            manifest: manifest_path,
            version,
            expires_in_days,
            freshness_keys,
        } => {
            ensure!(
                (1..=MAX_RELEASE_DAYS).contains(&expires_in_days),
                "a release part lasts 1 to {MAX_RELEASE_DAYS} days"
            );
            let network = network_of(&file)?;
            let version = match version {
                Some(version) => version,
                None if file.exists() => release::peek(&read(&file)?)?.version + 1,
                None => 1,
            };
            let manifest: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&manifest_path)?)
                    .with_context(|| format!("read {}", manifest_path.display()))?;
            let keys = if freshness_keys.is_empty() {
                vec![format!("alias/zolana-tee-policy-freshness-{network}")]
            } else {
                freshness_keys
            };
            let mut public_keys = Vec::new();
            for key in keys {
                public_keys.push(public_key(&key).await?);
            }
            let part = release::build(
                &network,
                version,
                now + expires_in_days * 86_400,
                public_keys,
                manifest::policy(&manifest, MAX_AGE_SECS)?,
            )?;
            write(&file, &part)?;
            println!("{}: {network} version {version}, unsigned", file.display());
        }
        Command::Sign { file, key } => {
            let mut part = read(&file)?;
            let signer = KmsSigner::new(aws_sdk_kms::Client::new(&aws().await), key).await?;
            let public_key = release::sign(&mut part, &signer).await?;
            write(&file, &part)?;
            println!(
                "{public_key} signed {}, {} signatures",
                file.display(),
                part.signatures.len()
            );
        }
        Command::Verify {
            file,
            previous,
            min_days_left,
        } => {
            let previous = previous.as_deref().map(read).transpose()?;
            let approved = release::verify(&read(&file)?, now, min_days_left, previous.as_ref())?;
            println!(
                "{}: {} version {}, verified",
                file.display(),
                approved.network,
                approved.version
            );
        }
        Command::VerifyServed {
            source,
            min_hours_left,
        } => {
            let body = if source.starts_with("https://") {
                let response = reqwest::get(&source).await?.error_for_status()?;
                response.bytes().await?.to_vec()
            } else {
                std::fs::read(&source).with_context(|| format!("read {source}"))?
            };
            ensure!(
                body.len() <= MAX_SIGNED_POLICY_BYTES,
                "{source} is too large"
            );
            let verified = release::verify_served(&body, now, min_hours_left)?;
            println!(
                "{source}: {} version {}, in force until {} (Unix seconds), verified",
                verified.release.network,
                verified.release.version,
                verified.expires_at()
            );
        }
        Command::CheckRelease {
            manifest,
            generation,
            urls,
        } => {
            let manifest: serde_json::Value = serde_json::from_slice(
                &std::fs::read(&manifest)
                    .with_context(|| format!("read {}", manifest.display()))?,
            )
            .with_context(|| format!("{} is not JSON", manifest.display()))?;
            let policy = manifest::generation_policy(&manifest, &generation, MAX_AGE_SECS)?;
            let key = release_check::check(&policy, &urls).await?;
            println!(
                "{} backends attest {generation} with key {} and refuse plaintext",
                urls.len(),
                hex::encode(key)
            );
        }
    }
    Ok(())
}

async fn aws() -> aws_config::SdkConfig {
    let region = RegionProviderChain::default_provider().or_else(DEFAULT_REGION);
    aws_config::defaults(BehaviorVersion::latest())
        .region(region)
        .load()
        .await
}

/// A lowercase hex key as given, or the key of a KMS key id or alias.
async fn public_key(key: &str) -> Result<String> {
    if key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(key.to_ascii_lowercase());
    }
    let client = aws_sdk_kms::Client::new(&aws().await);
    Ok(hex::encode(kms_public_key(&client, key).await?))
}

fn network_of(file: &Path) -> Result<String> {
    match file.file_stem().and_then(|stem| stem.to_str()) {
        Some(network) if !network.is_empty() => Ok(network.into()),
        _ => bail!("name the file <network>.json"),
    }
}

fn read(file: &Path) -> Result<SignedPart> {
    let bytes = std::fs::read(file).with_context(|| format!("read {}", file.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a release part", file.display()))
}

fn write(file: &Path, part: &SignedPart) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(part)?;
    bytes.push(b'\n');
    std::fs::write(file, bytes).with_context(|| format!("write {}", file.display()))
}
