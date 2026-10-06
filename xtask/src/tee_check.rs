//! Proves a live TEE prover end to end through the SDK, encrypted to its attested key.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use reqwest::Url;
use zeroize::Zeroizing;
use zolana_client::{
    error::ClientError,
    prover::{
        known_proving_keys,
        tee::{TeePolicy, TeePolicyFile},
        ExpectedProvingKey, ProveRequest, Prover, ProverClient,
    },
};

pub struct TeeCheckOptions {
    pub prover_url: String,
    /// A policy JSON file, the release pin when absent.
    pub policy: Option<PathBuf>,
    /// A raw prover request body and the proving key it targets.
    pub proof: Option<(PathBuf, String)>,
}

struct RawRequest {
    body: String,
    key: ExpectedProvingKey,
}

impl ProveRequest for RawRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        Ok(Zeroizing::new(self.body.clone()))
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        Ok(self.key.clone())
    }
}

impl TeeCheckOptions {
    pub fn parse(mut args: impl Iterator<Item = String>) -> Result<Self> {
        let usage =
            "usage: tee-check <prover-url> [--policy <policy.json>] [--prove <request.json> <key name>]";
        let mut options = Self {
            prover_url: args.next().context(usage)?,
            policy: None,
            proof: None,
        };
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--policy" => options.policy = Some(PathBuf::from(args.next().context(usage)?)),
                "--prove" => {
                    options.proof = Some((
                        PathBuf::from(args.next().context(usage)?),
                        args.next().context(usage)?,
                    ))
                }
                other => bail!("tee-check unexpected arg {other:?}"),
            }
        }
        Ok(options)
    }

    pub fn run(self) -> Result<()> {
        let mut url = Url::parse(&self.prover_url)?;
        // The key comes from the environment, a command line argument shows in the process list.
        if let Ok(key) = std::env::var("PROVER_API_KEY") {
            url.query_pairs_mut().append_pair("api-key", &key);
        }
        let policy = match &self.policy {
            Some(path) => read_policy(path)?,
            None => TeePolicy::default_deployment()?,
        };
        let prover = ProverClient::new(url.into()).with_tee(policy);

        let attested = prover.attest().context("attestation")?;
        println!("attested {attested}");
        let report = prover
            .check_proving_keys()
            .context("encrypted proving key check")?;
        println!(
            "encrypted proving key check passed, {} keys",
            report.keys.len()
        );

        if let Some((path, name)) = self.proof {
            let sha256 = known_proving_keys()
                .find(|(known, _)| *known == name)
                .map(|(_, sha256)| sha256)
                .with_context(|| format!("{name} is not a known proving key"))?;
            let request = RawRequest {
                body: fs::read_to_string(&path)?,
                key: ExpectedProvingKey { name, sha256 },
            };
            prover.prove(&request).context("encrypted proof")?;
            println!("encrypted proof returned from {}", request.key.name);
        }
        Ok(())
    }
}

/// A release pin file or a bare policy.
fn read_policy(path: &Path) -> Result<TeePolicy> {
    let json = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&json).with_context(|| format!("{} is not JSON", path.display()))?;
    if value.get("deployment").is_none() {
        return Ok(TeePolicy::from_json(&json)?);
    }
    serde_json::from_str::<TeePolicyFile>(&json)
        .with_context(|| format!("{} is not a pin file", path.display()))?
        .deployment
        .with_context(|| format!("{} pins no deployment", path.display()))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    const POLICY: &str = include_str!("../../prover/tee/testdata/probe_policy.json");

    fn read(name: &str, json: &str) -> Result<TeePolicy> {
        let path =
            std::env::temp_dir().join(format!("tee-check-{}-{name}.json", std::process::id()));
        fs::write(&path, json).unwrap();
        let policy = read_policy(&path);
        fs::remove_file(&path).unwrap();
        policy
    }

    #[test]
    fn read_policy_takes_a_pin_file_or_a_bare_policy() {
        let bare = read("bare", POLICY).unwrap();
        let pinned = read("pinned", &format!(r#"{{"deployment":{POLICY}}}"#)).unwrap();
        assert_eq!(bare, pinned);
        assert_eq!(bare, TeePolicy::from_json(POLICY).unwrap());
    }

    #[test]
    fn read_policy_reports_the_parse_error() {
        let error = read("empty", r#"{"deployment":null}"#).unwrap_err();
        assert!(
            format!("{error:#}").contains("pins no deployment"),
            "{error:#}"
        );
        let error = read(
            "typo",
            r#"{"deployment":{"platform":"aws-nitro","measurements":7}}"#,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("is not a pin file"),
            "{error:#}"
        );
        let error = read("bare-typo", &POLICY.replacen("\"gpu\"", "\"gpus\"", 1)).unwrap_err();
        assert!(format!("{error:#}").contains("`gpu"), "{error:#}");
        assert!(read_policy(&PathBuf::from("/nonexistent/policy.json")).is_err());
    }
}
