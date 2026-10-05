//! Proves a live TEE prover end to end through the SDK, sealed to its attested key.

use std::{fs, path::PathBuf};

use anyhow::{bail, Context, Result};
use reqwest::Url;
use zeroize::Zeroizing;
use zolana_client::{
    error::ClientError,
    prover::{
        known_proving_keys, tee::TeePolicy, ExpectedProvingKey, ProveRequest, Prover,
        ProverClient,
    },
};

pub struct TeeCheckOptions {
    pub prover_url: String,
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
        let usage = "usage: tee-check <prover-url> [--prove <request.json> <key name>]";
        let prover_url = args.next().context(usage)?;
        let proof = match args.next().as_deref() {
            None => None,
            Some("--prove") => Some((
                PathBuf::from(args.next().context(usage)?),
                args.next().context(usage)?,
            )),
            Some(other) => bail!("tee-check unexpected arg {other:?}"),
        };
        Ok(Self { prover_url, proof })
    }

    pub fn run(self) -> Result<()> {
        let mut url = Url::parse(&self.prover_url)?;
        // The key comes from the environment, a command line argument shows in the process list.
        if let Ok(key) = std::env::var("PROVER_API_KEY") {
            url.query_pairs_mut().append_pair("api-key", &key);
        }
        let prover = ProverClient::new(url.into()).with_tee(TeePolicy::pinned()?);

        let attested = prover.attest().context("attestation")?;
        println!(
            "attested, TCB {}, compose {}, GPU {}",
            attested.tcb_status,
            hex::encode(attested.compose_hash),
            if attested.gpu_verified { "verified" } else { "absent" },
        );
        let report = prover
            .check_proving_keys()
            .context("sealed proving key check")?;
        println!("sealed proving key check passed, {} keys", report.keys.len());

        if let Some((path, name)) = self.proof {
            let sha256 = known_proving_keys()
                .find(|(known, _)| *known == name)
                .map(|(_, sha256)| sha256)
                .with_context(|| format!("{name} is not a known proving key"))?;
            let request = RawRequest {
                body: fs::read_to_string(&path)?,
                key: ExpectedProvingKey { name, sha256 },
            };
            prover.prove(&request).context("sealed proof")?;
            println!("sealed proof returned from {}", request.key.name);
        }
        Ok(())
    }
}
