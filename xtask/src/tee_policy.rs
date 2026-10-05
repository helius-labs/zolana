//! Pins a live TEE prover into the SDK release.

use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use rand_core::{OsRng, TryRngCore};
use reqwest::Url;
use zolana_client::{
    prover::tee::{inspect, Evidence, GpuRequirement, TeeError, TeePolicy, ATTESTATION_PATH},
    ProverClient,
};

const RUST_POLICY: &str = "sdk-libs/client/src/prover/tee/policy.json";
const TS_POLICY: &str = "sdk-libs/ts/src/client/prover/tee/pinned.ts";
const DEFAULT_MAX_AGE_SECS: u64 = 600;

pub struct TeePolicyOptions {
    pub prover_url: String,
    pub gpu: GpuRequirement,
    /// Start a new pin instead of extending the pinned one.
    pub replace: bool,
}

impl TeePolicyOptions {
    pub fn parse(mut args: impl Iterator<Item = String>) -> Result<Self> {
        let prover_url = args
            .next()
            .context("usage: tee-policy <prover-url> [--gpu-required] [--replace]")?;
        let mut options = Self {
            prover_url,
            gpu: GpuRequirement::Optional,
            replace: false,
        };
        for arg in args {
            match arg.as_str() {
                "--gpu-required" => options.gpu = GpuRequirement::Required,
                "--replace" => options.replace = true,
                other => bail!("tee-policy unexpected arg {other:?}"),
            }
        }
        Ok(options)
    }

    /// Attests the prover again under the pins it writes.
    pub fn run(self, root: &Path) -> Result<()> {
        // The key comes from the environment, a command line argument shows in the process list.
        let mut prover_url = Url::parse(&self.prover_url)?;
        if let Ok(key) = std::env::var("PROVER_API_KEY") {
            prover_url.query_pairs_mut().append_pair("api-key", &key);
        }
        let evidence = fetch_evidence(&prover_url)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let identity = inspect(evidence, now)?;
        if identity.key_provider.name != "kms" {
            bail!(
                "prover keys come from {:?}, not a KMS",
                identity.key_provider.name
            );
        }

        let mut policy = match (self.replace, TeePolicy::pinned()) {
            (false, Ok(pinned)) => pinned,
            (true, _) | (false, Err(TeeError::NoPinnedDeployment)) => TeePolicy {
                app_id: identity.app_id,
                hpke_public_key: identity.hpke_public_key,
                key_provider_id: identity.key_provider.id.clone(),
                os_image_hashes: Vec::new(),
                measurements: Vec::new(),
                compose_hashes: Vec::new(),
                tcb_statuses: vec!["UpToDate".into()],
                gpu: self.gpu,
                max_age_secs: DEFAULT_MAX_AGE_SECS,
            },
            (false, Err(error)) => return Err(error.into()),
        };
        // A new app id or KMS root derives a new key, pinned only under `--replace`.
        if policy.app_id != identity.app_id
            || policy.hpke_public_key != identity.hpke_public_key
            || policy.key_provider_id != identity.key_provider.id
        {
            bail!("prover is another app or key than the pinned one, rerun with --replace");
        }
        // A GPU-required pin never drops back to optional on an update without `--gpu-required`.
        if self.gpu == GpuRequirement::Required {
            policy.gpu = GpuRequirement::Required;
        }
        push_new(&mut policy.compose_hashes, identity.compose_hash);
        push_new(&mut policy.os_image_hashes, identity.os_image_hash);
        push_new(&mut policy.measurements, identity.measurement);
        if !policy.tcb_statuses.contains(&identity.tcb_status) {
            bail!(
                "prover TCB status is {}, refusing to pin it",
                identity.tcb_status
            );
        }

        write_pins(root, &policy)?;
        let attested = ProverClient::new(prover_url.into())
            .with_tee(policy)
            .attest()
            .context("prover fails the policy just written")?;
        println!(
            "pinned compose {} TCB {} GPU {}",
            hex::encode(attested.compose_hash),
            attested.tcb_status,
            if attested.gpu_verified {
                "verified"
            } else {
                "absent"
            },
        );
        Ok(())
    }
}

fn fetch_evidence(prover_url: &Url) -> Result<Evidence> {
    let mut nonce = [0u8; 32];
    OsRng.try_fill_bytes(&mut nonce)?;
    let mut url = prover_url.clone();
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("prover URL cannot take a path"))?
        .pop_if_empty()
        .extend(
            ATTESTATION_PATH
                .split('/')
                .filter(|segment| !segment.is_empty()),
        );
    url.query_pairs_mut()
        .append_pair("nonce", &hex::encode(nonce));
    // reqwest errors print the URL, and the URL carries the API key.
    let response = reqwest::blocking::get(url)
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| anyhow::anyhow!("attestation request failed, {}", e.without_url()))?;
    response
        .json()
        .map_err(|e| anyhow::anyhow!("attestation is malformed, {}", e.without_url()))
}

fn push_new<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn write_pins(root: &Path, policy: &TeePolicy) -> Result<()> {
    let file = serde_json::json!({ "deployment": policy });
    fs::write(
        root.join(RUST_POLICY),
        format!("{}\n", serde_json::to_string_pretty(&file)?),
    )?;
    let ts = format!(
        "/** Mirrors `{RUST_POLICY}`, kept equal by a test. */\nexport const PINNED_TEE_POLICY_FILE: Readonly<{{ deployment: unknown }}> = Object.freeze({});\n",
        serde_json::to_string_pretty(&file)?
    );
    fs::write(root.join(TS_POLICY), ts)?;
    Ok(())
}
