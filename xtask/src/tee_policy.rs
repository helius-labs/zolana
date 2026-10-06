//! Pins a live TEE prover into the SDK release.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use rand_core::{OsRng, TryRngCore};
use reqwest::Url;
use zolana_client::{
    prover::tee::{
        inspect, Attestation, AttestedIdentity, DstackIdentity, DstackPolicy, GpuRequirement,
        NitroMeasurement, NitroPolicy, PlatformIdentity, PlatformPolicy, TeeError, TeePolicy,
        TeePolicyFile, ATTESTATION_PATH, MAX_ATTESTATION_BYTES,
    },
    ProverClient,
};

const MEASURE: &str = "tools/nitro/aws_nitro.py measure";
const RUST_POLICY: &str = "sdk-libs/client/src/prover/tee/policy.json";
const TS_POLICY: &str = "sdk-libs/ts/src/client/prover/tee/default.ts";

pub struct TeePolicyOptions {
    pub prover_url: String,
    pub gpu: GpuRequirement,
    /// Start a new pin instead of extending the pinned one.
    pub replace: bool,
    pub expect_pcrs: Option<PathBuf>,
}

struct Pin<'a> {
    current: Option<&'a PlatformPolicy>,
    identity: &'a AttestedIdentity,
    built: Option<&'a NitroMeasurement>,
}

impl TeePolicyOptions {
    pub fn parse(mut args: impl Iterator<Item = String>) -> Result<Self> {
        let usage =
            "usage: tee-policy <prover-url> [--gpu-required] [--replace] [--expect-pcrs <file>]";
        let mut options = Self {
            prover_url: args.next().context(usage)?,
            gpu: GpuRequirement::Optional,
            replace: false,
            expect_pcrs: None,
        };
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--gpu-required" => options.gpu = GpuRequirement::Required,
                "--replace" => options.replace = true,
                "--expect-pcrs" => options.expect_pcrs = Some(args.next().context(usage)?.into()),
                other => bail!("tee-policy unexpected arg {other:?}"),
            }
        }
        Ok(options)
    }

    pub fn run(self, root: &Path) -> Result<()> {
        // The key comes from the environment, a command line argument shows in the process list.
        let mut prover_url = Url::parse(&self.prover_url)?;
        if let Ok(key) = std::env::var("PROVER_API_KEY") {
            prover_url.query_pairs_mut().append_pair("api-key", &key);
        }
        let built = self.expect_pcrs.as_deref().map(read_pcrs).transpose()?;
        let attestation = fetch_attestation(&prover_url)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let identity = inspect(attestation, now)?;

        let current = match (self.replace, TeePolicy::default_deployment()) {
            (false, Ok(current)) => Some(current),
            (true, _) | (false, Err(TeeError::NoDefaultDeployment)) => None,
            (false, Err(error)) => return Err(error.into()),
        };
        // A GPU-required pin never drops back to optional on an update without `--gpu-required`.
        let gpu = match current.as_ref().map(TeePolicy::gpu) {
            Some(GpuRequirement::Required) => GpuRequirement::Required,
            _ => self.gpu,
        };
        let pins = Pin {
            current: current.as_ref().map(TeePolicy::pins),
            identity: &identity,
            built: built.as_ref(),
        }
        .extend()?;
        let policy = TeePolicy::new(pins).with_gpu(gpu)?;
        let policy = match &current {
            Some(current) => policy.with_max_age(current.max_age()),
            None => policy,
        };

        let prover = ProverClient::new(prover_url.into()).with_tee(policy.clone());
        let attested = prover
            .attest()
            .context("prover fails the candidate policy")?;
        prover
            .check_proving_keys()
            .context("encrypted proving key check failed")?;
        write_pins(root, policy)?;
        println!("pinned {attested}");
        Ok(())
    }
}

impl Pin<'_> {
    /// The pinned measurements plus the live prover's, refusing a prover the pin cannot extend to.
    fn extend(self) -> Result<PlatformPolicy> {
        let Self {
            current,
            identity,
            built,
        } = self;
        let found_platform = identity.platform.platform();
        if let Some(current) = current.filter(|pins| pins.platform() != found_platform) {
            bail!(
                "prover attests as {found_platform}, the pin is {}, rerun with --replace",
                current.platform()
            );
        }
        match &identity.platform {
            PlatformIdentity::DstackTdx(found) => {
                if built.is_some() {
                    bail!("--expect-pcrs applies to an aws-nitro prover only");
                }
                let mut pins = match current {
                    Some(PlatformPolicy::DstackTdx(pins)) => pins.clone(),
                    _ => new_dstack(found, identity.hpke_public_key),
                };
                if found.key_provider.name != "kms" {
                    bail!(
                        "prover keys come from {:?}, not a KMS",
                        found.key_provider.name
                    );
                }
                // A new app id or KMS root derives a new key, pinned only under `--replace`.
                if pins.app_id != found.app_id
                    || pins.hpke_public_key != identity.hpke_public_key
                    || pins.key_provider_id != found.key_provider.id
                {
                    bail!("prover is another app or key than the pinned one, rerun with --replace");
                }
                if !pins.tcb_statuses.contains(&found.tcb_status) {
                    bail!(
                        "prover TCB status is {}, refusing to pin it",
                        found.tcb_status
                    );
                }
                push_new(&mut pins.compose_hashes, found.compose_hash);
                push_new(&mut pins.os_image_hashes, found.os_image_hash);
                push_new(&mut pins.measurements, found.measurement.clone());
                Ok(PlatformPolicy::DstackTdx(pins))
            }
            PlatformIdentity::AwsNitro(found) => {
                matches_build(&found.measurement, built)?;
                let mut pins = match current {
                    Some(PlatformPolicy::AwsNitro(pins)) => pins.clone(),
                    _ => NitroPolicy::default(),
                };
                push_new(&mut pins.measurements, found.measurement.clone());
                Ok(PlatformPolicy::AwsNitro(pins))
            }
            _ => bail!("cannot pin a {found_platform} prover"),
        }
    }
}

fn matches_build(live: &NitroMeasurement, built: Option<&NitroMeasurement>) -> Result<()> {
    let built = built.with_context(|| {
        format!("pinning an aws-nitro prover needs --expect-pcrs <file>, write it with {MEASURE}")
    })?;
    if live != built {
        bail!("live PCR0 to PCR2 differ from --expect-pcrs, refusing to pin");
    }
    Ok(())
}

fn read_pcrs(path: &Path) -> Result<NitroMeasurement> {
    let json = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_pcrs(&json).with_context(|| format!("reading {}", path.display()))
}

fn parse_pcrs(json: &str) -> Result<NitroMeasurement> {
    let file: serde_json::Value = serde_json::from_str(json)?;
    // The parent's measurements.json carries the same PCR names without a source.
    if file.get("source").and_then(serde_json::Value::as_str) != Some("measure") {
        bail!("the PCR file is not {MEASURE} output");
    }
    let pcr = |name: &str| -> Result<[u8; 48]> {
        let value = file
            .get(name)
            .and_then(serde_json::Value::as_str)
            .with_context(|| format!("{name} is missing"))?;
        hex::FromHex::from_hex(value).with_context(|| format!("{name} is not 48 bytes of hex"))
    };
    Ok(NitroMeasurement {
        pcr0: pcr("PCR0")?,
        pcr1: pcr("PCR1")?,
        pcr2: pcr("PCR2")?,
    })
}

fn new_dstack(found: &DstackIdentity, hpke_public_key: [u8; 32]) -> DstackPolicy {
    DstackPolicy {
        app_id: found.app_id,
        hpke_public_key,
        key_provider_id: found.key_provider.id.clone(),
        os_image_hashes: Vec::new(),
        measurements: Vec::new(),
        compose_hashes: Vec::new(),
        tcb_statuses: vec!["UpToDate".into()],
    }
}

fn fetch_attestation(prover_url: &Url) -> Result<Attestation> {
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
    let mut body = Vec::new();
    response
        .take(MAX_ATTESTATION_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|e| anyhow::anyhow!("attestation read failed, {}", e.kind()))?;
    if body.len() > MAX_ATTESTATION_BYTES {
        bail!("attestation exceeds {MAX_ATTESTATION_BYTES} bytes");
    }
    serde_json::from_slice(&body).context("attestation is malformed")
}

fn push_new<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn write_pins(root: &Path, policy: TeePolicy) -> Result<()> {
    let file = serde_json::to_string_pretty(&TeePolicyFile {
        deployment: Some(policy),
    })?;
    fs::write(root.join(RUST_POLICY), format!("{file}\n"))?;
    let ts = format!(
        "/** Mirrors `{RUST_POLICY}`, kept equal by a test. */\nexport const DEFAULT_TEE_POLICY_FILE: Readonly<{{ deployment: unknown }}> = Object.freeze({file});\n",
    );
    fs::write(root.join(TS_POLICY), ts)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measurement(pcr2: u8) -> NitroMeasurement {
        NitroMeasurement {
            pcr0: [1; 48],
            pcr1: [2; 48],
            pcr2: [pcr2; 48],
        }
    }

    #[test]
    fn a_nitro_pin_needs_the_built_pcrs_and_their_match() {
        let live = measurement(3);
        assert!(matches_build(&live, None).is_err());
        assert!(matches_build(&live, Some(&measurement(4))).is_err());
        assert!(matches_build(&live, Some(&measurement(3))).is_ok());
    }

    #[test]
    fn the_pcr_file_keeps_pcr0_to_pcr2_and_ignores_the_rest() {
        let mut file = serde_json::json!({
            "source": "measure",
            "HashAlgorithm": "Sha384 { ... }",
            "PCR0": "01".repeat(48),
            "PCR1": "02".repeat(48),
            "PCR2": "03".repeat(48),
            "nitro_cli": "1.4.2",
        });
        assert_eq!(parse_pcrs(&file.to_string()).unwrap(), measurement(3));
        file["source"] = "parent".into();
        assert!(parse_pcrs(&file.to_string()).is_err());
        file.as_object_mut().unwrap().remove("source");
        assert!(parse_pcrs(&file.to_string()).is_err());
        file["source"] = "measure".into();
        file["PCR2"] = "03".repeat(47).into();
        assert!(parse_pcrs(&file.to_string()).is_err());
        file.as_object_mut().unwrap().remove("PCR2");
        assert!(parse_pcrs(&file.to_string()).is_err());
    }
}
