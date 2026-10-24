use crate::{error::Result, Error};
use serde::Deserialize;
use zolana_tree::nullifier_tree::verify::verifying_keys::PROVING_KEY_SHA256S;

pub struct ProvingKeyReport {
    pub prefix: String,
}
#[derive(Clone)]
pub(crate) struct ExpectedProvingKey {
    pub name: String,
    pub sha256: [u8; 32],
}
impl ExpectedProvingKey {
    pub fn batch_address_append(height: u32, batch: u32) -> Result<Self> {
        let name = format!("batch_address-append_{height}_{batch}.key");
        let sha256 = PROVING_KEY_SHA256S
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, digest)| *digest)
            .ok_or_else(|| Error::Prover(format!("unsupported batch shape {height}x{batch}")))?;
        Ok(Self { name, sha256 })
    }
    pub fn prove_path(&self) -> String {
        format!("/prove/{}", self.name.trim_end_matches(".key"))
    }
    pub fn check(&self, reported: Option<&str>) -> Result<()> {
        if reported != Some(hex::encode(self.sha256).as_str()) {
            return Err(Error::ProvingKeyMismatch {
                key: self.name.clone(),
                expected: hex::encode(self.sha256),
                reported: reported.unwrap_or("missing").to_owned(),
            });
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyStatus {
    name: String,
    expected_sha256: Option<String>,
    loaded_sha256: Option<String>,
}
#[derive(Deserialize)]
struct Keys {
    prefix: String,
    keys: Vec<KeyStatus>,
}
pub(crate) fn check_report(value: serde_json::Value) -> Result<ProvingKeyReport> {
    let report: Keys = serde_json::from_value(value)?;
    let mut mismatches = Vec::new();
    for (name, digest) in PROVING_KEY_SHA256S {
        if let Some(status) = report.keys.iter().find(|status| status.name == *name) {
            for reported in [&status.expected_sha256, &status.loaded_sha256]
                .into_iter()
                .flatten()
            {
                if *reported != hex::encode(digest) {
                    mismatches.push(format!("{name}: {reported}"));
                }
            }
        }
    }
    if !mismatches.is_empty() {
        return Err(Error::ProverProvingKeysMismatch { mismatches });
    }
    Ok(ProvingKeyReport {
        prefix: report.prefix,
    })
}
