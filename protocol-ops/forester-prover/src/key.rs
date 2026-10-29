use crate::{error::Result, Error};
use serde::Deserialize;
use spr_tree::nullifier_tree::verify::verifying_keys::PROVING_KEY_SHA256S;

pub struct ProvingKeyReport {
    pub keys: usize,
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
struct KeyStatus {
    name: String,
    artifacts: Vec<Artifact>,
}
#[derive(Deserialize)]
struct Artifact {
    format: String,
    sha256: String,
    size: u64,
    url: String,
}
#[derive(Deserialize)]
struct Keys {
    keys: Vec<KeyStatus>,
}
pub(crate) fn check_report(value: serde_json::Value) -> Result<ProvingKeyReport> {
    let report: Keys = serde_json::from_value(value)?;
    let invalid = || Error::Prover("invalid /proving-keys catalog".into());
    let mut names = std::collections::HashSet::new();
    let mut mismatches = Vec::new();
    for key in &report.keys {
        if !names.insert(&key.name)
            || key.name.len() <= 4
            || !key.name.ends_with(".key")
            || key.name.contains("..")
            || !key
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
        {
            return Err(invalid());
        }
        let mut formats = std::collections::HashSet::new();
        let mut gnark = None;
        for artifact in &key.artifacts {
            let url = url::Url::parse(&artifact.url).map_err(|_| invalid())?;
            if !matches!(artifact.format.as_str(), "gnark" | "zopro")
                || !formats.insert(&artifact.format)
                || artifact.sha256.len() != 64
                || !artifact
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || artifact.size == 0
                || artifact.size > 9_007_199_254_740_991
                || !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(invalid());
            }
            if artifact.format == "gnark" {
                gnark = Some(&artifact.sha256);
            }
        }
        let gnark = gnark.ok_or_else(invalid)?;
        if let Some((_, digest)) = PROVING_KEY_SHA256S
            .iter()
            .find(|(name, _)| *name == key.name)
        {
            if *gnark != hex::encode(digest) {
                mismatches.push(key.name.clone());
            }
        }
    }
    if !mismatches.is_empty() {
        return Err(Error::ProverProvingKeysMismatch { mismatches });
    }
    Ok(ProvingKeyReport {
        keys: report.keys.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_catalog_contract() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/proving_key_catalog.json"
        ))
        .unwrap();
        assert_eq!(check_report(vectors["catalog"].clone()).unwrap().keys, 2);
        for case in vectors["invalidCatalogs"].as_array().unwrap() {
            assert!(
                check_report(case["catalog"].clone()).is_err(),
                "accepted {}",
                case["description"]
            );
        }
    }
}
