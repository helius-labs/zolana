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
}
#[derive(Deserialize)]
struct Keys {
    keys: Vec<KeyStatus>,
}
pub(crate) fn check_report(value: serde_json::Value) -> Result<ProvingKeyReport> {
    let report: Keys = serde_json::from_value(value)?;
    let mut mismatches = Vec::new();
    for key in &report.keys {
        let Some((_, digest)) = PROVING_KEY_SHA256S
            .iter()
            .find(|(name, _)| *name == key.name)
        else {
            continue;
        };
        let mut gnark = key.artifacts.iter().filter(|a| a.format == "gnark");
        match (gnark.next(), gnark.next()) {
            (Some(artifact), None) => {
                if artifact.sha256 != hex::encode(digest) {
                    mismatches.push(key.name.clone());
                }
            }
            _ => {
                return Err(Error::Prover(format!(
                    "{} must have exactly one gnark artifact",
                    key.name
                )))
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
    fn reads_the_shared_catalog() {
        let catalog = serde_json::from_str(include_str!(
            "../../../test-vectors/proving_key_catalog.json"
        ))
        .unwrap();
        assert_eq!(check_report(catalog).unwrap().keys, 2);
    }

    #[test]
    fn known_keys_require_one_gnark_artifact() {
        for artifacts in [
            serde_json::json!([]),
            serde_json::json!([
                {"format":"gnark", "sha256":"a"}, {"format":"gnark", "sha256":"b"}
            ]),
        ] {
            assert!(matches!(
                check_report(serde_json::json!({"keys":[{
                    "name":"batch_address-append_40_10.key", "artifacts":artifacts
                }]})),
                Err(Error::Prover(_))
            ));
        }
    }
}
