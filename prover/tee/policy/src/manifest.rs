//! The enclave measurements a zolana-infra release manifest serves.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use spr_prover_tee::TeePolicy;

const PRIMARY: &str = "tee-1";

/// The PCRs of every generation the manifest serves, in `nitro_serving` order.
pub fn measurements(manifest: &Value) -> Result<Vec<Value>> {
    let mut generations = manifest
        .get("nitro_generations")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if !generations.contains_key(PRIMARY) {
        if let Some(original) = manifest.get("nitro_measurements").filter(|v| !v.is_null()) {
            generations.insert(PRIMARY.into(), original.clone());
        }
    }
    let serving: Vec<String> = match manifest.get("nitro_serving").and_then(Value::as_array) {
        Some(names) if !names.is_empty() => names
            .iter()
            .map(|name| {
                name.as_str()
                    .map(str::to_owned)
                    .context("nitro_serving holds a non-string")
            })
            .collect::<Result<_>>()?,
        _ => vec![manifest
            .get("nitro_active_generation")
            .and_then(Value::as_str)
            .unwrap_or(PRIMARY)
            .to_owned()],
    };
    serving
        .iter()
        .map(|name| {
            let Some(record) = generations.get(name) else {
                bail!("nitro_serving names an unknown generation: {name}");
            };
            let mut pcrs = Map::new();
            for i in 0..3 {
                let pcr = record
                    .get(format!("PCR{i}"))
                    .and_then(Value::as_str)
                    .with_context(|| format!("{name} has no PCR{i}"))?;
                pcrs.insert(format!("pcr{i}"), pcr.to_lowercase().into());
            }
            Ok(Value::Object(pcrs))
        })
        .collect()
}

/// The aws-nitro policy of the generations the manifest serves.
pub fn policy(manifest: &Value, max_age_secs: u64) -> Result<TeePolicy> {
    let policy = json!({
        "platform": "aws-nitro",
        "measurements": measurements(manifest)?,
        "gpu": "optional",
        "max_age_secs": max_age_secs,
    });
    serde_json::from_value(policy)
        .context("the manifest's measurements are not an aws-nitro policy")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Value {
        json!({
            "nitro_measurements": { "PCR0": "A".repeat(96), "PCR1": "b".repeat(96), "PCR2": "c".repeat(96) },
            "nitro_generations": { "tee-2": { "PCR0": "d".repeat(96), "PCR1": "b".repeat(96), "PCR2": "e".repeat(96) } },
            "nitro_active_generation": "tee-2",
            "nitro_serving": ["tee-1", "tee-2"],
        })
    }

    #[test]
    fn the_serving_generations_in_order() {
        let pcr0: Vec<_> = measurements(&manifest())
            .unwrap()
            .iter()
            .map(|m| m["pcr0"].clone())
            .collect();
        assert_eq!(pcr0, [json!("a".repeat(96)), json!("d".repeat(96))]);
        policy(&manifest(), 600).unwrap();
    }

    #[test]
    fn serving_defaults_to_the_active_generation() {
        let mut manifest = manifest();
        manifest.as_object_mut().unwrap().remove("nitro_serving");
        let pcr0: Vec<_> = measurements(&manifest)
            .unwrap()
            .iter()
            .map(|m| m["pcr0"].clone())
            .collect();
        assert_eq!(pcr0, [json!("d".repeat(96))]);
    }

    #[test]
    fn an_unknown_generation_is_refused() {
        let mut manifest = manifest();
        manifest["nitro_serving"] = json!(["tee-9"]);
        assert!(measurements(&manifest).is_err());
    }
}
