use serde_json::{json, Map, Value};

use crate::classify::ErrorClass;

/// Phase timings of one attempt; `None` means the phase did not run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timings {
    pub sync_ms: Option<u64>,
    pub prove_ms: Option<u64>,
    pub send_ms: Option<u64>,
    pub confirm_ms: Option<u64>,
}

/// The outcome of one attempt, as one CloudWatch Embedded Metric Format record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub timestamp_ms: u64,
    pub total_ms: u64,
    pub timings: Timings,
    pub error_class: Option<ErrorClass>,
    pub signature: Option<String>,
}

impl Record {
    pub fn success(&self) -> bool {
        self.error_class.is_none()
    }

    /// One EMF JSON line, published without dimensions under `namespace`.
    pub fn to_emf(&self, namespace: &str) -> String {
        let mut metrics = vec![json!({"Name": "Success", "Unit": "Count"})];
        let mut fields = Map::new();
        fields.insert("Success".into(), json!(u8::from(self.success())));
        let mut add = |name: &str, value: Option<u64>| {
            if let Some(value) = value {
                metrics.push(json!({"Name": name, "Unit": "Milliseconds"}));
                fields.insert(name.into(), json!(value));
            }
        };
        add("TotalMs", Some(self.total_ms));
        add("SyncMs", self.timings.sync_ms);
        add("ProveMs", self.timings.prove_ms);
        add("SendMs", self.timings.send_ms);
        add("ConfirmMs", self.timings.confirm_ms);
        if let Some(class) = self.error_class {
            fields.insert("ErrorClass".into(), json!(class.as_str()));
        }
        if let Some(signature) = &self.signature {
            fields.insert("Signature".into(), json!(signature));
        }
        fields.insert(
            "_aws".into(),
            json!({
                "Timestamp": self.timestamp_ms,
                "CloudWatchMetrics": [{
                    "Namespace": namespace,
                    "Dimensions": [[]],
                    "Metrics": metrics,
                }],
            }),
        );
        Value::Object(fields).to_string()
    }

    /// The human summary line of this attempt.
    pub fn summary(&self, detail: &str) -> String {
        let phase = |name: &str, value: Option<u64>| {
            value.map_or(String::new(), |ms| format!(" {name}={ms}ms"))
        };
        let outcome = match self.error_class {
            None => "ok".to_string(),
            Some(class) => format!("fail class={}", class.as_str()),
        };
        let signature = self
            .signature
            .as_deref()
            .map_or(String::new(), |signature| format!(" signature={signature}"));
        let detail = if detail.is_empty() {
            String::new()
        } else {
            format!(" {detail}")
        };
        format!(
            "canary {outcome} total={}ms{}{}{}{}{signature}{detail}",
            self.total_ms,
            phase("sync", self.timings.sync_ms),
            phase("prove", self.timings.prove_ms),
            phase("send", self.timings.send_ms),
            phase("confirm", self.timings.confirm_ms),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> Value {
        assert!(!line.contains('\n'));
        serde_json::from_str(line).unwrap()
    }

    fn metric_names(record: &Value) -> Vec<(String, String)> {
        record["_aws"]["CloudWatchMetrics"][0]["Metrics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|metric| {
                (
                    metric["Name"].as_str().unwrap().to_string(),
                    metric["Unit"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn success_record_carries_every_measured_phase() {
        let record = Record {
            timestamp_ms: 1_700_000_000_000,
            total_ms: 4_200,
            timings: Timings {
                sync_ms: None,
                prove_ms: Some(1_500),
                send_ms: Some(200),
                confirm_ms: Some(2_500),
            },
            error_class: None,
            signature: Some("sig".into()),
        };
        let line = parse(&record.to_emf("spr/devnet/canary"));
        let directive = &line["_aws"]["CloudWatchMetrics"][0];
        assert_eq!(line["_aws"]["Timestamp"], 1_700_000_000_000u64);
        assert_eq!(directive["Namespace"], "spr/devnet/canary");
        assert_eq!(directive["Dimensions"], json!([[]]));
        assert_eq!(
            metric_names(&line),
            [
                ("Success", "Count"),
                ("TotalMs", "Milliseconds"),
                ("ProveMs", "Milliseconds"),
                ("SendMs", "Milliseconds"),
                ("ConfirmMs", "Milliseconds"),
            ]
            .map(|(name, unit)| (name.to_string(), unit.to_string()))
        );
        assert_eq!(line["Success"], 1);
        assert_eq!(line["TotalMs"], 4_200);
        assert_eq!(line["ProveMs"], 1_500);
        assert_eq!(line["SendMs"], 200);
        assert_eq!(line["ConfirmMs"], 2_500);
        assert!(line.get("SyncMs").is_none());
        assert!(line.get("ErrorClass").is_none());
        assert_eq!(line["Signature"], "sig");
    }

    #[test]
    fn failure_record_reports_zero_and_its_class() {
        let record = Record {
            timestamp_ms: 1,
            total_ms: 900,
            timings: Timings {
                sync_ms: Some(800),
                ..Timings::default()
            },
            error_class: Some(ErrorClass::Indexer),
            signature: None,
        };
        let line = parse(&record.to_emf("ns"));
        assert_eq!(line["Success"], 0);
        assert_eq!(line["SyncMs"], 800);
        assert_eq!(line["ErrorClass"], "indexer");
        assert_eq!(
            metric_names(&line),
            [
                ("Success", "Count"),
                ("TotalMs", "Milliseconds"),
                ("SyncMs", "Milliseconds"),
            ]
            .map(|(name, unit)| (name.to_string(), unit.to_string()))
        );
    }

    #[test]
    fn summary_is_one_line_with_the_class() {
        let record = Record {
            timestamp_ms: 1,
            total_ms: 46_000,
            timings: Timings {
                prove_ms: Some(1_000),
                send_ms: Some(100),
                ..Timings::default()
            },
            error_class: Some(ErrorClass::ConfirmTimeout),
            signature: Some("sig".into()),
        };
        assert_eq!(
            record.summary("not indexed"),
            "canary fail class=confirm_timeout total=46000ms prove=1000ms send=100ms signature=sig not indexed"
        );
    }
}
