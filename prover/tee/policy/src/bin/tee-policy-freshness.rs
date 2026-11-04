//! The Lambda that keeps one network's TEE policy in force: each run publishes
//! the release part with a freshness part issued now (`spr_tee_policy::freshness`).
//!
//! Environment: NETWORK, BUCKET, KEY_ID (the network's freshness KMS key),
//! FRESHNESS_SECONDS and METRICS_NAMESPACE, where each run records
//! ReleaseDaysLeft; the missing-run alarm watches that metric.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_cloudwatch::types::{MetricDatum, StandardUnit};
use lambda_runtime::{service_fn, LambdaEvent};
use serde_json::{json, Value};
use spr_tee_policy::{
    freshness::{Freshener, S3Store},
    kms::KmsSigner,
    pins,
};

fn env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("set {name}"))
}

#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let network = env("NETWORK")?;
    let (signers, _) = pins::pinned(&network)?;
    let freshener = Freshener {
        store: S3Store {
            client: aws_sdk_s3::Client::new(&config),
            bucket: env("BUCKET")?,
        },
        signer: KmsSigner::new(aws_sdk_kms::Client::new(&config), env("KEY_ID")?).await?,
        network,
        signers,
        lifetime_secs: env("FRESHNESS_SECONDS")?
            .parse()
            .context("FRESHNESS_SECONDS")?,
    };
    let namespace = env("METRICS_NAMESPACE")?;
    let cloudwatch = aws_sdk_cloudwatch::Client::new(&config);
    let (freshener, namespace, cloudwatch) = (&freshener, &namespace, &cloudwatch);
    lambda_runtime::run(service_fn(move |_: LambdaEvent<Value>| async move {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let published = freshener.publish(now).await?;
        let days_left = published.release_expires_at.saturating_sub(now) as f64 / 86_400.0;
        cloudwatch
            .put_metric_data()
            .namespace(namespace)
            .metric_data(
                MetricDatum::builder()
                    .metric_name("ReleaseDaysLeft")
                    .value(days_left)
                    .unit(StandardUnit::None)
                    .build(),
            )
            .send()
            .await
            .context("record ReleaseDaysLeft")?;
        Ok::<_, lambda_runtime::Error>(json!({
            "network": freshener.network,
            "release_version": published.release_version,
            "expires_at": published.expires_at,
        }))
    }))
    .await
}
