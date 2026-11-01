//! Test-only stdin driver for the real SDK transport through the local GK harness.
use super::*;
use crate::prover::tee::{Anchors, TeePolicyDocument, TeePolicyLoader};
use crate::prover::{known_proving_keys, verify_proof_statement};
use spr_interface::{verifying_keys::CircuitId, N_PUBLIC_SLOTS};
use std::io::{self, BufRead, Write};
use std::sync::Mutex;

const INPUTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../prover/server/prover/request/testdata/transfer-2x2.json"
));

fn verify(value: &serde_json::Value, wrong_statement: bool) -> bool {
    let (name, sha256) = known_proving_keys()
        .find(|(name, _)| *name == "transfer_confidential_2_2.key")
        .unwrap();
    let key = ExpectedProvingKey {
        name: name.into(),
        sha256,
    };
    let proof = proof_from_value(value, "fixture proof", &key).unwrap();
    let input: serde_json::Value = serde_json::from_str(INPUTS).unwrap();
    let mut hash: [u8; 32] = hex::decode(
        input["publicInputHash"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap()
    .try_into()
    .unwrap();
    if wrong_statement {
        hash[31] ^= 1;
    }
    let vk = CircuitId::ConfidentialSigner(2, 2, N_PUBLIC_SLOTS as u8)
        .verifying_key()
        .unwrap();
    verify_proof_statement(&proof, hash, vk).is_ok()
}

struct Policy(Arc<Mutex<serde_json::Value>>);
#[async_trait::async_trait]
impl TeePolicyLoader for Policy {
    async fn load(&self) -> Result<TeePolicyDocument, TeeError> {
        let value = self.0.lock().unwrap();
        Ok(TeePolicyDocument {
            policy_json: value.to_string(),
            valid_until: value["expires_at"].as_u64().unwrap(),
        })
    }
}

#[test]
#[ignore = "stdin protocol driven by tools/tee-fleet/gk-sdk-driver.mjs"]
fn gk_sdk_loopback() {
    let mut lines = io::stdin().lock().lines();
    let config: serde_json::Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    let url: Url = config["url"].as_str().unwrap().parse().unwrap();
    assert_eq!(url.scheme(), "http");
    assert_eq!(url.host_str(), Some("127.0.0.1"));
    let root: Vec<u8> = serde_json::from_value(config["root"].clone()).unwrap();
    let policy = Arc::new(Mutex::new(config["policy"].clone()));
    let source = Arc::new(TeePolicySource::new("fixture", Policy(policy.clone())));
    let mut client = ProverClient::new(url.to_string());
    client.client.tee = Tee::On(Box::new(
        TeeSession::source(source.clone()).with_test_anchors(Anchors {
            nitro: Box::leak(root.into_boxed_slice()),
            ..Anchors::PRODUCTION
        }),
    ));
    assert_eq!(config["body"].as_str().unwrap(), INPUTS);
    let endpoint = client.client.endpoint.url("/prove/sample").unwrap();
    for line in lines {
        let command: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let answer = match command["action"].as_str().unwrap() {
            "policy" => {
                *policy.lock().unwrap() = command["policy"].clone();
                source.expire_for_test();
                serde_json::json!({"updated": true})
            }
            "verify" => {
                serde_json::json!({"verified": verify(&command["proof"], command["wrong_statement"].as_bool().unwrap_or(false))})
            }
            "send" => {
                match client.runtime.block_on(client.client.post(
                    &endpoint,
                    INPUTS,
                    Delivery::InResponse,
                )) {
                    Ok((status, body)) if status.is_success() => {
                        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
                        assert!(verify(&body, false), "native proof verification failed");
                        serde_json::json!({"status": body["status"], "http_status": status.as_u16()})
                    }
                    Ok((status, _)) => serde_json::json!({"http_status": status.as_u16()}),
                    Err(ClientError::ProverOutcomeUnknown) => {
                        serde_json::json!({"outcome_unknown": true})
                    }
                    Err(error) => panic!("fixture SDK exchange failed: {error}"),
                }
            }
            _ => panic!("unknown fixture command"),
        };
        println!("{answer}");
        io::stdout().flush().unwrap();
    }
}
