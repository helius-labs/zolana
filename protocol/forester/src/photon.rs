//! The queue-only Photon client used by protocol maintenance.
use anyhow::{bail, Context, Result};
use reqwest::{blocking::Client, redirect::Policy};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use solana_address::Address;
use std::time::Duration;

pub const PAGE_LIMIT: u64 = 1000;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hash(pub [u8; 32]);
impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let mut hash = [0; 32];
        let count = bs58::decode(encoded)
            .onto(&mut hash)
            .map_err(serde::de::Error::custom)?;
        if count != hash.len() {
            return Err(serde::de::Error::custom("queue hash must be 32 bytes"));
        }
        Ok(Self(hash))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NullifierQueueElement {
    pub seq: u64,
    pub value: Hash,
}
#[derive(Deserialize)]
pub struct QueueElements {
    pub elements: Vec<NullifierQueueElement>,
}
pub struct PhotonClient {
    endpoint: String,
    http: Client,
}
impl PhotonClient {
    pub fn new(endpoint: String) -> Result<Self> {
        let http = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { endpoint, http })
    }
    pub fn get_nullifier_queue_elements(
        &self,
        tree: Address,
        start: Option<u64>,
        limit: u64,
    ) -> Result<QueueElements> {
        if !(1..=PAGE_LIMIT).contains(&limit) {
            bail!("queue page limit must be 1..={PAGE_LIMIT}");
        }
        let body = json!({"jsonrpc":"2.0", "id":1, "method":"getNullifierQueueElements", "params":{"treeAccount":tree.to_string(),"startSeq":start.unwrap_or_default(),"limit":limit}});
        let response = self
            .http
            .post(&self.endpoint)
            .json(&body)
            .send()
            .map_err(scrub)?
            .error_for_status()
            .map_err(scrub)?;
        let value: Value = response.json().map_err(scrub)?;
        if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || value.get("id") != Some(&json!(1))
        {
            bail!("invalid Photon JSON-RPC envelope");
        }
        if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
            bail!("Photon queue request failed: {error}");
        }
        serde_json::from_value(
            value
                .get("result")
                .cloned()
                .context("Photon response has no result")?,
        )
        .context("decode queued nullifiers")
    }
}
fn scrub(mut error: reqwest::Error) -> reqwest::Error {
    if let Some(url) = error.url_mut() {
        let pairs = url
            .query_pairs()
            .map(|(name, value)| {
                let value = if name == "api-key" {
                    "redacted".into()
                } else {
                    value.into_owned()
                };
                (name.into_owned(), value)
            })
            .collect::<Vec<_>>();
        if !pairs.is_empty() {
            url.query_pairs_mut().clear().extend_pairs(pairs);
        }
    }
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        thread,
    };

    fn serve(expected_request: Value, response: Value) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            let mut content_length = 0;
            loop {
                line.clear();
                assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
                if let Some(length) = line.to_ascii_lowercase().strip_prefix("content-length: ") {
                    content_length = length.trim().parse().unwrap();
                }
            }
            let mut request_bytes = vec![0; content_length];
            reader.read_exact(&mut request_bytes).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&request_bytes).unwrap(),
                expected_request
            );
            let response_json = response.to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_json}", response_json.len()).unwrap();
        });
        (endpoint, worker)
    }
    #[test]
    fn queue_request_matches_photon_contract_and_decodes_base58_values() {
        let tree = Address::new_unique();
        let expected = json!({"jsonrpc":"2.0", "id":1, "method":"getNullifierQueueElements", "params":{"treeAccount":tree.to_string(), "startSeq":7, "limit":10}});
        let response = json!({"jsonrpc":"2.0", "id":1, "result":{"context":{"slot":123}, "elements":[{"seq":7, "value":bs58::encode([7;32]).into_string()}]}});
        let (endpoint, worker) = serve(expected, response);
        let fetched = PhotonClient::new(endpoint)
            .unwrap()
            .get_nullifier_queue_elements(tree, Some(7), 10)
            .unwrap();
        assert_eq!(
            fetched.elements,
            vec![NullifierQueueElement {
                seq: 7,
                value: Hash([7; 32])
            }]
        );
        worker.join().unwrap();
    }
    #[test]
    fn invalid_queue_hashes_are_rejected_instead_of_padded() {
        for value in [
            "0".to_owned(),
            bs58::encode([1; 31]).into_string(),
            bs58::encode([1; 33]).into_string(),
        ] {
            let decoded =
                serde_json::from_value::<NullifierQueueElement>(json!({"seq":1,"value":value}));
            assert!(decoded.is_err());
        }
    }
}
