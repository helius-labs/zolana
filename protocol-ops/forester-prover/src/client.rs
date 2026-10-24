use crate::{
    error::Result,
    indexed::{IndexedBatchRequest, ProofDataSource, ProvenIndexedBatch},
    key::{check_report, ExpectedProvingKey, ProvingKeyReport},
    proof, BatchAddressAppendInputs, Error,
};
use reqwest::{blocking::Client, redirect::Policy, StatusCode};
use serde_json::Value;
use std::{
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};
use url::Url;

pub struct ProverClient {
    backend: Backend,
    source: ProofDataSource,
}
enum Backend {
    Remote {
        endpoint: String,
        http: Client,
    },
    #[cfg(feature = "native")]
    Local(crate::native::LocalProver),
}
impl ProverClient {
    pub fn new(endpoint: String) -> Result<Self> {
        let http = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(600))
            .build()
            .map_err(http_error)?;
        Ok(Self {
            backend: Backend::Remote { endpoint, http },
            source: ProofDataSource::Prover,
        })
    }
    pub fn local(keys: PathBuf) -> Result<Self> {
        Self::local_with_scratch(keys, std::env::temp_dir().join("zolana-forester-prover"))
    }
    pub fn local_with_scratch(keys: PathBuf, scratch: PathBuf) -> Result<Self> {
        #[cfg(feature = "native")]
        {
            Ok(Self {
                backend: Backend::Local(crate::native::LocalProver::new(keys, scratch)),
                source: ProofDataSource::Client,
            })
        }
        #[cfg(not(feature = "native"))]
        {
            Err(Error::Prover(format!(
                "local proving at {} with scratch {} requires the native feature",
                keys.display(),
                scratch.display()
            )))
        }
    }
    pub fn with_proof_data_source(mut self, source: ProofDataSource) -> Self {
        if matches!(self.backend, Backend::Remote { .. }) {
            self.source = source;
        }
        self
    }
    pub fn proof_data_source(&self) -> ProofDataSource {
        self.source
    }
    pub fn check_proving_keys(&self) -> Result<ProvingKeyReport> {
        match &self.backend {
            Backend::Remote { .. } => check_report(self.get("/proving-keys")?),
            #[cfg(feature = "native")]
            Backend::Local(_) => Ok(ProvingKeyReport {
                prefix: "local (key digests checked on load)".into(),
            }),
        }
    }
    pub fn check_indexed(&self) -> Result<()> {
        if self.get("/health")?.get("indexed").and_then(Value::as_bool) != Some(true) {
            return Err(Error::ProverIndexerUnconfigured);
        }
        Ok(())
    }
    pub fn prove_indexed(&self, request: &IndexedBatchRequest) -> Result<ProvenIndexedBatch> {
        let key = request.proving_key()?;
        let value = self.send(&request.body()?, &key, true)?;
        let batch_proof = proof::decode(&value, &key)?;
        let resolution = value
            .get("resolution")
            .or_else(|| value.get("proof").and_then(|proof| proof.get("resolution")))
            .ok_or_else(|| Error::ProofParse("indexed response has no resolution".into()))?;
        request.finish(batch_proof, resolution.clone())
    }
    pub fn prove_batch_address_append(
        &self,
        inputs: &BatchAddressAppendInputs,
    ) -> Result<zolana_interface::instruction::NullifierTreeProof> {
        let key = ExpectedProvingKey::batch_address_append(inputs.tree_height, inputs.batch_size)?;
        let verified = match &self.backend {
            Backend::Remote { .. } => {
                let body = serde_json::to_string(&inputs.to_json())?;
                proof::decode(&self.send(&body, &key, false)?, &key)?.compress()?
            }
            #[cfg(feature = "native")]
            Backend::Local(local) => local
                .prove(&key, inputs)
                .map_err(|error| Error::Prover(format!("{error:#}")))?
                .compress()?,
        };
        let hash = proof::coordinate(&inputs.public_input_hash.to_str_radix(16))?;
        proof::verify(&verified, hash, inputs.batch_size)?;
        Ok(verified)
    }
    fn remote(&self) -> Result<(&str, &Client)> {
        match &self.backend {
            Backend::Remote { endpoint, http } => Ok((endpoint, http)),
            #[cfg(feature = "native")]
            Backend::Local(_) => Err(Error::Prover(
                "indexed HTTP calls are unavailable for local proving".into(),
            )),
        }
    }
    fn url(&self, path: &str) -> Result<Url> {
        endpoint_url(self.remote()?.0, path)
    }
    fn get(&self, path: &str) -> Result<Value> {
        let (_, http) = self.remote()?;
        let response = http
            .get(self.url(path)?)
            .timeout(Duration::from_secs(30))
            .send()
            .map_err(http_error)?;
        let status = response.status();
        let body: Value = response.json().map_err(http_error)?;
        if !status.is_success() {
            return Err(failure(status, &body));
        }
        Ok(body)
    }
    fn send(&self, body: &str, key: &ExpectedProvingKey, indexed: bool) -> Result<Value> {
        let (_, http) = self.remote()?;
        let gateway = is_gateway(self.remote()?.0);
        if gateway && indexed {
            return Err(Error::ProverIndexerUnconfigured);
        }
        let mut path = if gateway {
            "/prove".into()
        } else {
            key.prove_path()
        };
        if indexed {
            path.push_str("/indexed");
        }
        let url = self.url(&path)?;
        let mut attempt = 0;
        let response = loop {
            attempt += 1;
            let response = http
                .post(url.clone())
                .header("X-Async", "true")
                .header("Content-Type", "application/json")
                .body(body.to_owned())
                .send();
            match response {
                Err(error) if error.is_connect() && attempt < 3 => {
                    thread::sleep(Duration::from_secs(2))
                }
                Ok(response)
                    if response.status() == StatusCode::TOO_MANY_REQUESTS && attempt < 3 =>
                {
                    thread::sleep(Duration::from_secs(2))
                }
                other => break other.map_err(http_error)?,
            }
        };
        let status = response.status();
        let value: Value = response.json().map_err(http_error)?;
        if !status.is_success() {
            return Err(failure(status, &value));
        }
        if value.get("proof").is_none() {
            if let Some(job) = value.get("jobId").and_then(Value::as_str) {
                return self.poll(job, key, gateway);
            }
        }
        Ok(value)
    }
    fn poll(&self, job: &str, key: &ExpectedProvingKey, gateway: bool) -> Result<Value> {
        let (_, http) = self.remote()?;
        let path = if gateway {
            "/prove".into()
        } else {
            key.prove_path()
        };
        let mut url = self.url(&format!("{path}/status"))?;
        url.query_pairs_mut().append_pair("jobId", job);
        let started = Instant::now();
        let mut interval = Duration::from_millis(25);
        let max_wait = Duration::from_secs(1200);
        loop {
            let remaining = max_wait
                .checked_sub(started.elapsed())
                .ok_or_else(|| Error::ProverServer("batch proof polling timed out".into()))?;
            match http
                .get(url.clone())
                .timeout(remaining.min(Duration::from_secs(30)))
                .send()
            {
                Ok(response) => {
                    let status = response.status();
                    let body = response.json::<Value>();
                    if status.is_client_error() {
                        return Err(failure(status, &body.map_err(http_error)?));
                    }
                    if status.is_success() {
                        let value = body.map_err(http_error)?;
                        match value.get("status").and_then(Value::as_str) {
                            Some("completed") => {
                                return Ok(value.get("result").unwrap_or(&value).clone())
                            }
                            Some("failed") => return Err(failure(status, &value)),
                            _ => {}
                        }
                    }
                }
                Err(error) if !error.is_connect() && !error.is_timeout() && !error.is_body() => {
                    return Err(http_error(error))
                }
                Err(_) => {}
            }
            thread::sleep(interval.min(max_wait.saturating_sub(started.elapsed())));
            interval = (interval * 2).min(Duration::from_secs(3));
        }
    }
}
fn endpoint_url(base: &str, path: &str) -> Result<Url> {
    let mut url = Url::parse(base).map_err(|_| Error::Prover("invalid prover URL".into()))?;
    url.path_segments_mut()
        .map_err(|_| Error::Prover("invalid prover URL".into()))?
        .pop_if_empty()
        .extend(path.split('/').filter(|part| !part.is_empty()));
    Ok(url)
}
fn is_gateway(base: &str) -> bool {
    Url::parse(base).ok().is_some_and(|url| {
        url.path().trim_end_matches('/') == "/v1/zolana"
            && url
                .host_str()
                .is_some_and(|host| host == "helius-rpc.com" || host.ends_with(".helius-rpc.com"))
    })
}
fn failure(status: StatusCode, value: &Value) -> Error {
    match value.get("code").and_then(Value::as_str) {
        Some("indexer_not_ready") => Error::IndexerProofDataNotReady,
        Some("indexer_unconfigured") => Error::ProverIndexerUnconfigured,
        _ => Error::ProverServer(format!("status {status}: {value}")),
    }
}
fn http_error(mut error: reqwest::Error) -> Error {
    if let Some(url) = error.url_mut() {
        redact_in_place(url);
    }
    Error::ProverServer(error.to_string())
}
pub fn redact_api_key(text: &str) -> String {
    match Url::parse(text) {
        Ok(mut url) => {
            redact_in_place(&mut url);
            url.into()
        }
        Err(_) => "invalid URL".into(),
    }
}
fn redact_in_place(url: &mut Url) {
    let query = url
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
    if !query.is_empty() {
        url.query_pairs_mut().clear().extend_pairs(query);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexed::BatchAnchor;
    use solana_address::Address;
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    fn server(responses: Vec<(&'static str, u16, Value)>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}?api-key=secret", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            for (expected, status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut request_bytes = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let count = stream.read(&mut chunk).unwrap();
                    assert_ne!(count, 0, "request ended before its headers");
                    request_bytes.extend_from_slice(&chunk[..count]);
                    if let Some(end) = request_bytes
                        .windows(4)
                        .position(|bytes| bytes == b"\r\n\r\n")
                    {
                        let headers = String::from_utf8_lossy(&request_bytes[..end]);
                        let size = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .and_then(|value| value.parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if request_bytes.len() >= end + 4 + size {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(request_bytes).unwrap();
                assert!(
                    request.starts_with(expected),
                    "unexpected request: {request}"
                );
                if expected.starts_with("POST") {
                    assert!(request.to_ascii_lowercase().contains("x-async: true"));
                }
                let body = body.to_string();
                write!(stream, "HTTP/1.1 {status} test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        (endpoint, handle)
    }
    fn request() -> IndexedBatchRequest {
        IndexedBatchRequest {
            previous_batches: vec![],
            tree: Address::new_from_array([4; 32]),
            tree_height: 40,
            batch_size: 10,
            start_index: 1,
            anchor: BatchAnchor {
                next_index: 1,
                root: [0; 32],
            },
            leaves_hash_chain: [0; 32],
        }
    }
    #[test]
    fn queued_indexed_proof_polls_its_key_route_and_rejects_wrong_key() {
        let point = serde_json::json!(["0x1", "0x2"]);
        let proof = serde_json::json!({"ar": point, "bs": [point, point], "krs": point, "provingKeySha256": "wrong"});
        let (endpoint, handle) = server(vec![
            (
                "POST /prove/batch_address-append_40_10/indexed?api-key=secret ",
                202,
                serde_json::json!({"jobId":"job/1"}),
            ),
            (
                "GET /prove/batch_address-append_40_10/status?api-key=secret&jobId=job%2F1 ",
                503,
                serde_json::json!({"error":"busy"}),
            ),
            (
                "GET /prove/batch_address-append_40_10/status?api-key=secret&jobId=job%2F1 ",
                200,
                serde_json::json!({"status":"completed", "result":{"proof":proof}}),
            ),
        ]);
        let proof_attempt = ProverClient::new(endpoint)
            .unwrap()
            .prove_indexed(&request());
        assert!(matches!(
            proof_attempt,
            Err(Error::ProvingKeyMismatch { .. })
        ));
        handle.join().unwrap();
    }
    #[test]
    fn typed_indexer_lag_is_preserved_for_watch_retries() {
        let (endpoint, handle) = server(vec![(
            "POST /prove/batch_address-append_40_10/indexed?api-key=secret ",
            409,
            serde_json::json!({"code":"indexer_not_ready"}),
        )]);
        assert!(matches!(
            ProverClient::new(endpoint)
                .unwrap()
                .prove_indexed(&request()),
            Err(Error::IndexerProofDataNotReady)
        ));
        handle.join().unwrap();
    }
    #[test]
    fn urls_preserve_gateway_queries_and_mask_credentials() {
        let url = endpoint_url(
            "https://prover.example/v1/zolana?api-key=secret&region=eu",
            "/prove/batch_address-append_40_10",
        )
        .unwrap();
        assert_eq!(redact_api_key(url.as_str()), "https://prover.example/v1/zolana/prove/batch_address-append_40_10?api-key=redacted&region=eu");
    }
    #[test]
    fn proving_key_startup_check_rejects_stale_batch_keys() {
        let (endpoint, handle) = server(vec![(
            "GET /proving-keys?api-key=secret ",
            200,
            serde_json::json!({"prefix":"old", "keys":[{"name":"batch_address-append_40_10.key", "expectedSha256":"00", "loadedSha256":null}]}),
        )]);
        assert!(matches!(
            ProverClient::new(endpoint).unwrap().check_proving_keys(),
            Err(Error::ProverProvingKeysMismatch { .. })
        ));
        handle.join().unwrap();
    }
}
