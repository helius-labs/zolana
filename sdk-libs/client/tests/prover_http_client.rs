//! The prover clients send through any `zolana_api` HTTP client: a fake one
//! here, in place of a prover. It records what the clients send and answers
//! a proof in the response, a queued proof with its status polls, and the
//! proving-keys read, or fails as a custom client can.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use reqwest::{header::HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use zeroize::Zeroizing;
use zolana_api::{ApiError, BlockingHttpClient, HttpClient, HttpFuture, HttpRequest, HttpResponse};
use zolana_client::{
    prover::{
        known_proving_keys, AsyncProverClient, Delivery, ExpectedProvingKey, ProveRequest,
        ProverClient,
    },
    ClientError, Prover,
};

const PROVER_URL: &str = "https://gateway.invalid/v1/zolana?api-key=secret";
const PROVE_URL: &str = "https://gateway.invalid/v1/zolana/prove/test?api-key=secret";
const STATUS_URL: &str =
    "https://gateway.invalid/v1/zolana/prove/test/status?api-key=secret&jobId=job-1";
const PROVING_KEYS_URL: &str = "https://gateway.invalid/v1/zolana/proving-keys?api-key=secret";

struct Request(Delivery);

const IN_RESPONSE: Request = Request(Delivery::InResponse);
const QUEUED: Request = Request(Delivery::Queued);

impl ProveRequest for Request {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        Ok(Zeroizing::new(r#"{"inputs":1}"#.to_string()))
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        Ok(ExpectedProvingKey {
            name: "test.key".to_string(),
            sha256: [7u8; 32],
        })
    }

    fn delivery(&self) -> Delivery {
        self.0
    }
}

/// One scripted answer: a response, or a failure without one.
type Answer = Result<(u16, Value), Failure>;

#[derive(Debug)]
enum Failure {
    /// No response arrived.
    NoResponse(&'static str),
    /// The status arrived and the body was lost.
    BodyLost(&'static str),
}

/// Answers requests in the scripted order and records them.
#[derive(Debug)]
struct FakeClient {
    answers: Mutex<Vec<Answer>>,
    requests: Arc<Mutex<Vec<HttpRequest>>>,
}

impl FakeClient {
    fn answering(answers: Vec<Answer>) -> (Self, Arc<Mutex<Vec<HttpRequest>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let client = Self {
            answers: Mutex::new(answers.into_iter().rev().collect()),
            requests: requests.clone(),
        };
        (client, requests)
    }

    fn answer(&self, request: HttpRequest) -> Result<HttpResponse, ApiError> {
        self.requests.lock().unwrap().push(request);
        let answer = self
            .answers
            .lock()
            .unwrap()
            .pop()
            .expect("more requests than scripted answers");
        let (status, body) = answer.map_err(|failure| match failure {
            Failure::NoResponse(reason) => ApiError::HttpClient(reason.into()),
            Failure::BodyLost(reason) => ApiError::ResponseLost(reason.into()),
        })?;
        Ok(HttpResponse {
            status: StatusCode::from_u16(status).expect("a valid status"),
            headers: HeaderMap::new(),
            body: body.to_string().into_bytes(),
        })
    }
}

impl BlockingHttpClient for FakeClient {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, ApiError> {
        self.answer(request)
    }
}

impl HttpClient for FakeClient {
    fn send<'a>(&'a self, request: HttpRequest) -> HttpFuture<'a> {
        Box::pin(async move { self.answer(request) })
    }
}

fn proof() -> Value {
    let zero = "0x0";
    json!({
        "ar": [zero, zero],
        "bs": [[zero, zero], [zero, zero]],
        "krs": [zero, zero],
        "provingKeySha256": "07".repeat(32),
    })
}

fn proof_in_response() -> Vec<Answer> {
    vec![Ok((200, json!({ "proof": proof() })))]
}

fn queued_then_proof() -> Vec<Answer> {
    vec![
        Ok((202, json!({ "jobId": "job-1", "status": "queued" }))),
        Ok((200, json!({ "status": "processing" }))),
        Ok((
            200,
            json!({ "status": "completed", "result": { "proof": proof(), "proofDurationMs": 7 } }),
        )),
    ]
}

fn proving_keys() -> Vec<Answer> {
    let keys: Vec<Value> = known_proving_keys()
        .map(|(name, sha256)| {
            let hex: String = sha256.iter().map(|byte| format!("{byte:02x}")).collect();
            json!({
                "name": name,
                "expectedSha256": hex,
                "loadedSha256": null,
                "available": true,
            })
        })
        .collect();
    vec![Ok((
        200,
        json!({ "prefix": "proving-keys/test", "keys": keys }),
    ))]
}

fn header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

/// A proof `POST`: a JSON body on the key's proof path, the rail in a header
/// and the client's proof timeout on the request.
fn assert_proof_post(request: &HttpRequest, rail: &str) {
    assert_eq!(request.method, Method::POST);
    assert_eq!(request.url, PROVE_URL);
    assert_eq!(header(request, "content-type"), Some("application/json"));
    assert_eq!(header(request, rail), Some("true"));
    assert_eq!(request.body.as_slice(), br#"{"inputs":1}"#);
    assert_eq!(request.timeout, Some(Duration::from_secs(600)));
}

/// A status poll or a check: a bare `GET`, bounded on its own.
fn assert_get(request: &HttpRequest, url: &str) {
    assert_eq!(request.method, Method::GET);
    assert_eq!(request.url, url);
    assert!(request.body.is_empty());
    assert_eq!(request.timeout, Some(Duration::from_secs(30)));
}

fn assert_sync_route(requests: &[HttpRequest]) {
    assert_eq!(requests.len(), 1);
    assert_proof_post(&requests[0], "x-sync");
    assert_eq!(header(&requests[0], "x-async"), None);
}

fn assert_queued_route(requests: &[HttpRequest]) {
    assert_eq!(requests.len(), 3);
    assert_proof_post(&requests[0], "x-async");
    assert_eq!(header(&requests[0], "x-sync"), None);
    assert_get(&requests[1], STATUS_URL);
    assert_get(&requests[2], STATUS_URL);
}

#[test]
fn a_proof_in_the_response_goes_through_the_client() {
    let (client, requests) = FakeClient::answering(proof_in_response());
    ProverClient::with_client(PROVER_URL.to_string(), client)
        .prove(&IN_RESPONSE)
        .expect("the proof");
    assert_sync_route(&requests.lock().unwrap());
}

#[tokio::test]
async fn an_async_proof_in_the_response_goes_through_the_client() {
    let (client, requests) = FakeClient::answering(proof_in_response());
    AsyncProverClient::with_client(PROVER_URL.to_string(), client)
        .prove(&IN_RESPONSE)
        .await
        .expect("the proof");
    assert_sync_route(&requests.lock().unwrap());
}

#[test]
fn a_queued_proof_is_polled_through_the_client() {
    let (client, requests) = FakeClient::answering(queued_then_proof());
    ProverClient::with_client(PROVER_URL.to_string(), client)
        .prove(&QUEUED)
        .expect("the queued proof");
    assert_queued_route(&requests.lock().unwrap());
}

#[tokio::test]
async fn an_async_queued_proof_is_polled_through_the_client() {
    let (client, requests) = FakeClient::answering(queued_then_proof());
    AsyncProverClient::with_client(PROVER_URL.to_string(), client)
        .prove(&QUEUED)
        .await
        .expect("the queued proof");
    assert_queued_route(&requests.lock().unwrap());
}

#[test]
fn the_proving_keys_are_read_through_the_client() {
    let (client, requests) = FakeClient::answering(proving_keys());
    let report = ProverClient::with_client(PROVER_URL.to_string(), client)
        .check_proving_keys()
        .expect("a matching prover");
    assert_eq!(report.prefix, "proving-keys/test");
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_get(&requests[0], PROVING_KEYS_URL);
}

/// The client's answer is the prover's, whatever its status: a shed
/// in-response proof falls back to the queue, and the proof's reported key is
/// checked as it is from a `reqwest` client.
#[test]
fn the_client_answers_as_the_prover_does() {
    let mut shed_then_queued = vec![Ok((429, json!({ "code": "prover_busy" })))];
    shed_then_queued.extend(queued_then_proof());
    let (client, requests) = FakeClient::answering(shed_then_queued);
    ProverClient::with_client(PROVER_URL.to_string(), client)
        .prove(&IN_RESPONSE)
        .expect("the proof from the queue");
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert_proof_post(&requests[0], "x-sync");
    assert_queued_route(&requests[1..]);

    let mut other_key = proof();
    other_key["provingKeySha256"] = json!("08".repeat(32));
    let (client, _) = FakeClient::answering(vec![Ok((200, json!({ "proof": other_key })))]);
    assert!(matches!(
        ProverClient::with_client(PROVER_URL.to_string(), client).prove(&IN_RESPONSE),
        Err(ClientError::ProvingKeyMismatch { .. })
    ));
}

/// A client's failure is a transport failure: a proof submission is retried,
/// and a failed check is reported with the client's reason.
#[test]
fn a_client_failure_is_retried_and_reported() {
    let mut failed_then_proof = vec![Err(Failure::NoResponse("offline"))];
    failed_then_proof.extend(proof_in_response());
    let (client, requests) = FakeClient::answering(failed_then_proof);
    ProverClient::with_client(PROVER_URL.to_string(), client)
        .prove(&IN_RESPONSE)
        .expect("the proof on the second attempt");
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_proof_post(&requests[0], "x-sync");
    assert_proof_post(&requests[1], "x-sync");

    let (client, _) = FakeClient::answering(vec![Err(Failure::NoResponse("offline"))]);
    let error = ProverClient::with_client(PROVER_URL.to_string(), client)
        .check_proving_keys()
        .expect_err("the client fails");
    assert_eq!(
        error.to_string(),
        "prover server error: proving keys request failed: HTTP client error: offline"
    );
}

/// A custom client's failure names the URL, `api-key` and all; the key stays
/// out of the error on the check and on a proof that exhausts its retries.
#[test]
fn a_client_failure_keeps_the_api_key_out() {
    const FAILURE: &str = "connect error for https://gw/v1?api-key=SECRET";
    let failing = |count| {
        (0..count)
            .map(|_| Err(Failure::NoResponse(FAILURE)))
            .collect()
    };
    let (client, _) = FakeClient::answering(failing(1));
    let check = ProverClient::with_client(PROVER_URL.to_string(), client)
        .check_proving_keys()
        .expect_err("the client fails");
    let (client, _) = FakeClient::answering(failing(3));
    let proof = ProverClient::with_client(PROVER_URL.to_string(), client)
        .prove(&IN_RESPONSE)
        .expect_err("every attempt fails");
    for error in [check, proof] {
        let error = error.to_string();
        assert!(!error.contains("SECRET"), "{error}");
        assert!(error.contains("https://gw/v1?api-key=redacted"), "{error}");
    }
}

/// A body lost after the prover answered is not posted again: the prover has
/// the proof inputs and may be proving it.
#[test]
fn a_lost_proof_response_is_not_resubmitted() {
    let (client, requests) = FakeClient::answering(vec![Err(Failure::BodyLost("reset"))]);
    let error = ProverClient::with_client(PROVER_URL.to_string(), client)
        .prove(&IN_RESPONSE)
        .expect_err("the body is lost");
    assert_eq!(
        error.to_string(),
        "prover server error: failed to read response body: reset"
    );
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_proof_post(&requests[0], "x-sync");
}

#[tokio::test]
async fn an_async_lost_proof_response_is_not_resubmitted() {
    let (client, requests) = FakeClient::answering(vec![Err(Failure::BodyLost("reset"))]);
    let error = AsyncProverClient::with_client(PROVER_URL.to_string(), client)
        .prove(&IN_RESPONSE)
        .await
        .expect_err("the body is lost");
    assert_eq!(
        error.to_string(),
        "prover server error: failed to read response body: reset"
    );
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_proof_post(&requests[0], "x-sync");
}
