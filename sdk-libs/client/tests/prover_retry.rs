//! The prover client against a mock prover: a prover without a queue sheds
//! queued requests with a 429 and the client retries them, and a gateway URL's
//! `api-key` rides on every request and stays out of error text.

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

use serde_json::{json, Value};
use zeroize::Zeroizing;
use zolana_client::{
    prover::{AsyncProverClient, Delivery, ExpectedProvingKey, ProveRequest, ProverClient},
    ClientError,
};

struct Request(Delivery);

const IN_RESPONSE: Request = Request(Delivery::InResponse);
const QUEUED: Request = Request(Delivery::Queued);

impl ProveRequest for Request {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        Ok(Zeroizing::new("{}".to_string()))
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

fn proof() -> Value {
    let zero = "0x0";
    json!({
        "ar": [zero, zero],
        "bs": [[zero, zero], [zero, zero]],
        "krs": [zero, zero],
        "provingKeySha256": "07".repeat(32),
    })
}

fn shed_then_proof() -> Vec<(u16, Value)> {
    vec![
        (429, json!({ "code": "prover_busy" })),
        (429, json!({ "code": "prover_busy" })),
        (200, json!({ "proof": proof() })),
    ]
}

fn queued_then_proof() -> Vec<(u16, Value)> {
    vec![
        (202, json!({ "jobId": "job-1", "status": "queued" })),
        (200, json!({ "status": "completed", "proof": proof() })),
    ]
}

/// Joining returns the requested paths.
fn serve(responses: Vec<(u16, Value)>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock prover");
    let url = format!(
        "http://{}",
        listener.local_addr().expect("mock prover address")
    );
    let server = thread::spawn(move || {
        responses
            .into_iter()
            .map(|(status, body)| {
                let (mut stream, _) = listener.accept().expect("accept a request");
                let path = read_request_path(&mut stream);
                let body = body.to_string();
                write!(
                    stream,
                    "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .expect("write the response");
                path
            })
            .collect()
    });
    (url, server)
}

fn read_request_path(stream: &mut impl Read) -> String {
    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = stream.read(&mut buffer).expect("read the request");
        assert_ne!(read, 0, "the client closed before sending a request");
        data.extend_from_slice(buffer.get(..read).expect("read length within the buffer"));
        let request = String::from_utf8_lossy(&data);
        if let Some((head, body)) = request.split_once("\r\n\r\n") {
            let length = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if body.len() >= length {
                return head
                    .split_whitespace()
                    .nth(1)
                    .expect("request path")
                    .to_string();
            }
        }
    }
}

/// Accepts every connection and closes it at once, so each request fails in
/// transport. It holds its port for the whole test, which a released port
/// would not: another test's server could take that and answer.
fn close_every_connection() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind closing listener");
    let url = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    thread::spawn(move || listener.incoming().for_each(drop));
    url
}

/// Answers once with a 200 whose body stops short of its Content-Length.
fn serve_truncated_body() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock prover");
    let url = format!(
        "http://{}",
        listener.local_addr().expect("mock prover address")
    );
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept a request");
        read_request_path(&mut stream);
        write!(
            stream,
            "HTTP/1.1 200 Mock\r\nContent-Type: application/json\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{{"
        )
        .expect("write the response");
    });
    url
}

fn gateway(base: &str, key: &str) -> String {
    format!("{base}/v1/zolana?api-key={key}")
}

const GATEWAY_PATHS: [&str; 2] = [
    "/v1/zolana/prove?api-key=test-key",
    "/v1/zolana/prove/status?api-key=test-key&jobId=job-1",
];

/// The failure is the one expected, and the key is not in its text.
fn assert_no_key(error: ClientError, expected: &str) -> String {
    let error = error.to_string();
    assert!(error.starts_with(expected), "unexpected error: {error}");
    assert!(!error.contains("secret-key"), "key leaked: {error}");
    error
}

/// As [`assert_no_key`], and the text still names the endpoint, key masked.
fn assert_key_masked(error: ClientError, expected: &str) {
    let error = assert_no_key(error, expected);
    assert!(error.contains("api-key=redacted"), "URL not kept: {error}");
}

#[test]
fn a_proof_shed_by_a_prover_without_a_queue_is_retried() {
    let (url, server) = serve(shed_then_proof());
    ProverClient::new(url)
        .prove(&IN_RESPONSE)
        .expect("a busy prover should be retried, not failed");
    assert_eq!(
        server.join().expect("mock prover thread"),
        ["/prove", "/prove", "/prove"]
    );
}

#[tokio::test]
async fn async_client_retries_a_proof_shed_by_a_prover_without_a_queue() {
    let (url, server) = serve(shed_then_proof());
    AsyncProverClient::new(url)
        .prove(&IN_RESPONSE)
        .await
        .expect("a busy prover should be retried, not failed");
    assert_eq!(
        server.join().expect("mock prover thread"),
        ["/prove", "/prove", "/prove"]
    );
}

// The key used to ride inside the path (`...?api-key=<key>/prove`), and the
// gateway answered every proof 401. A queued proof has to carry it on both the
// submission and each status poll.
#[test]
fn a_gateway_key_rides_on_every_request() {
    let (url, server) = serve(queued_then_proof());
    ProverClient::new(gateway(&url, "test-key"))
        .prove(&QUEUED)
        .expect("proof through the gateway");
    assert_eq!(server.join().expect("mock prover thread"), GATEWAY_PATHS);
}

#[tokio::test]
async fn async_client_sends_a_gateway_key_on_every_request() {
    let (url, server) = serve(queued_then_proof());
    AsyncProverClient::new(gateway(&url, "test-key"))
        .prove(&QUEUED)
        .await
        .expect("proof through the gateway");
    assert_eq!(server.join().expect("mock prover thread"), GATEWAY_PATHS);
}

#[test]
fn transport_errors_mask_the_gateway_key() {
    let client = ProverClient::new(gateway(&close_every_connection(), "secret-key"));
    assert_key_masked(
        client
            .check_proving_keys()
            .expect_err("the connection closes"),
        "prover server error: proving keys request failed",
    );
    assert_key_masked(
        client
            .prove(&IN_RESPONSE)
            .expect_err("every attempt closes"),
        "prover server error: request failed after",
    );
}

#[tokio::test]
async fn async_transport_errors_mask_the_gateway_key() {
    let client = AsyncProverClient::new(gateway(&close_every_connection(), "secret-key"));
    assert_key_masked(
        client
            .check_proving_keys()
            .await
            .expect_err("the connection closes"),
        "prover server error: proving keys request failed",
    );
    assert_key_masked(
        client
            .prove(&IN_RESPONSE)
            .await
            .expect_err("every attempt closes"),
        "prover server error: request failed after",
    );
}

// reqwest's body errors carry no URL today; the key stays out if that changes.
#[test]
fn body_read_errors_leave_the_gateway_key_out() {
    let client = ProverClient::new(gateway(&serve_truncated_body(), "secret-key"));
    assert_no_key(
        client
            .check_proving_keys()
            .expect_err("the body is cut short"),
        "prover server error: failed to read response body",
    );
}

#[tokio::test]
async fn async_body_read_errors_leave_the_gateway_key_out() {
    let client = AsyncProverClient::new(gateway(&serve_truncated_body(), "secret-key"));
    assert_no_key(
        client
            .check_proving_keys()
            .await
            .expect_err("the body is cut short"),
        "prover server error: failed to read response body",
    );
}
