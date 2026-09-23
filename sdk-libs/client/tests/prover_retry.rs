//! A prover without a queue sheds queued requests with a 429; the client retries them.

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

use serde_json::{json, Value};
use zeroize::Zeroizing;
use zolana_client::{
    prover::{AsyncProverClient, Delivery, ProveRequest, ProverClient},
    ClientError,
};

struct InResponseRequest;

impl ProveRequest for InResponseRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        Ok(Zeroizing::new("{}".to_string()))
    }

    fn delivery(&self) -> Delivery {
        Delivery::InResponse
    }
}

fn shed_then_proof() -> Vec<(u16, Value)> {
    let zero = "0x0";
    let proof =
        json!({ "ar": [zero, zero], "bs": [[zero, zero], [zero, zero]], "krs": [zero, zero] });
    vec![
        (429, json!({ "code": "prover_busy" })),
        (429, json!({ "code": "prover_busy" })),
        (200, json!({ "proof": proof })),
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

#[test]
fn a_proof_shed_by_a_prover_without_a_queue_is_retried() {
    let (url, server) = serve(shed_then_proof());
    ProverClient::new(url)
        .prove(&InResponseRequest)
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
        .prove(&InResponseRequest)
        .await
        .expect("a busy prover should be retried, not failed");
    assert_eq!(
        server.join().expect("mock prover thread"),
        ["/prove", "/prove", "/prove"]
    );
}
