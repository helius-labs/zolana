mod support;

use reqwest::blocking::Client;
use serde_json::Value;
use std::{
    fs::{self, OpenOptions},
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zolana_forester_prover::ProverClient;

struct ProverServer {
    child: Child,
    endpoint: String,
    http: Client,
    log: PathBuf,
}

impl ProverServer {
    fn start() -> Self {
        let binary = std::env::var_os("FORESTER_TEST_PROVER_BIN")
            .expect("set FORESTER_TEST_PROVER_BIN to the Go prover binary");
        let keys = std::env::var_os("FORESTER_TEST_KEYS_DIR").expect("set FORESTER_TEST_KEYS_DIR");
        let redis = std::env::var("FORESTER_TEST_REDIS_URL")
            .expect("set FORESTER_TEST_REDIS_URL to an isolated test Redis database");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let metrics = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let metrics_address = metrics.local_addr().unwrap();
        let log = std::env::temp_dir().join(format!(
            "forester-redis-proof-{}-{}.log",
            std::process::id(),
            address.port()
        ));
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&log)
            .unwrap();
        let stderr = output.try_clone().unwrap();
        let http = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        drop((listener, metrics));
        let child = Command::new(binary)
            .arg("start")
            .arg("--keys-dir")
            .arg(keys)
            .args(["--redis-url", &redis])
            .args(["--serve", "batch_address-append_40_10"])
            .args(["--circuit", "address-append-test"])
            .args(["--preload-circuits", "address-append-test"])
            .args(["--prover-address", &address.to_string()])
            .args(["--metrics-address", &metrics_address.to_string()])
            .env("PROVER_MAX_CONCURRENCY", "1")
            .env_remove("QUEUE_MODE")
            .env_remove("SERVER_MODE")
            .stdout(Stdio::from(output))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("start Redis-backed batch prover");
        let mut server = Self {
            child,
            endpoint: format!("http://{address}"),
            http,
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            assert!(
                server.child.try_wait().unwrap().is_none(),
                "batch prover exited before becoming ready"
            );
            if server
                .http
                .get(format!("{}/ready", server.endpoint))
                .send()
                .is_ok_and(|response| response.status().is_success())
            {
                return server;
            }
            assert!(
                Instant::now() < deadline,
                "batch prover did not become ready"
            );
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn completed_results(&self) -> u64 {
        let stats: Value = self
            .http
            .get(format!("{}/queue/stats", self.endpoint))
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .unwrap();
        let queues = stats["queues"].as_object().unwrap();
        assert_eq!(
            (
                queues.contains_key("zk_address_append_queue"),
                queues.contains_key("zk_address_append_processing_queue"),
            ),
            (true, true),
            "Redis exposes the batch pending and processing queues"
        );
        queues["zk_results_queue"].as_u64().unwrap()
    }
}

impl Drop for ProverServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if thread::panicking() {
            if let Ok(log) = fs::read_to_string(&self.log) {
                eprintln!("Redis batch prover log:\n{log}");
            }
        }
        let _ = fs::remove_file(&self.log);
    }
}

#[test]
#[ignore = "requires the Go prover binary, pinned 40x10 key, and isolated Redis database"]
fn redis_batch_proof() {
    let server = ProverServer::start();
    let before = server.completed_results();
    // Distinct public inputs avoid reusing Redis results from an earlier test run.
    let first_value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let inputs = support::batch_inputs(first_value);
    let prover = ProverClient::new(server.endpoint.clone()).unwrap();
    let proof = prover.prove_batch_address_append(&inputs).unwrap();
    support::assert_batch_proof(&inputs, &proof);
    assert_eq!(
        server.completed_results(),
        before + 1,
        "a new proof must complete through the Redis worker"
    );
}
