use super::*;

const POLICY: &str = include_str!("../../prover/tee/testdata/probe_policy.json");

fn arguments(prover: &str) -> Vec<String> {
    [
        "--rpc",
        "http://127.0.0.1:8899",
        "--indexer",
        "http://127.0.0.1:8784",
        "--prover",
        prover,
        "--tree",
        "11111111111111111111111111111111",
        "--keypairs",
        "unused-wallet-directory",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn parse_with_policy(label: &str, json: &str) -> Result<Options> {
    let path = std::env::temp_dir().join(format!(
        "zolana-loadtest-policy-{}-{label}.json",
        std::process::id()
    ));
    fs::write(&path, json).unwrap();
    let mut args = arguments("https://prover.example/v1/zolana");
    args.extend(["--prover-tee-policy".into(), path.display().to_string()]);
    let result = Options::parse(args);
    fs::remove_file(path).unwrap();
    result
}

#[test]
fn supplied_bare_and_wrapped_policies_reach_the_loadtest_options() {
    let expected = TeePolicy::from_file_json(POLICY).unwrap();
    for (label, json) in [
        ("bare", POLICY.to_string()),
        ("wrapped", format!(r#"{{"deployment":{POLICY}}}"#)),
    ] {
        let options = parse_with_policy(label, &json).unwrap();
        assert_eq!(
            (options.prover_url.as_str(), options.prover_tee),
            ("https://prover.example/v1/zolana", Some(expected.clone())),
            "the supplied URL and policy must stay together"
        );
    }
}

#[test]
fn remote_provers_without_a_policy_fail_before_loading_wallets() {
    for prover in [
        "https://prover.example",
        "https://mainnet.helius-rpc.com/v1/zolana?api-key=fixture",
        "http://10.0.0.1:3001",
    ] {
        let error = Options::parse(arguments(prover)).err().unwrap();
        assert_eq!(
            error.to_string(),
            "--prover-tee-policy <file> is required for a remote prover"
        );
    }
}

#[test]
fn loopback_provers_allow_development_without_a_policy() {
    for prover in [
        "http://127.0.0.1:3001",
        "http://localhost:3001",
        "http://[::1]:3001",
    ] {
        assert_eq!(Options::parse(arguments(prover)).unwrap().prover_tee, None);
    }
}

#[test]
fn malformed_policy_files_fail_before_loading_wallets() {
    let error = parse_with_policy("malformed", "{}").err().unwrap();
    assert!(
        matches!(
            error.downcast_ref::<spr_client::prover::tee::TeeError>(),
            Some(spr_client::prover::tee::TeeError::Policy(_))
        ),
        "{error:#}"
    );
}

#[test]
fn absent_policy_files_fail_before_loading_wallets() {
    let path = std::env::temp_dir().join(format!(
        "zolana-loadtest-policy-{}-absent.json",
        std::process::id()
    ));
    let mut args = arguments("https://prover.example");
    args.extend(["--prover-tee-policy".into(), path.display().to_string()]);
    let error = Options::parse(args).err().unwrap();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
}
