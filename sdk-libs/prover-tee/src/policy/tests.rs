use std::{fs, time::Duration};

use serde_json::{json, Value};

use super::*;

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../prover/tee/testdata/policy_cases.json"
);
const DEPLOYMENTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../prover/tee/deployments");
const KEY: &str = "6316a7bc6187cd6f3e7fd7d95809e3ee23c610e8f4472b474f719dcb6365ce33";

fn deployment(file: &str) -> Value {
    serde_json::from_str::<Value>(file).unwrap()["deployment"].take()
}

fn dstack() -> Value {
    deployment(include_str!(
        "../../../../prover/tee/testdata/live_policy.json"
    ))
}

fn nitro() -> Value {
    deployment(include_str!(
        "../../../../prover/tee/testdata/nitro_live_policy.json"
    ))
}

fn edited(mut policy: Value, change: impl FnOnce(&mut Value)) -> Value {
    change(&mut policy);
    policy
}

/// `policy` with the pin at `pointer` in uppercase.
fn uppercase(policy: Value, pointer: &str) -> Value {
    edited(policy, |policy| {
        let pin = policy.pointer_mut(pointer).unwrap();
        let upper = pin.as_str().unwrap().to_uppercase();
        assert_ne!(*pin, upper, "{pointer} holds no letter");
        *pin = upper.into();
    })
}

fn case(name: &str, policy: Value, expect: &str) -> Value {
    json!({ "name": name, "policy": policy, "expect": expect })
}

fn cases() -> Vec<Value> {
    let max_age = |secs: Value| edited(nitro(), |policy| policy["max_age_secs"] = secs);
    let keyed = || edited(nitro(), |policy| policy["hpke_public_key"] = KEY.into());
    let positional = |policy: Value, fields: &[&str]| {
        edited(policy, |policy| {
            let entry = &mut policy["measurements"][0];
            let values: Value = fields.iter().map(|field| entry[field].take()).collect();
            *entry = values;
        })
    };
    let mut cases = vec![
        case("a dstack-tdx policy", dstack(), "accept"),
        case("an aws-nitro policy", nitro(), "accept"),
        case("an aws-nitro policy that pins its key", keyed(), "accept"),
        case("a max age of one second", max_age(1.into()), "accept"),
        case(
            "a max age of 2^53 - 1 seconds",
            max_age(MAX_INTEGER.into()),
            "accept",
        ),
        case("a max age of zero", max_age(0.into()), "reject"),
        case(
            "a max age of 2^53 seconds",
            max_age((MAX_INTEGER + 1).into()),
            "reject",
        ),
        case(
            "a max age of 2^64 - 1 seconds",
            max_age(u64::MAX.into()),
            "reject",
        ),
        case("a negative max age", max_age((-1).into()), "reject"),
        case("a fractional max age", max_age(1.5.into()), "reject"),
        case(
            "a pin with one uppercase digit",
            edited(nitro(), |policy| {
                let pin = &mut policy["measurements"][0]["pcr0"];
                *pin = pin.as_str().unwrap().replacen('e', "E", 1).into();
            }),
            "reject",
        ),
        case(
            "an aws-nitro measurement as a positional array",
            positional(nitro(), &["pcr0", "pcr1", "pcr2"]),
            "reject",
        ),
        case(
            "a dstack-tdx measurement as a positional array",
            positional(dstack(), &["mrtd", "rtmr0", "rtmr1", "rtmr2"]),
            "reject",
        ),
    ];
    for pointer in [
        "/app_id",
        "/hpke_public_key",
        "/key_provider_id",
        "/os_image_hashes/0",
        "/measurements/0/mrtd",
        "/measurements/0/rtmr0",
        "/measurements/0/rtmr1",
        "/measurements/0/rtmr2",
        "/compose_hashes/0",
    ] {
        let name = format!("an uppercase dstack-tdx pin at {pointer}");
        cases.push(case(&name, uppercase(dstack(), pointer), "reject"));
    }
    for pointer in [
        "/measurements/0/pcr0",
        "/measurements/0/pcr1",
        "/measurements/0/pcr2",
        "/hpke_public_key",
    ] {
        let name = format!("an uppercase aws-nitro pin at {pointer}");
        cases.push(case(&name, uppercase(keyed(), pointer), "reject"));
    }
    cases
}

#[test]
fn policy_vectors() {
    let generated = json!({
        "note": "Whether a client accepts each bare policy, alone or as a pin file's deployment. Regenerate with UPDATE_VECTORS=1 cargo test -p spr-prover-tee policy_vectors.",
        "cases": cases(),
    });
    if std::env::var("UPDATE_VECTORS").as_deref() == Ok("1") {
        let mut text = serde_json::to_string_pretty(&generated).unwrap();
        text.push('\n');
        fs::write(VECTORS_PATH, text).unwrap();
    }
    let vectors: Value = serde_json::from_str(&fs::read_to_string(VECTORS_PATH).unwrap()).unwrap();
    assert_eq!(vectors, generated, "regenerate with UPDATE_VECTORS=1");

    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let bare = case["policy"].to_string();
        let pinned = json!({ "deployment": case["policy"] }).to_string();
        for parsed in [
            TeePolicy::from_json(&bare),
            TeePolicy::from_file_json(&bare),
            TeePolicy::from_file_json(&pinned),
        ] {
            match case["expect"].as_str().unwrap() {
                "accept" => {
                    let policy = parsed.unwrap_or_else(|e| panic!("{name}: {e}"));
                    let written = serde_json::to_value(&policy).unwrap();
                    assert_eq!(written, case["policy"], "{name}");
                }
                _ => assert!(
                    matches!(parsed, Err(TeeError::Policy(_))),
                    "{name} gave {parsed:?}"
                ),
            }
        }
    }
}

#[test]
fn a_built_policy_takes_a_max_age_from_one_second_to_2_53_minus_1() {
    let policy = || TeePolicy::from_json(&nitro().to_string()).unwrap();
    for secs in [1, 600, MAX_INTEGER] {
        let built = policy().with_max_age(Duration::from_secs(secs)).unwrap();
        assert_eq!(built.max_age(), Duration::from_secs(secs));
    }
    for max_age in [
        Duration::ZERO,
        Duration::from_millis(999),
        Duration::from_secs(MAX_INTEGER + 1),
        Duration::MAX,
    ] {
        assert!(matches!(
            policy().with_max_age(max_age),
            Err(TeeError::Policy(_))
        ));
    }
}

/// Every pin file a release wrote still loads; a measurement record is not a pin file.
#[test]
fn every_published_deployment_loads() {
    let mut loaded = 0;
    for entry in fs::read_dir(DEPLOYMENTS).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if name.ends_with("-measurements.json") {
            continue;
        }
        let pin = fs::read_to_string(&path).unwrap();
        TeePolicy::from_file_json(&pin).unwrap_or_else(|e| panic!("{name}: {e}"));
        loaded += 1;
    }
    assert!(loaded >= 8, "{loaded} pin files");
}
