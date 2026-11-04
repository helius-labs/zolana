use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use super::*;

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../prover/tee/testdata/signed_policy.json"
);
const NOW: u64 = 1_800_000_000;
const RELEASE_EXPIRES_AT: u64 = 1_900_000_000;
const ISSUED_AT: u64 = NOW - 3_600;
const MAX_LIFETIME: u64 = 3 * 86_400;
const FRESH_UNTIL: u64 = ISSUED_AT + MAX_LIFETIME;
/// Release keys of seeds 1 to 3, two of them per release.
const RELEASE_SEEDS: [u8; 3] = [1, 2, 3];
/// Freshness keys of seeds 5 and 6 the release names, one of them per freshness part.
const FRESHNESS_SEEDS: [u8; 2] = [5, 6];
/// Not pinned in either role.
const UNPINNED: u8 = 4;

/// The identity point with y = p + 1, past the field prime.
const NON_CANONICAL_Y: &str = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
/// The identity point with its x sign bit set.
const NEGATIVE_ZERO: &str = "0100000000000000000000000000000000000000000000000000000000000080";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(seed: u8) -> String {
    hex::encode(key(seed).verifying_key().as_bytes())
}

fn release(version: u64, expires_at: u64) -> Value {
    json!({
        "network": "fixture",
        "version": version,
        "expires_at": expires_at,
        "freshness": {
            "public_keys": FRESHNESS_SEEDS.map(public),
            "threshold": 1,
            "max_lifetime_secs": MAX_LIFETIME,
        },
        "policy": {
            "platform": "aws-nitro",
            "measurements": [{
                "pcr0": "e452a98072521751e8fa434d796fbd782d3dcf5f2d90db110b57b6c8ffe27b424ad3a65dd555fd7eaaf2b66802dcc43b",
                "pcr1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
                "pcr2": "ef81b17ada922b489c73604f2caa6f883486bda34c4f621401f096df591c6737b234798663d19b40178c725e231de386",
            }],
            "gpu": "optional",
            "max_age_secs": 600,
        },
    })
}

fn bytes(payload: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(payload).unwrap();
    bytes.push(b'\n');
    bytes
}

fn freshness_of(release: &[u8], version: u64) -> Value {
    serde_json::to_value(FreshnessPayload::of(
        release,
        version,
        "fixture",
        ISSUED_AT,
        FRESH_UNTIL,
    ))
    .unwrap()
}

fn part(domain: &[u8], payload: &[u8], seeds: &[u8]) -> Value {
    let keys: Vec<_> = seeds.iter().map(|&seed| key(seed)).collect();
    serde_json::to_value(SignedPart::sign(domain, payload, &keys)).unwrap()
}

/// A release signed by `release_seeds` and its freshness signed by `freshness_seeds`.
fn file_of(
    release: &Value,
    release_seeds: &[u8],
    freshness: &Value,
    freshness_seeds: &[u8],
) -> Value {
    json!({
        "release": part(RELEASE_DOMAIN, &bytes(release), release_seeds),
        "freshness": part(FRESHNESS_DOMAIN, &bytes(freshness), freshness_seeds),
    })
}

/// A file every client accepts, with `change` applied to its release payload
/// before signing; the freshness part binds the changed release.
fn with_release(change: impl FnOnce(&mut Value)) -> Value {
    let mut payload = release(2, RELEASE_EXPIRES_AT);
    change(&mut payload);
    let version = payload["version"].as_u64().unwrap_or(2);
    let freshness = freshness_of(&bytes(&payload), version);
    file_of(&payload, &[1, 2], &freshness, &[5])
}

/// A file every client accepts, with `change` applied to its freshness payload before signing.
fn with_freshness(change: impl FnOnce(&mut Value)) -> Value {
    let payload = release(2, RELEASE_EXPIRES_AT);
    let mut freshness = freshness_of(&bytes(&payload), 2);
    change(&mut freshness);
    file_of(&payload, &[1, 2], &freshness, &[5])
}

/// A file whose release names `change`d freshness signers, its freshness signed by `seeds`.
fn with_signers(change: impl FnOnce(&mut Value), seeds: &[u8]) -> Value {
    let mut payload = release(2, RELEASE_EXPIRES_AT);
    change(&mut payload["freshness"]);
    let freshness = freshness_of(&bytes(&payload), 2);
    file_of(&payload, &[1, 2], &freshness, seeds)
}

/// A freshness part issued at `issued_at` for a minute.
fn issued(issued_at: u64) -> impl FnOnce(&mut Value) {
    move |freshness| {
        freshness["issued_at"] = issued_at.into();
        freshness["expires_at"] = (issued_at + 60).into();
    }
}

fn accepted(name: &str, file: Value, expires_at: u64) -> Value {
    json!({ "name": name, "file": file, "version": 2, "expires_at": expires_at })
}

fn refused_case(name: &str, file: Value, error: &str) -> Value {
    json!({ "name": name, "file": file, "error": error })
}

fn cases() -> Vec<Value> {
    let good = || with_release(|_| ());
    let payload = release(2, RELEASE_EXPIRES_AT);
    let freshness = freshness_of(&bytes(&payload), 2);
    let edit = |change: &dyn Fn(&mut Value)| {
        let mut file = good();
        change(&mut file);
        file
    };
    vec![
        accepted("two of three release signers", good(), FRESH_UNTIL),
        accepted(
            "every release signer and an unpinned key",
            file_of(&payload, &[1, 2, 3, UNPINNED], &freshness, &[5]),
            FRESH_UNTIL,
        ),
        accepted(
            "the other freshness key",
            file_of(&payload, &[1, 3], &freshness, &[6]),
            FRESH_UNTIL,
        ),
        accepted(
            "freshness signers the release names in place of the earlier ones",
            with_signers(
                |signers| signers["public_keys"] = json!([public(UNPINNED)]),
                &[UNPINNED],
            ),
            FRESH_UNTIL,
        ),
        accepted(
            "freshness issued as far ahead as the clock skew allows",
            with_freshness(issued(NOW + MAX_CLOCK_SKEW_SECS)),
            NOW + MAX_CLOCK_SKEW_SECS + 60,
        ),
        accepted(
            "a release that expires before its freshness",
            with_release(|release| release["expires_at"] = (NOW + 60).into()),
            NOW + 60,
        ),
        refused_case(
            "one release signer",
            file_of(&payload, &[1], &freshness, &[5]),
            "signature",
        ),
        refused_case(
            "one release signer listed twice",
            file_of(&payload, &[1, 1], &freshness, &[5]),
            "signature",
        ),
        refused_case(
            "a release key that signed another payload",
            edit(&|file| {
                let other = part(
                    RELEASE_DOMAIN,
                    &bytes(&release(3, RELEASE_EXPIRES_AT)),
                    &[2],
                );
                let second = file["release"]["signatures"]
                    .get_mut(1)
                    .expect("the good file carries two release signatures");
                *second = other["signatures"][0].clone();
            }),
            "signature",
        ),
        refused_case(
            "an unpinned key completing the release quorum",
            file_of(&payload, &[1, UNPINNED], &freshness, &[5]),
            "signature",
        ),
        refused_case(
            "a freshness key completing the release quorum",
            file_of(&payload, &[1, 5], &freshness, &[5]),
            "signature",
        ),
        refused_case(
            "release signatures under the freshness domain",
            edit(&|file| {
                file["release"] = part(FRESHNESS_DOMAIN, &bytes(&payload), &[1, 2]);
            }),
            "signature",
        ),
        refused_case(
            "an altered release payload",
            edit(&|file| {
                let altered = bytes(&release(3, RELEASE_EXPIRES_AT));
                file["release"]["payload"] = hex::encode(&altered).into();
                file["freshness"] =
                    part(FRESHNESS_DOMAIN, &bytes(&freshness_of(&altered, 3)), &[5]);
            }),
            "signature",
        ),
        refused_case(
            "a release for another network",
            with_release(|release| release["network"] = "other".into()),
            "network",
        ),
        refused_case(
            "an expired release",
            with_release(|release| release["expires_at"] = NOW.into()),
            "expired",
        ),
        refused_case(
            "release version zero",
            with_release(|release| release["version"] = 0.into()),
            "malformed",
        ),
        refused_case(
            "a release version beyond a safe integer",
            with_release(|release| release["version"] = (MAX_INTEGER + 1).into()),
            "malformed",
        ),
        refused_case(
            "an unknown release field",
            with_release(|release| release["comment"] = "x".into()),
            "malformed",
        ),
        refused_case(
            "a release that names no freshness signers",
            with_release(|release| {
                release.as_object_mut().unwrap().remove("freshness");
            }),
            "malformed",
        ),
        refused_case(
            "an unknown freshness signers field",
            with_signers(|signers| signers["comment"] = "x".into(), &[5]),
            "malformed",
        ),
        refused_case(
            "a freshness threshold of zero",
            with_signers(|signers| signers["threshold"] = 0.into(), &[5]),
            "malformed",
        ),
        refused_case(
            "a freshness threshold above its keys",
            with_signers(|signers| signers["threshold"] = 3.into(), &[5, 6]),
            "malformed",
        ),
        refused_case(
            "a repeated freshness key",
            with_signers(
                |signers| signers["public_keys"] = json!([public(5), public(5)]),
                &[5],
            ),
            "malformed",
        ),
        refused_case(
            "an uppercase freshness key",
            with_signers(
                |signers| signers["public_keys"] = json!([public(5).to_uppercase()]),
                &[5],
            ),
            "malformed",
        ),
        refused_case(
            "a freshness key that is not an Ed25519 point",
            with_signers(
                |signers| {
                    signers["public_keys"] = json!([format!("02{}", "00".repeat(31))]);
                },
                &[5],
            ),
            "malformed",
        ),
        refused_case(
            "a non-canonical freshness key beside a valid one",
            with_signers(
                |signers| signers["public_keys"] = json!([public(5), NON_CANONICAL_Y]),
                &[5],
            ),
            "malformed",
        ),
        refused_case(
            "a negative zero freshness key beside a valid one",
            with_signers(
                |signers| signers["public_keys"] = json!([public(5), NEGATIVE_ZERO]),
                &[5],
            ),
            "malformed",
        ),
        refused_case(
            "a zero freshness lifetime",
            with_signers(|signers| signers["max_lifetime_secs"] = 0.into(), &[5]),
            "malformed",
        ),
        refused_case(
            "a deployment wrapper as the policy",
            with_release(|release| {
                let policy = release["policy"].take();
                release["policy"] = json!({ "deployment": policy });
            }),
            "malformed",
        ),
        refused_case(
            "an unknown policy field",
            with_release(|release| release["policy"]["comment"] = "x".into()),
            "malformed",
        ),
        refused_case(
            "a zero max age",
            with_release(|release| release["policy"]["max_age_secs"] = 0.into()),
            "malformed",
        ),
        refused_case(
            "uppercase release payload hex",
            edit(&|file| {
                let upper = file["release"]["payload"].as_str().unwrap().to_uppercase();
                file["release"]["payload"] = upper.into();
            }),
            "malformed",
        ),
        refused_case(
            "uppercase freshness payload hex",
            edit(&|file| {
                let upper = file["freshness"]["payload"]
                    .as_str()
                    .unwrap()
                    .to_uppercase();
                file["freshness"]["payload"] = upper.into();
            }),
            "malformed",
        ),
        refused_case(
            "an unknown file field",
            edit(&|file| file["comment"] = "x".into()),
            "malformed",
        ),
        refused_case(
            "an unknown part field",
            edit(&|file| file["freshness"]["comment"] = "x".into()),
            "malformed",
        ),
        refused_case(
            "no freshness part",
            edit(&|file| {
                file.as_object_mut().unwrap().remove("freshness");
            }),
            "malformed",
        ),
        refused_case(
            "an unsigned freshness part",
            file_of(&payload, &[1, 2], &freshness, &[]),
            "freshness",
        ),
        refused_case(
            "freshness signed by a release key",
            file_of(&payload, &[1, 2], &freshness, &[3]),
            "freshness",
        ),
        refused_case(
            "freshness signed by a key the release no longer names",
            with_signers(|signers| signers["public_keys"] = json!([public(6)]), &[5]),
            "freshness",
        ),
        refused_case(
            "one freshness signer of a threshold of two",
            with_signers(|signers| signers["threshold"] = 2.into(), &[5]),
            "freshness",
        ),
        refused_case(
            "freshness signed by an unpinned key",
            file_of(&payload, &[1, 2], &freshness, &[UNPINNED]),
            "freshness",
        ),
        refused_case(
            "freshness signatures under the release domain",
            edit(&|file| {
                file["freshness"] = part(RELEASE_DOMAIN, &bytes(&freshness), &[5]);
            }),
            "freshness",
        ),
        refused_case(
            "an altered freshness payload",
            edit(&|file| {
                let mut later = freshness.clone();
                later["expires_at"] = (FRESH_UNTIL + 86_400).into();
                file["freshness"]["payload"] = hex::encode(bytes(&later)).into();
            }),
            "freshness",
        ),
        refused_case(
            "freshness for another network",
            with_freshness(|freshness| freshness["network"] = "other".into()),
            "freshness",
        ),
        refused_case(
            "freshness for another release version",
            with_freshness(|freshness| freshness["release_version"] = 1.into()),
            "freshness",
        ),
        refused_case(
            "freshness for another release payload",
            with_freshness(|freshness| {
                freshness["release_sha256"] = hex::encode(Sha256::digest(b"other")).into();
            }),
            "freshness",
        ),
        refused_case(
            "freshness naming the release hash in uppercase",
            with_freshness(|freshness| {
                let upper = freshness["release_sha256"].as_str().unwrap().to_uppercase();
                freshness["release_sha256"] = upper.into();
            }),
            "freshness",
        ),
        refused_case(
            "an unknown freshness field",
            with_freshness(|freshness| freshness["comment"] = "x".into()),
            "malformed",
        ),
        refused_case(
            "freshness issued at its expiry",
            with_freshness(|freshness| freshness["issued_at"] = FRESH_UNTIL.into()),
            "malformed",
        ),
        refused_case(
            "a freshness expiry beyond a safe integer",
            with_freshness(|freshness| freshness["expires_at"] = (MAX_INTEGER + 1).into()),
            "malformed",
        ),
        refused_case(
            "freshness longer than the release allows",
            with_freshness(|freshness| freshness["expires_at"] = (FRESH_UNTIL + 1).into()),
            "lifetime",
        ),
        refused_case(
            "freshness issued beyond the clock skew",
            with_freshness(issued(NOW + MAX_CLOCK_SKEW_SECS + 1)),
            "future",
        ),
        refused_case(
            "stale freshness",
            with_freshness(|freshness| freshness["expires_at"] = NOW.into()),
            "stale",
        ),
    ]
}

fn vectors() -> Value {
    json!({
        "note": "Test-only signers. Seed i is 32 bytes of value i; the pinned release keys are seeds 1 to 3, releases name seeds 5 and 6 as freshness keys, and seed 4 is in neither role. Regenerate with UPDATE_VECTORS=1 cargo test -p spr-prover-tee signed_policy_vectors.",
        "network": "fixture",
        "public_keys": RELEASE_SEEDS.map(public),
        "threshold": 2,
        "max_clock_skew_secs": MAX_CLOCK_SKEW_SECS,
        "now": NOW,
        "cases": cases(),
    })
}

fn signers(vectors: &Value) -> PolicySigners {
    let keys = vectors["public_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| fixed(key.as_str().unwrap()).unwrap())
        .collect();
    PolicySigners::new(
        vectors["network"].as_str().unwrap(),
        keys,
        vectors["threshold"].as_u64().unwrap() as usize,
    )
    .unwrap()
}

#[test]
fn signed_policy_vectors() {
    let generated = vectors();
    if std::env::var("UPDATE_VECTORS").as_deref() == Ok("1") {
        let mut text = serde_json::to_string_pretty(&generated).unwrap();
        text.push('\n');
        std::fs::write(VECTORS_PATH, text).unwrap();
    }
    let vectors: Value =
        serde_json::from_str(&std::fs::read_to_string(VECTORS_PATH).unwrap()).unwrap();
    assert_eq!(vectors, generated, "regenerate with UPDATE_VECTORS=1");

    let signers = signers(&vectors);
    let now = vectors["now"].as_u64().unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let file = serde_json::to_vec(&case["file"]).unwrap();
        match SignedPolicyFile::verify(&file, &signers, now) {
            Ok(verified) => {
                assert_eq!(
                    Some(verified.release.version),
                    case["version"].as_u64(),
                    "{name} verified"
                );
                assert_eq!(
                    Some(verified.expires_at()),
                    case["expires_at"].as_u64(),
                    "{name}"
                );
            }
            Err(TeeError::SignedPolicy(check)) => {
                assert_eq!(Some(check), case["error"].as_str(), "{name}")
            }
            Err(error) => panic!("{name}: {error}"),
        }
    }
}

#[test]
fn signers_refuse_a_threshold_they_cannot_meet_or_a_repeated_key() {
    let a = key(1).verifying_key().to_bytes();
    assert!(PolicySigners::new("n", vec![a], 2).is_err());
    assert!(PolicySigners::new("n", vec![a], 0).is_err());
    assert!(PolicySigners::new("n", vec![a, a], 1).is_err());
    assert!(PolicySigners::new("", vec![a], 1).is_err());
    for encoding in [NON_CANONICAL_Y, NEGATIVE_ZERO] {
        let key = fixed(encoding).unwrap();
        assert!(
            VerifyingKey::from_bytes(&key).is_ok(),
            "dalek alone reads {encoding}"
        );
        assert!(PolicySigners::new("n", vec![key], 1).is_err(), "{encoding}");
    }
    assert!(PolicySigners::new("n", vec![a], 1).is_ok());
}

#[test]
fn a_fixture_file_verifies() {
    let release: ReleasePayload = serde_json::from_value(release(2, RELEASE_EXPIRES_AT)).unwrap();
    let file = SignedPolicyFile::sign(
        &release,
        &[key(1), key(2)],
        (ISSUED_AT, FRESH_UNTIL),
        &[key(5)],
    )
    .unwrap();
    let signers = PolicySigners::new(
        "fixture",
        RELEASE_SEEDS
            .map(|s| key(s).verifying_key().to_bytes())
            .to_vec(),
        2,
    )
    .unwrap();
    let verified =
        SignedPolicyFile::verify(&serde_json::to_vec(&file).unwrap(), &signers, NOW).unwrap();
    assert_eq!(verified.release, release);
    assert_eq!(verified.expires_at(), FRESH_UNTIL);
}
