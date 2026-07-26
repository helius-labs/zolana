//! Rust-side oracle for the gnark proof parser (rows C08 and T23).
//!
//! Both rows are the same shape and both run against the usual direction of
//! this port. Nearly every divergence found so far was TypeScript refusing input
//! Rust accepts, and the standing answer is to relax TypeScript. Here TypeScript
//! is right twice and Rust was relaxed in ways that cannot be defended.
//!
//! C08: the rail was inferred from which fields the response carried, so an
//! eddsa request answered with a commitment-bearing proof was packed as
//! `TransactProof::P256`. That proof cannot verify against either verifying key,
//! so the permissiveness bought nothing and cost a baffling on-chain failure in
//! place of a parse error.
//!
//! T23: `hex_to_be_32` read several spellings of one number and one spelling of
//! a different one. It stripped `0x` repeatedly, discarded a minus sign,
//! substituted zero for an unparsable string, truncated an oversized value to
//! its low 32 bytes, and never checked the BN254 base modulus. Non-canonical
//! encodings let two byte strings mean one field element, which misleads
//! anything comparing bytes instead of values.
//!
//! The interesting inputs here are adversarial rather than typical, so the
//! oracle enumerates them: a coordinate at the modulus, just below, just above,
//! a doubled prefix, a negative, an unparsable string, and an oversized value.
//!
//! Regenerate with
//! `ZOLANA_UPDATE_TS_ORACLES=1 cargo test -p zolana-client --lib ts_proof_oracle`.

use std::path::PathBuf;

use serde_json::{json, Value};

use super::proof::proof_from_gnark_json;

/// `p - 1`, the largest legal coordinate.
const MAX_COORDINATE: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46";
/// `p`, the smallest illegal one.
const MODULUS: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
/// `p + 1`, congruent to 1 and therefore a second spelling of a legal value.
const ABOVE_MODULUS: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd48";

fn point(x: &str, y: &str) -> Value {
    json!([x, y])
}

/// A G1 point on the curve, so a rejection names the coordinate under test
/// rather than the curve equation.
fn valid_point() -> Value {
    point("0x0", "0x0")
}

/// The coordinate under test goes in `bs`, the G2 point. TypeScript checks that
/// a nonzero G1 point lies on the curve and Rust defers that to compression, so
/// putting an arbitrary value in `ar` would compare the curve check rather than
/// the coordinate parser. Neither side curve-checks G2.
fn proof_json(coordinate: &str, committed: bool) -> String {
    let mut body = json!({
        "ar": valid_point(),
        "bs": [point(coordinate, "0x0"), valid_point()],
        "krs": valid_point(),
    });
    if committed {
        body["proof_commitment"] = valid_point();
        body["proof_commitment_pok"] = valid_point();
    }
    body.to_string()
}

fn rail_json(committed: bool) -> String {
    proof_json("0x0", committed)
}

/// Every coordinate spelling worth arguing about, each as the X of `ar`.
fn coordinates() -> Vec<(&'static str, String)> {
    vec![
        ("zero", "0x0".to_string()),
        ("one", "0x1".to_string()),
        ("no prefix", "1".to_string()),
        ("uppercase prefix", "0X1".to_string()),
        ("uppercase digits", "0xAB".to_string()),
        ("full width", format!("0x{}", "0".repeat(63) + "1")),
        ("modulus minus one", format!("0x{MAX_COORDINATE}")),
        ("modulus", format!("0x{MODULUS}")),
        ("modulus plus one", format!("0x{ABOVE_MODULUS}")),
        ("all ones", format!("0x{}", "f".repeat(64))),
        ("doubled prefix", "0x0x1".to_string()),
        ("negative", "-1".to_string()),
        ("negative with prefix", "-0x1".to_string()),
        ("unparsable", "hello".to_string()),
        ("empty", String::new()),
        ("bare prefix", "0x".to_string()),
        ("oversized", format!("0x{}", "1".repeat(66))),
        ("leading space", " 0x1".to_string()),
        ("trailing space", "0x1 ".to_string()),
        ("underscore separator", "0x1_0".to_string()),
    ]
}

/// A rejection carries no detail beyond the refusal, so the recorded outcome is
/// the accepted bytes or nothing.
fn coordinate_case(name: &str, value: &str) -> Value {
    let parsed = proof_from_gnark_json(&proof_json(value, false), false);
    json!({
        "name": name,
        "value": value,
        "accepted": parsed.is_some(),
        // `bs` is stored as read, so an accepted coordinate is visible in the
        // first 32 bytes and a spelling that decoded to the wrong number shows up
        // here rather than only in the accept column.
        "b": parsed.map(|proof| hex(&proof.b)),
    })
}

/// The rail the caller asked for against the rail the response carries.
fn rail_case(requested_committed: bool, response_committed: bool) -> Value {
    let parsed = proof_from_gnark_json(&rail_json(response_committed), requested_committed);
    json!({
        "requestedCommitment": requested_committed,
        "responseCommitment": response_committed,
        "accepted": parsed.is_some(),
        "hasCommitment": parsed.map(|proof| proof.commitment.is_some()),
    })
}

/// One commitment field without the other. Rust reads both as
/// `#[serde(default)] Vec<String>` and decides presence on either being
/// non-empty, so a half-present commitment must fail on the pair rather than
/// silently drop one point.
fn half_commitment_case(name: &str, body: Value) -> Value {
    json!({
        "name": name,
        "body": body.to_string(),
        "accepted": proof_from_gnark_json(&body.to_string(), true).is_some(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn oracle_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../ts/client/test/oracles")
        .join("proof-canonical-v1.json")
}

#[test]
fn ts_proof_oracle_is_current() {
    let coordinate_cases: Vec<Value> = coordinates()
        .into_iter()
        .map(|(name, value)| coordinate_case(name, &value))
        .collect();

    let rail_cases: Vec<Value> = [(false, false), (false, true), (true, false), (true, true)]
        .into_iter()
        .map(|(requested, response)| rail_case(requested, response))
        .collect();

    let half_commitment_cases = vec![
        half_commitment_case(
            "commitment without its proof of knowledge",
            json!({
                "ar": valid_point(),
                "bs": [valid_point(), valid_point()],
                "krs": valid_point(),
                "proof_commitment": valid_point(),
            }),
        ),
        half_commitment_case(
            "proof of knowledge without its commitment",
            json!({
                "ar": valid_point(),
                "bs": [valid_point(), valid_point()],
                "krs": valid_point(),
                "proof_commitment_pok": valid_point(),
            }),
        ),
        half_commitment_case(
            "both fields explicitly empty",
            json!({
                "ar": valid_point(),
                "bs": [valid_point(), valid_point()],
                "krs": valid_point(),
                "proof_commitment": [],
                "proof_commitment_pok": [],
            }),
        ),
    ];

    let oracle = json!({
        "modulus": MODULUS,
        "coordinates": coordinate_cases,
        "rails": rail_cases,
        "halfCommitments": half_commitment_cases,
    });

    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&oracle).expect("render")
    );
    crate::prover::oracle_file::assert_oracle_current(&oracle_path(), &rendered);
}
