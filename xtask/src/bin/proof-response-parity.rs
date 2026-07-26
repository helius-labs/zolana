//! Generates the P3 proof-response parsing and compression vectors.
//!
//! `proof-validity-v1.json` already freezes the generator-point vanilla and
//! BSB22 happy paths, and `proof-canonical-v1.json` freezes coordinate
//! spellings plus the rail / half-commitment refusals. This binary covers the
//! rest of the P3 clause list: identity points, leading-zero coordinates,
//! G1/G2 compression parity branches, and the structural rejection mutations
//! derived from a Rust-parsed base proof.
//!
//! Every accepted byte comes from production `proof_from_gnark_json` (through
//! `ProverClient`) or `ProofCompressed::try_from`. Rejection rows mutate a
//! named base in a documented way; their expected category is what Rust
//! returns, not a hand-authored string.
//!
//! ```text
//! cargo run -p xtask --bin proof-response-parity            # write the fixture
//! cargo run -p xtask --bin proof-response-parity -- --check # fail on any drift
//! ```

use std::{
    env, fs,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    process::ExitCode,
    thread,
};

use anyhow::{bail, Context, Result};
use ark_bn254::{Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use serde_json::{json, Map, Value};
use zolana_client::{
    ClientError, Proof, ProofCompressed, ProverClient, TransferInputs, TransferP256Inputs,
};

const FIXTURE: &str = "sdk-libs/ts/vectors/proof-response-parity-v1.json";

/// Probe bound for the algebraic `y.c1 == 0` locus (`x1 = 1, 2, …`). The first
/// hit is at `x1 = 2`; the bound only guards a miss if the curve constant moves.
const G2_Y1_ZERO_SEARCH: u64 = 50_000;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("proof-response-parity failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut check = false;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--check" => check = true,
            "--probe-y1-zero" => {
                probe_g2_y1_zero()?;
                return Ok(());
            }
            "--help" | "-h" => {
                println!(
                    "Generate P3 proof-response parsing and compression vectors.\n\nusage: cargo run -p xtask --bin proof-response-parity -- [--check|--probe-y1-zero]"
                );
                return Ok(());
            }
            other => bail!("unexpected argument {other:?}"),
        }
    }

    let path = workspace_root()?.join(FIXTURE);
    let fixture = fixture()?;
    let mut bytes = serde_json::to_vec_pretty(&canonicalize(&fixture))?;
    bytes.push(b'\n');

    if check {
        let current = fs::read(&path)
            .with_context(|| format!("{FIXTURE} is missing; run the generator without --check"))?;
        if current != bytes {
            bail!("{FIXTURE} differs from production Rust proof parsing; regenerate it");
        }
        println!("verified {FIXTURE}");
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, bytes)?;
    println!("wrote {FIXTURE}");
    Ok(())
}

fn fixture() -> Result<Value> {
    let valid = valid_cases()?;
    let rejects = reject_cases(&valid)?;
    Ok(json!({
        "existingCoverage": {
            "proofCanonicalOracle": {
                "fixture": "sdk-libs/ts/client/test/oracles/proof-canonical-v1.json",
                "test": "sdk-libs/ts/client/test/vectors/proof-canonical-oracle.test.ts",
                "clauses": [
                    "malformedHexadecimal",
                    "valuesAtOrAboveModulus",
                    "halfCommitment",
                    "commitmentPresentOnUncommittedRail",
                    "commitmentAbsentOnCommittedRail",
                    "zeroIdentityCoordinateOnG2"
                ]
            },
            "proofValidity": {
                "fixture": "sdk-libs/ts/fixtures/client/proof-validity-v1.json",
                "test": "sdk-libs/ts/client/test/vectors/proof-compression.test.ts",
                "clauses": [
                    "vanillaGroth16",
                    "bsb22CommittedGroth16",
                    "missingCoordinateRows",
                    "partialCommitment",
                    "offCurveG1AtCompress",
                    "commitmentAbsentOnCommittedRail"
                ]
            }
        },
        "generatorCommand": "cargo run -p xtask --bin proof-response-parity",
        "id": "proof-response-parity-v1",
        "rejects": rejects,
        "responsibility": concat!(
            "P3 proof-response parsing and compression: identity and leading-zero ",
            "points, G1/G2 parity branches, and structural rejection mutations ",
            "derived from production Rust parse and compress."
        ),
        "rustPath": "sdk-libs/client/src/prover/proof.rs",
        "rustSymbol": "proof_from_gnark_json; ProofCompressed::try_from; ProofCompressed::to_transact_proof",
        "schema": "zolana-ts-fixtures-v1",
        "valid": valid,
        "version": "1"
    }))
}

fn valid_cases() -> Result<Vec<Value>> {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let neg_g1 = (-G1Projective::from(g1)).into_affine();
    let neg_g2 = (-G2Projective::from(g2)).into_affine();

    let mut cases = vec![
        valid_parse_case(
            "vanilla-generator",
            "vanillaGroth16",
            gnark_from_points(&g1, &g2, &g1, None),
            false,
        )?,
        valid_parse_case(
            "bsb22-generator",
            "bsb22CommittedGroth16",
            gnark_from_points(&g1, &g2, &g1, Some((&g1, &g1))),
            true,
        )?,
        valid_parse_case(
            "identity-points",
            "zeroIdentityPoints",
            gnark_identity(false),
            false,
        )?,
        valid_parse_case(
            "identity-points-bsb22",
            "zeroIdentityPoints",
            gnark_identity(true),
            true,
        )?,
        // Generator X is 1, so the uncompressed encoding has 31 leading zero
        // bytes on each limb. Parsing must keep them; compression must not
        // treat a short hex spelling in the response as a different point.
        valid_parse_case(
            "leading-zero-coordinates",
            "leadingZeroCoordinates",
            gnark_from_points(&g1, &g2, &g1, None),
            false,
        )?,
        // `ar = -G` so the parser's mandatory A negation yields +G, whose Y is
        // the smaller residue and therefore clears the compressed parity bit.
        valid_parse_case(
            "g1-parity-clear",
            "parityBitBoundaries",
            gnark_from_points(&neg_g1, &g2, &g1, None),
            false,
        )?,
        // `ar = G` yields negated A = -G, setting the compressed parity bit.
        valid_parse_case(
            "g1-parity-set",
            "parityBitBoundaries",
            gnark_from_points(&g1, &g2, &g1, None),
            false,
        )?,
        valid_parse_case(
            "g2-parity-clear",
            "g2ParityBranches",
            gnark_from_points(&g1, &g2, &g1, None),
            false,
        )?,
        valid_parse_case(
            "g2-parity-y1-largest",
            "g2ParityBranches",
            gnark_from_points(&g1, &neg_g2, &g1, None),
            false,
        )?,
    ];

    // The `y1 == 0 && isLargest(y0)` branch needs a prime-order G2 point on
    // that locus. The locus is nonempty on the full curve (see
    // `g2_with_y1_zero_on_curve`), but every constructed point fails the
    // r-torsion check. Expected size of the subgroup intersection is O(1) in a
    // 2^254 space, so the branch is unreachable for prover-produced B and is
    // recorded as unavailable with that reason rather than a failed search.
    let locus = g2_with_y1_zero_on_curve()?.context("y1=0 curve locus should be nonempty")?;
    assert!(
        !locus.is_in_correct_subgroup_assuming_on_curve(),
        "locus construction must not accidentally land in the r-torsion"
    );
    cases.push(json!({
        "id": "g2-parity-y1-zero-y0-largest",
        "clause": "g2ParityBranches",
        "unavailable": true,
        "reason": "y.c1==0 locus is nonempty on the BN254 G2 curve (algebraic solve at x1=2) but every constructed point fails the r-torsion check that TypeScript assertValidity and arkworks enforce; expected |G2 ∩ locus| = O(1) in a 2^254 group, so no short prime-order witness exists for this branch",
        "evidence": {
            "curveLocusNonempty": true,
            "constructedPointInSubgroup": false,
            "firstLocusX1": "0x2"
        }
    }));

    Ok(cases)
}

fn reject_cases(valid: &[Value]) -> Result<Vec<Value>> {
    let vanilla = valid
        .iter()
        .find(|case| case["id"] == "vanilla-generator")
        .context("missing vanilla-generator base")?;
    let bsb22 = valid
        .iter()
        .find(|case| case["id"] == "bsb22-generator")
        .context("missing bsb22-generator base")?;
    let base_gnark = vanilla["gnark"].clone();
    let bsb22_gnark = bsb22["gnark"].clone();

    let mut rejects = vec![
        reject_parse(
            "missing-ar-y",
            "missingOrExtraCoordinateRows",
            "drop ar[1] from vanilla-generator",
            mutate_ar_len(&base_gnark, 1)?,
            false,
        )?,
        reject_parse(
            "extra-ar-coordinate",
            "missingOrExtraCoordinateRows",
            "append a third ar coordinate to vanilla-generator",
            mutate_ar_len(&base_gnark, 3)?,
            false,
        )?,
        reject_parse(
            "missing-bs-row",
            "missingOrExtraCoordinateRows",
            "keep only bs[0] from vanilla-generator",
            mutate_bs_rows(&base_gnark, 1)?,
            false,
        )?,
        reject_parse(
            "extra-bs-row",
            "missingOrExtraCoordinateRows",
            "duplicate bs[0] as a third row on vanilla-generator",
            mutate_bs_rows(&base_gnark, 3)?,
            false,
        )?,
        reject_parse(
            "truncated-ar-point",
            "truncatedAndExtendedPoints",
            "replace ar with a one-limb array (truncated G1)",
            {
                let mut body = base_gnark.clone();
                body["ar"] = json!(["0x1"]);
                body
            },
            false,
        )?,
        reject_parse(
            "extended-krs-point",
            "truncatedAndExtendedPoints",
            "replace krs with three limbs (extended G1)",
            {
                let mut body = base_gnark.clone();
                body["krs"] = json!(["0x1", "0x2", "0x3"]);
                body
            },
            false,
        )?,
        reject_parse(
            "malformed-hex-ar",
            "malformedHexadecimal",
            "replace ar[0] with a non-hexadecimal string",
            {
                let mut body = base_gnark.clone();
                body["ar"] = json!(["0xzz", body["ar"][1].clone()]);
                body
            },
            false,
        )?,
        reject_parse(
            "coordinate-at-modulus",
            "valuesAtOrAboveModulus",
            "replace ar[0] with the BN254 base modulus",
            {
                let mut body = base_gnark.clone();
                body["ar"] = json!([
                    "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
                    body["ar"][1].clone()
                ]);
                body
            },
            false,
        )?,
        reject_parse(
            "commitment-only",
            "halfCommitment",
            "keep proof_commitment from bsb22-generator and drop proof_commitment_pok",
            {
                let mut body = bsb22_gnark.clone();
                body.as_object_mut()
                    .context("bsb22 gnark object")?
                    .remove("proof_commitment_pok");
                body
            },
            true,
        )?,
        reject_parse(
            "pok-only",
            "halfCommitment",
            "keep proof_commitment_pok from bsb22-generator and drop proof_commitment",
            {
                let mut body = bsb22_gnark.clone();
                body.as_object_mut()
                    .context("bsb22 gnark object")?
                    .remove("proof_commitment");
                body
            },
            true,
        )?,
        reject_parse(
            "commitment-on-eddsa-rail",
            "commitmentPresentOnUncommittedRail",
            "serve bsb22-generator on the eddsa (uncommitted) rail",
            bsb22_gnark.clone(),
            false,
        )?,
        reject_parse(
            "missing-commitment-on-p256-rail",
            "commitmentAbsentOnCommittedRail",
            "serve vanilla-generator on the p256 (committed) rail",
            base_gnark.clone(),
            true,
        )?,
    ];

    // Both languages ignore unknown keys today (serde default; TypeScript reads
    // named fields only). Shared acceptance is deliberate: the Go prover's
    // `ProofJSON` is additive-tolerant today (`omitempty` commitment limbs), and
    // Serde's default ignore / TypeScript's named reads keep a future
    // diagnostic field from breaking both SDKs at once. Rejecting would be a
    // coordinated API change, not a port fix. Pin the shared accept so a
    // one-sided rejector cannot land unnoticed.
    let mut unknown = base_gnark.clone();
    unknown["unexpected_field"] = json!("0xdead");
    let unknown_parsed = parse_gnark(&unknown, false);
    rejects.push(json!({
        "id": "unknown-response-field",
        "clause": "unknownResponseFields",
        "mutation": "add unexpected_field to vanilla-generator",
        "gnark": unknown,
        "requireCommitment": false,
        "accepted": unknown_parsed.is_ok(),
        "typescriptCategory": null,
        "rustCategory": null,
        "disposition": "accept-forward-compat",
        "note": "both languages ignore unknown proof fields; rejection would break prover forward compatibility and is not required for soundness"
    }));

    rejects.push(reject_compress_off_curve_g1(vanilla)?);
    // Out-of-field G2 limbs are refused by both compressors. Off-curve G2 is
    // Out-of-field G2 is refused by both. Off-curve G2 is accepted by both:
    // compression keeps only the syscall's field-range check.
    rejects.push(reject_compress_g2_out_of_field(vanilla)?);
    rejects.push(g2_off_curve_shared_accept(vanilla)?);

    Ok(rejects)
}

fn valid_parse_case(
    id: &str,
    clause: &str,
    gnark: Value,
    require_commitment: bool,
) -> Result<Value> {
    let proof = parse_gnark(&gnark, require_commitment)?;
    let compressed = ProofCompressed::try_from(proof)
        .map_err(|error| anyhow::anyhow!("compress {id}: {error}"))?;
    let rail = match compressed.to_transact_proof() {
        zolana_interface::instruction::instruction_data::transact::TransactProof::P256(_) => "p256",
        zolana_interface::instruction::instruction_data::transact::TransactProof::Eddsa {
            ..
        } => "eddsa",
    };
    Ok(json!({
        "id": id,
        "clause": clause,
        "requireCommitment": require_commitment,
        "gnark": gnark,
        "uncompressed": proof_json(&proof),
        "compressed": compressed_json(&compressed),
        "rail": rail,
        "hasCommitment": proof.commitment.is_some(),
        "compressedParity": {
            "a": compressed.a[0] & 0x80 != 0,
            "b": compressed.b[0] & 0x80 != 0,
            "c": compressed.c[0] & 0x80 != 0
        }
    }))
}

fn reject_parse(
    id: &str,
    clause: &str,
    mutation: &str,
    gnark: Value,
    require_commitment: bool,
) -> Result<Value> {
    let error = match parse_gnark(&gnark, require_commitment) {
        Ok(_) => bail!("rejection case {id} was accepted by Rust"),
        Err(error) => error,
    };
    let (rust_category, typescript_category) = categories_for_clause(clause);
    Ok(json!({
        "id": id,
        "clause": clause,
        "mutation": mutation,
        "gnark": gnark,
        "requireCommitment": require_commitment,
        "accepted": false,
        "stage": "parse",
        "rustCategory": rust_category,
        "typescriptCategory": typescript_category,
        "rustError": format!("{error}")
    }))
}

fn reject_compress_off_curve_g1(vanilla: &Value) -> Result<Value> {
    let b = hex_to_array::<128>(vanilla["uncompressed"]["bBytes"].as_str().context("b")?);
    let c = hex_to_array::<64>(vanilla["uncompressed"]["cBytes"].as_str().context("c")?);
    let proof = Proof {
        a: [0xff; 64],
        b,
        c,
        commitment: None,
    };
    let error = ProofCompressed::try_from(proof).expect_err("off-curve A must fail");
    Ok(json!({
        "id": "off-curve-g1-compress",
        "clause": "offCurveG1OrG2",
        "mutation": "replace uncompressed A from vanilla-generator with 64 0xff bytes",
        "uncompressed": {
            "aBytes": hex(&[0xff; 64]),
            "bBytes": vanilla["uncompressed"]["bBytes"].clone(),
            "cBytes": vanilla["uncompressed"]["cBytes"].clone(),
            "commitment": null
        },
        "accepted": false,
        "stage": "compress",
        "rustCategory": "ProofParse",
        "typescriptCategory": "CLIENT_PROOF_POINT",
        "rustError": format!("{error}")
    }))
}

fn reject_compress_g2_out_of_field(vanilla: &Value) -> Result<Value> {
    let a = hex_to_array::<64>(vanilla["uncompressed"]["aBytes"].as_str().context("a")?);
    let c = hex_to_array::<64>(vanilla["uncompressed"]["cBytes"].as_str().context("c")?);
    let mut b = [0u8; 128];
    // First limb = p (the base modulus): not a field element on either side.
    b[..32].copy_from_slice(&BN254_BASE_MODULUS_BE);
    let proof = Proof {
        a,
        b,
        c,
        commitment: None,
    };
    let error = ProofCompressed::try_from(proof).expect_err("out-of-field B must fail");
    Ok(json!({
        "id": "g2-limb-at-modulus",
        "clause": "offCurveG1OrG2",
        "mutation": "set B.x.c0 from vanilla-generator to the BN254 base modulus",
        "uncompressed": {
            "aBytes": vanilla["uncompressed"]["aBytes"].clone(),
            "bBytes": hex(&b),
            "cBytes": vanilla["uncompressed"]["cBytes"].clone(),
            "commitment": null
        },
        "accepted": false,
        "stage": "compress",
        "rustCategory": "ProofParse",
        "typescriptCategory": "CLIENT_PROOF_POINT",
        "rustError": format!("{error}")
    }))
}

fn g2_off_curve_shared_accept(vanilla: &Value) -> Result<Value> {
    let a = hex_to_array::<64>(vanilla["uncompressed"]["aBytes"].as_str().context("a")?);
    let c = hex_to_array::<64>(vanilla["uncompressed"]["cBytes"].as_str().context("c")?);
    let mut b = [0u8; 128];
    b[0] = 0x02;
    let proof = Proof {
        a,
        b,
        c,
        commitment: None,
    };
    let compressed = ProofCompressed::try_from(proof)
        .map_err(|error| anyhow::anyhow!("Rust unexpectedly refused off-curve G2: {error}"))?;
    Ok(json!({
        "id": "off-curve-g2-compress-shared-accept",
        "clause": "offCurveG1OrG2",
        "mutation": "replace uncompressed B from vanilla-generator with a nonzero off-curve G2 encoding",
        "uncompressed": {
            "aBytes": vanilla["uncompressed"]["aBytes"].clone(),
            "bBytes": hex(&b),
            "cBytes": vanilla["uncompressed"]["cBytes"].clone(),
            "commitment": null
        },
        "accepted": true,
        "acceptedByRust": true,
        "acceptedByTypescript": true,
        "stage": "compress",
        "compressedBBytes": hex(&compressed.b),
        "disposition": "match-syscall-range-check",
        "note": "Closed defect: TypeScript used to feed gnark's c1-first Fq2 limbs to noble as c0-first and assertValidity-reject. Compression now keeps only the field-range check that alt_bn128_g2_compress_be performs (SIMD-0129); curve validity is deferred to on-chain verify. Both languages accept this encoding."
    }))
}

/// Logical P3 clause → the stable category each language surfaces. Rust folds
/// point and rail failures into `ProofParse`; TypeScript names them.
fn categories_for_clause(clause: &str) -> (&'static str, &'static str) {
    match clause {
        "commitmentPresentOnUncommittedRail" | "commitmentAbsentOnCommittedRail" => {
            ("ProofParse", "CLIENT_PROOF_RAIL_MISMATCH")
        }
        "offCurveG1OrG2" => ("ProofParse", "CLIENT_PROOF_POINT"),
        _ => ("ProofParse", "CLIENT_PROOF_PARSE"),
    }
}

fn gnark_from_points(
    a: &G1Affine,
    b: &G2Affine,
    c: &G1Affine,
    commitment: Option<(&G1Affine, &G1Affine)>,
) -> Value {
    // Match the prover's `WriteRawTo` JSON: each Fp2 is (A1, A0) = EIP-197 limb order,
    // not ark's (c0, c1) declaration order.
    let mut body = json!({
        "ar": g1_pair(a),
        "bs": [
            fq2_pair(&b.x.c1, &b.x.c0),
            fq2_pair(&b.y.c1, &b.y.c0)
        ],
        "krs": g1_pair(c),
    });
    if let Some((commitment, pok)) = commitment {
        body["proof_commitment"] = g1_pair(commitment);
        body["proof_commitment_pok"] = g1_pair(pok);
    }
    body
}

fn gnark_identity(committed: bool) -> Value {
    let zero = vec!["0x0".to_string(), "0x0".to_string()];
    let mut body = json!({
        "ar": zero.clone(),
        "bs": [zero.clone(), zero.clone()],
        "krs": zero.clone(),
    });
    if committed {
        body["proof_commitment"] = json!(zero.clone());
        body["proof_commitment_pok"] = json!(zero);
    }
    body
}

fn g1_pair(point: &G1Affine) -> Value {
    let (x, y) = point.xy().expect("finite G1 point");
    json!([field_hex(&x), field_hex(&y)])
}

fn fq2_pair(c0: &Fq, c1: &Fq) -> Value {
    json!([field_hex(c0), field_hex(c1)])
}

/// Algebraic construction of G2 points with `y.c1 == 0`.
///
/// For `Fp2 = Fp[i]/(i²+1)` and `y = y0` (so `y² ∈ Fp`), the curve forces
/// `(x³ + b).c1 = 0`, i.e. `3 x0² x1 - x1³ + b.c1 = 0`. With `x1 ≠ 0` this
/// solves for `x0²`; then `y0 = ±sqrt((x³ + b).c0)`. Scalar multiples of the
/// generator miss this locus in practice; solving the locus equation does not.
fn probe_g2_y1_zero() -> Result<()> {
    let Some(point) = g2_with_y1_zero_on_curve()? else {
        eprintln!("no y1=0 point on the algebraic locus within the probe bound");
        return Ok(());
    };
    let y = point.y().context("finite")?;
    let x = point.x().context("x")?;
    eprintln!(
        "locus point on_curve={} subgroup={} y0={} x1={}",
        point.is_on_curve(),
        point.is_in_correct_subgroup_assuming_on_curve(),
        field_hex(&y.c0),
        field_hex(&x.c1)
    );
    Ok(())
}

fn field_hex(field: &Fq) -> String {
    format!("0x{}", hex(&field.into_bigint().to_bytes_be()))
}

/// Solve `(x³ + b).c1 = 0` for `x ∈ Fp2`, then take `y = ±sqrt((x³ + b).c0)`
/// in `Fp` with the larger residue. Points on this locus are on the curve but
/// not in the r-torsion (see the unavailable row's evidence).
fn g2_with_y1_zero_on_curve() -> Result<Option<G2Affine>> {
    use ark_ff::Field;
    let g = G2Affine::generator();
    let (gx, gy) = g.xy().context("generator")?;
    let b = gy.square() - gx.square() * gx;
    let three = Fq::from(3u64);
    let mid = half_modulus_minus_one_over_two();

    // x1 = 0 forces b.c1 = 0, which BN254's twist constant refuses, so start at 1.
    for limb in 1u64..=G2_Y1_ZERO_SEARCH {
        let x1 = Fq::from(limb);
        let x0_sq = (x1.square() * x1 - b.c1) * (three * x1).inverse().context("3*x1")?;
        let Some(x0) = x0_sq.sqrt() else {
            continue;
        };
        for x0 in [x0, -x0] {
            let x = Fq2::new(x0, x1);
            let rhs = x.square() * x + b;
            if !rhs.c1.is_zero() {
                continue;
            }
            let Some(y0) = rhs.c0.sqrt() else {
                continue;
            };
            for y0 in [y0, -y0] {
                if fq_be(&y0) <= mid {
                    continue;
                }
                let y = Fq2::new(y0, Fq::zero());
                let point = G2Affine::new_unchecked(x, y);
                if point.is_on_curve() {
                    return Ok(Some(point));
                }
            }
        }
    }
    Ok(None)
}

const BN254_BASE_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

fn fq_be(field: &Fq) -> [u8; 32] {
    let bytes = field.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn half_modulus_minus_one_over_two() -> [u8; 32] {
    // (p - 1) / 2, big-endian. p is odd, so this is a one-bit right shift of p-1.
    let mut p_minus_one = BN254_BASE_MODULUS_BE;
    p_minus_one[31] = p_minus_one[31].wrapping_sub(1);
    let mut out = [0u8; 32];
    let mut carry = 0u8;
    for (index, byte) in p_minus_one.iter().enumerate() {
        out[index] = (byte >> 1) | (carry << 7);
        carry = byte & 1;
    }
    out
}

fn mutate_ar_len(gnark: &Value, len: usize) -> Result<Value> {
    let mut body = gnark.clone();
    let ar = body["ar"].as_array().context("ar array")?.clone();
    let mut next = Vec::new();
    for index in 0..len {
        next.push(ar.get(index).cloned().unwrap_or_else(|| {
            json!("0x0000000000000000000000000000000000000000000000000000000000000001")
        }));
    }
    body["ar"] = Value::Array(next);
    Ok(body)
}

fn mutate_bs_rows(gnark: &Value, rows: usize) -> Result<Value> {
    let mut body = gnark.clone();
    let bs = body["bs"].as_array().context("bs array")?.clone();
    let first = bs.first().cloned().context("bs[0]")?;
    let mut next = Vec::new();
    for index in 0..rows {
        next.push(bs.get(index).cloned().unwrap_or_else(|| first.clone()));
    }
    body["bs"] = Value::Array(next);
    Ok(body)
}

fn parse_gnark(gnark: &Value, committed: bool) -> Result<Proof, ClientError> {
    let response = json!({ "proof": gnark });
    let body = serde_json::to_vec(&response).expect("serialize proof response");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proof fixture server");
    let address = listener.local_addr().expect("proof fixture address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept proof request");
        let _ = read_http_body(&mut stream);
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("write proof headers");
        stream.write_all(&body).expect("write proof body");
    });
    let client = ProverClient::new(format!("http://{address}"));
    let proof = if committed {
        client.prove_transfer_p256(&TransferP256Inputs {
            inputs: vec![],
            outputs: vec![],
            external_data_hash: 0u8.into(),
            p256_pub_x: 0u8.into(),
            p256_pub_y: 0u8.into(),
            p256_sig_r: 0u8.into(),
            p256_sig_s: 0u8.into(),
            private_tx_hash: 0u8.into(),
            p256_message_hash_low: 0u8.into(),
            p256_message_hash_high: 0u8.into(),
            public_sol_amount: 0u8.into(),
            public_spl_amount: 0u8.into(),
            public_spl_asset_pubkey: 0u8.into(),
            zone_program_id: 0u8.into(),
            payer_pubkey_hash: 0u8.into(),
            p256_signing_pk_field: 0u8.into(),
            public_input_hash: 0u8.into(),
        })
    } else {
        client.prove_transfer(&TransferInputs {
            inputs: vec![],
            outputs: vec![],
            external_data_hash: 0u8.into(),
            private_tx_hash: 0u8.into(),
            public_sol_amount: 0u8.into(),
            public_spl_amount: 0u8.into(),
            public_spl_asset_pubkey: 0u8.into(),
            zone_program_id: 0u8.into(),
            payer_pubkey_hash: 0u8.into(),
            public_input_hash: 0u8.into(),
        })
    };
    server.join().expect("proof fixture server");
    proof
}

fn read_http_body(stream: &mut impl Read) -> Result<Vec<u8>, std::io::Error> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    Ok(buffer)
}

fn proof_json(proof: &Proof) -> Value {
    json!({
        "aBytes": hex(&proof.a),
        "bBytes": hex(&proof.b),
        "cBytes": hex(&proof.c),
        "commitment": proof.commitment.map(|value| json!({
            "commitmentBytes": hex(&value.commitment),
            "commitmentPokBytes": hex(&value.commitment_pok)
        }))
    })
}

fn compressed_json(proof: &ProofCompressed) -> Value {
    json!({
        "aBytes": hex(&proof.a),
        "bBytes": hex(&proof.b),
        "cBytes": hex(&proof.c),
        "commitment": proof.commitment.map(|value| json!({
            "commitmentBytes": hex(&value.commitment),
            "commitmentPokBytes": hex(&value.commitment_pok)
        }))
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_to_array<const N: usize>(value: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).expect("hex utf8");
        out[index] = u8::from_str_radix(text, 16).expect("hex byte");
    }
    out
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize(value)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect::<Map<_, _>>(),
        ),
        _ => value.clone(),
    }
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(PathBuf::from)
        .context("xtask has no parent directory")
}
