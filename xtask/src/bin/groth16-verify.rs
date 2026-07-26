//! Test-only Groth16 verifier oracle for TypeScript proof certification (P4).
//!
//! Mirrors `programs/shielded-pool/src/instructions/verifier.rs::verify_groth16`:
//! decompress compressed wire points with `groth16_solana`, then call
//! `Groth16Verifier::new` / `new_with_commitment` against the embedded
//! release-targeted verifying keys in `zolana_interface`. It does not reimplement
//! pairings.
//!
//! ```text
//! # Live request on stdin, JSON result on stdout:
//! cargo run -p xtask --bin groth16-verify
//!
//! # Self-check: every supported VK resolves and garbage proofs are rejected.
//! cargo run -p xtask --bin groth16-verify -- --check
//! ```
//!
//! Stable failure codes (never library message text):
//! `encoding`, `rail_mismatch`, `verification_failure`, `unknown_vk`.

use std::{
    env, io,
    process::{ExitCode, Termination},
};

use anyhow::{bail, Context, Result};
use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use serde_json::{json, Value};
use zolana_interface::verifying_keys::{
    merge_8_1, merge_zone_8_1, transfer_confidential_1_1, transfer_confidential_1_2,
    transfer_confidential_1_8, transfer_confidential_2_2, transfer_confidential_2_3,
    transfer_confidential_3_3, transfer_confidential_4_3, transfer_confidential_4_4,
    transfer_confidential_5_3, transfer_confidential_5_4, transfer_p256_confidential_1_1,
    transfer_p256_confidential_1_2, transfer_p256_confidential_1_8, transfer_p256_confidential_2_2,
    transfer_p256_confidential_2_3, transfer_p256_confidential_3_3, transfer_p256_confidential_4_3,
    transfer_p256_confidential_4_4, transfer_p256_confidential_5_3, transfer_p256_confidential_5_4,
    transfer_p256_zone_1_1, transfer_p256_zone_1_2, transfer_p256_zone_1_8, transfer_p256_zone_2_2,
    transfer_p256_zone_2_3, transfer_p256_zone_3_3, transfer_p256_zone_4_3, transfer_p256_zone_4_4,
    transfer_p256_zone_5_3, transfer_p256_zone_5_4, transfer_zone_1_1, transfer_zone_1_2,
    transfer_zone_1_8, transfer_zone_2_2, transfer_zone_2_3, transfer_zone_3_3, transfer_zone_4_3,
    transfer_zone_4_4, transfer_zone_5_3, transfer_zone_5_4, transfer_zone_authority_1_1,
    transfer_zone_authority_2_2, transfer_zone_authority_3_3, transfer_zone_authority_4_4,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailCode {
    Encoding,
    RailMismatch,
    VerificationFailure,
    UnknownVk,
}

impl FailCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Encoding => "encoding",
            Self::RailMismatch => "rail_mismatch",
            Self::VerificationFailure => "verification_failure",
            Self::UnknownVk => "unknown_vk",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Confidential,
    Zone,
    ZoneAuthority,
    Merge,
    MergeZone,
}

impl Family {
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "confidential" => Self::Confidential,
            "zone" => Self::Zone,
            "zone_authority" => Self::ZoneAuthority,
            "merge" => Self::Merge,
            "merge_zone" => Self::MergeZone,
            other => bail!("unknown family {other:?}"),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rail {
    Eddsa,
    P256,
}

impl Rail {
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "eddsa" => Self::Eddsa,
            "p256" => Self::P256,
            other => bail!("unknown rail {other:?}"),
        })
    }

    fn committed(self) -> bool {
        matches!(self, Self::P256)
    }
}

struct VerifyRequest {
    family: Family,
    rail: Rail,
    n_inputs: usize,
    n_outputs: usize,
    public_input_hash: [u8; 32],
    a: [u8; 32],
    b: [u8; 64],
    c: [u8; 32],
    commitment: Option<([u8; 32], [u8; 32])>,
}

fn main() -> impl Termination {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("groth16-verify failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let mut check = false;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--check" => check = true,
            "--help" | "-h" => {
                println!(
                    "Test-only Groth16 verifier oracle.\n\n\
                     usage:\n  cargo run -p xtask --bin groth16-verify            # JSON on stdin\n\
                     cargo run -p xtask --bin groth16-verify -- --check  # VK table + reject garbage"
                );
                return Ok(ExitCode::SUCCESS);
            }
            other => bail!("unexpected argument {other:?}"),
        }
    }

    if check {
        self_check()?;
        println!("groth16-verify self-check ok");
        return Ok(ExitCode::SUCCESS);
    }

    let request: Value = serde_json::from_reader(io::stdin().lock()).context("read stdin JSON")?;
    let parsed = parse_request(&request)?;
    let result = match verify(&parsed) {
        Ok(()) => json!({ "ok": true }),
        Err(code) => json!({ "ok": false, "code": code.as_str() }),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(ExitCode::SUCCESS)
}

fn self_check() -> Result<()> {
    let shapes = [
        (1, 1),
        (1, 2),
        (2, 2),
        (2, 3),
        (3, 3),
        (4, 3),
        (4, 4),
        (5, 3),
        (5, 4),
        (1, 8),
    ];
    for (n_in, n_out) in shapes {
        select_vk(Family::Confidential, Rail::Eddsa, n_in, n_out)
            .map_err(|_| anyhow::anyhow!("missing confidential eddsa vk {n_in}x{n_out}"))?;
        select_vk(Family::Confidential, Rail::P256, n_in, n_out)
            .map_err(|_| anyhow::anyhow!("missing confidential p256 vk {n_in}x{n_out}"))?;
        select_vk(Family::Zone, Rail::Eddsa, n_in, n_out)
            .map_err(|_| anyhow::anyhow!("missing zone eddsa vk {n_in}x{n_out}"))?;
        select_vk(Family::Zone, Rail::P256, n_in, n_out)
            .map_err(|_| anyhow::anyhow!("missing zone p256 vk {n_in}x{n_out}"))?;
    }
    for (n_in, n_out) in [(1, 1), (2, 2), (3, 3), (4, 4)] {
        select_vk(Family::ZoneAuthority, Rail::Eddsa, n_in, n_out)
            .map_err(|_| anyhow::anyhow!("missing zone_authority vk {n_in}x{n_out}"))?;
    }
    select_vk(Family::Merge, Rail::P256, 8, 1).map_err(|_| anyhow::anyhow!("missing merge vk"))?;
    select_vk(Family::MergeZone, Rail::P256, 8, 1)
        .map_err(|_| anyhow::anyhow!("missing merge_zone vk"))?;

    let garbage = VerifyRequest {
        family: Family::Confidential,
        rail: Rail::Eddsa,
        n_inputs: 1,
        n_outputs: 1,
        public_input_hash: [0u8; 32],
        a: [0u8; 32],
        b: [0u8; 64],
        c: [0u8; 32],
        commitment: None,
    };
    match verify(&garbage) {
        Err(FailCode::Encoding) | Err(FailCode::VerificationFailure) => Ok(()),
        Err(other) => bail!("garbage proof returned unexpected code {}", other.as_str()),
        Ok(()) => bail!("garbage proof verified; oracle has no teeth"),
    }
}

fn parse_request(value: &Value) -> Result<VerifyRequest> {
    let family = Family::parse(
        value
            .get("family")
            .and_then(Value::as_str)
            .context("family")?,
    )?;
    let rail = match family {
        Family::ZoneAuthority => Rail::Eddsa,
        Family::Merge | Family::MergeZone => Rail::P256,
        Family::Confidential | Family::Zone => Rail::parse(
            value
                .get("rail")
                .and_then(Value::as_str)
                .context("rail")?,
        )?,
    };
    let shape = value.get("shape").context("shape")?;
    let n_inputs = shape
        .get("inputs")
        .and_then(Value::as_u64)
        .context("shape.inputs")? as usize;
    let n_outputs = shape
        .get("outputs")
        .and_then(Value::as_u64)
        .context("shape.outputs")? as usize;
    let proof = value.get("proof").context("proof")?;
    let commitment = match (
        proof.get("commitment").and_then(Value::as_str),
        proof.get("commitmentPok").and_then(Value::as_str),
    ) {
        (Some(c), Some(pok)) => Some((hex_fixed(c)?, hex_fixed(pok)?)),
        (None, None) => None,
        _ => bail!("commitment and commitmentPok must both be present or both absent"),
    };
    Ok(VerifyRequest {
        family,
        rail,
        n_inputs,
        n_outputs,
        public_input_hash: hex_fixed(
            value
                .get("publicInputHashBytes")
                .and_then(Value::as_str)
                .context("publicInputHashBytes")?,
        )?,
        a: hex_fixed(proof.get("a").and_then(Value::as_str).context("proof.a")?)?,
        b: hex_fixed(proof.get("b").and_then(Value::as_str).context("proof.b")?)?,
        c: hex_fixed(proof.get("c").and_then(Value::as_str).context("proof.c")?)?,
        commitment,
    })
}

fn verify(request: &VerifyRequest) -> Result<(), FailCode> {
    let vk = select_vk(
        request.family,
        request.rail,
        request.n_inputs,
        request.n_outputs,
    )?;
    let vk_committed = vk.vk_commitment.is_some();
    let proof_committed = request.commitment.is_some();
    // Zone-authority is always vanilla; merge families are always committed.
    let expected_committed = match request.family {
        Family::ZoneAuthority => false,
        Family::Merge | Family::MergeZone => true,
        Family::Confidential | Family::Zone => request.rail.committed(),
    };
    if proof_committed != expected_committed || proof_committed != vk_committed {
        return Err(FailCode::RailMismatch);
    }

    let proof_a = decompress_g1(&request.a).map_err(|_| FailCode::Encoding)?;
    let proof_b = decompress_g2(&request.b).map_err(|_| FailCode::Encoding)?;
    let proof_c = decompress_g1(&request.c).map_err(|_| FailCode::Encoding)?;
    let public_inputs = [request.public_input_hash];

    match request.commitment {
        Some((commitment, commitment_pok)) => {
            let commitment = decompress_g1(&commitment).map_err(|_| FailCode::Encoding)?;
            let commitment_pok = decompress_g1(&commitment_pok).map_err(|_| FailCode::Encoding)?;
            let mut verifier = Groth16Verifier::new_with_commitment(
                &proof_a,
                &proof_b,
                &proof_c,
                &commitment,
                &commitment_pok,
                &public_inputs,
                vk,
            )
            .map_err(|_| FailCode::VerificationFailure)?;
            verifier
                .verify()
                .map_err(|_| FailCode::VerificationFailure)?;
        }
        None => {
            let mut verifier =
                Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, vk)
                    .map_err(|_| FailCode::VerificationFailure)?;
            verifier
                .verify()
                .map_err(|_| FailCode::VerificationFailure)?;
        }
    }
    Ok(())
}

fn select_vk(
    family: Family,
    rail: Rail,
    n_inputs: usize,
    n_outputs: usize,
) -> Result<&'static Groth16Verifyingkey<'static>, FailCode> {
    let is_p256 = matches!(rail, Rail::P256);
    let key = match family {
        Family::Confidential => match (n_inputs, n_outputs, is_p256) {
            (1, 1, false) => &transfer_confidential_1_1::VERIFYINGKEY,
            (1, 1, true) => &transfer_p256_confidential_1_1::VERIFYINGKEY,
            (1, 2, false) => &transfer_confidential_1_2::VERIFYINGKEY,
            (1, 2, true) => &transfer_p256_confidential_1_2::VERIFYINGKEY,
            (2, 2, false) => &transfer_confidential_2_2::VERIFYINGKEY,
            (2, 2, true) => &transfer_p256_confidential_2_2::VERIFYINGKEY,
            (2, 3, false) => &transfer_confidential_2_3::VERIFYINGKEY,
            (2, 3, true) => &transfer_p256_confidential_2_3::VERIFYINGKEY,
            (3, 3, false) => &transfer_confidential_3_3::VERIFYINGKEY,
            (3, 3, true) => &transfer_p256_confidential_3_3::VERIFYINGKEY,
            (4, 3, false) => &transfer_confidential_4_3::VERIFYINGKEY,
            (4, 3, true) => &transfer_p256_confidential_4_3::VERIFYINGKEY,
            (4, 4, false) => &transfer_confidential_4_4::VERIFYINGKEY,
            (4, 4, true) => &transfer_p256_confidential_4_4::VERIFYINGKEY,
            (5, 3, false) => &transfer_confidential_5_3::VERIFYINGKEY,
            (5, 3, true) => &transfer_p256_confidential_5_3::VERIFYINGKEY,
            (5, 4, false) => &transfer_confidential_5_4::VERIFYINGKEY,
            (5, 4, true) => &transfer_p256_confidential_5_4::VERIFYINGKEY,
            (1, 8, false) => &transfer_confidential_1_8::VERIFYINGKEY,
            (1, 8, true) => &transfer_p256_confidential_1_8::VERIFYINGKEY,
            _ => return Err(FailCode::UnknownVk),
        },
        Family::Zone => match (n_inputs, n_outputs, is_p256) {
            (1, 1, false) => &transfer_zone_1_1::VERIFYINGKEY,
            (1, 1, true) => &transfer_p256_zone_1_1::VERIFYINGKEY,
            (1, 2, false) => &transfer_zone_1_2::VERIFYINGKEY,
            (1, 2, true) => &transfer_p256_zone_1_2::VERIFYINGKEY,
            (2, 2, false) => &transfer_zone_2_2::VERIFYINGKEY,
            (2, 2, true) => &transfer_p256_zone_2_2::VERIFYINGKEY,
            (2, 3, false) => &transfer_zone_2_3::VERIFYINGKEY,
            (2, 3, true) => &transfer_p256_zone_2_3::VERIFYINGKEY,
            (3, 3, false) => &transfer_zone_3_3::VERIFYINGKEY,
            (3, 3, true) => &transfer_p256_zone_3_3::VERIFYINGKEY,
            (4, 3, false) => &transfer_zone_4_3::VERIFYINGKEY,
            (4, 3, true) => &transfer_p256_zone_4_3::VERIFYINGKEY,
            (4, 4, false) => &transfer_zone_4_4::VERIFYINGKEY,
            (4, 4, true) => &transfer_p256_zone_4_4::VERIFYINGKEY,
            (5, 3, false) => &transfer_zone_5_3::VERIFYINGKEY,
            (5, 3, true) => &transfer_p256_zone_5_3::VERIFYINGKEY,
            (5, 4, false) => &transfer_zone_5_4::VERIFYINGKEY,
            (5, 4, true) => &transfer_p256_zone_5_4::VERIFYINGKEY,
            (1, 8, false) => &transfer_zone_1_8::VERIFYINGKEY,
            (1, 8, true) => &transfer_p256_zone_1_8::VERIFYINGKEY,
            _ => return Err(FailCode::UnknownVk),
        },
        Family::ZoneAuthority => match (n_inputs, n_outputs) {
            (1, 1) => &transfer_zone_authority_1_1::VERIFYINGKEY,
            (2, 2) => &transfer_zone_authority_2_2::VERIFYINGKEY,
            (3, 3) => &transfer_zone_authority_3_3::VERIFYINGKEY,
            (4, 4) => &transfer_zone_authority_4_4::VERIFYINGKEY,
            _ => return Err(FailCode::UnknownVk),
        },
        Family::Merge => {
            if (n_inputs, n_outputs) != (8, 1) {
                return Err(FailCode::UnknownVk);
            }
            &merge_8_1::VERIFYINGKEY
        }
        Family::MergeZone => {
            if (n_inputs, n_outputs) != (8, 1) {
                return Err(FailCode::UnknownVk);
            }
            &merge_zone_8_1::VERIFYINGKEY
        }
    };
    Ok(key)
}

fn hex_fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    if digits.len() != N * 2 {
        bail!("expected {} hex bytes, got {}", N, digits.len() / 2);
    }
    let mut out = [0u8; N];
    for (index, chunk) in digits.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    Ok(match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => bail!("invalid hex digit"),
    })
}
