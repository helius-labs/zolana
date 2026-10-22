//! PROOF_FIXTURES=<dir> cargo test -p xtask --test proof_fixtures -- --ignored --nocapture

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::Context;
use custom_ring_interface::{key_catalog::RING_KEYS, verifying_key as ring_verifying_key};
use groth16_solana::groth16::Groth16Verifyingkey;
use zolana_client::{prover::verify_proof_statement, ClientError, Proof};
use zolana_interface::{
    shape::SPP_SUPPORTED_SHAPES,
    verifying_keys::{
        merge_24_1, merge_52_1, merge_8_1, merge_ring_24_1, merge_ring_52_1, merge_ring_8_1,
        AnonymousRingEddsaProofData, Bsb22Commitment, CircuitId,
    },
    N_PUBLIC_SLOTS,
};

type VerifyingKey = &'static Groth16Verifyingkey<'static>;

#[test]
#[ignore = "needs PROOF_FIXTURES, the directory TestRequestFixturesProveUnderTheirLockedKeys writes"]
fn every_committed_verifying_key_verifies_its_proof_fixture() {
    let directory = std::env::var_os("PROOF_FIXTURES").expect("PROOF_FIXTURES names a directory");
    let directory = Path::new(&directory);
    let keys = selected_verifying_keys();
    let mut failures: Vec<String> = proof_stems(directory)
        .into_iter()
        .filter(|stem| !keys.contains_key(stem))
        .map(|stem| format!("{stem}: the programs select no committed verifying key"))
        .collect();
    for (stem, &key) in &keys {
        match verify_fixture(directory, stem, key) {
            Ok(()) => println!("{stem}: verified, refused with its public input plus one"),
            Err(error) => failures.push(format!("{stem}: {error:#}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every committed verifying key the programs select, by the key file it was exported from.
fn selected_verifying_keys() -> BTreeMap<String, VerifyingKey> {
    let slots = N_PUBLIC_SLOTS as u8;
    let proof_data = AnonymousRingEddsaProofData {
        bsb22_commitment: Bsb22Commitment {
            commitment: [0; 32],
            commitment_pok: [0; 32],
        },
        default_owner_tag: None,
    };
    let transfers = SPP_SUPPORTED_SHAPES.iter().flat_map(|shape| {
        let (n_inputs, n_outputs) = (shape.n_inputs() as u8, shape.n_outputs() as u8);
        [
            (
                "transfer_confidential",
                CircuitId::ConfidentialEddsa(n_inputs, n_outputs, slots),
            ),
            (
                "transfer_ring",
                CircuitId::ConfidentialRingEddsa(n_inputs, n_outputs, slots),
            ),
            (
                "transfer_eddsa_ring",
                CircuitId::AnonymousRingEddsa(n_inputs, n_outputs, slots, proof_data),
            ),
            (
                "transfer_ring_authority",
                CircuitId::RingAuthority(n_inputs, n_outputs, slots),
            ),
        ]
        .into_iter()
        .filter_map(move |(rail, circuit)| {
            Some((
                format!("{rail}_{n_inputs}_{n_outputs}"),
                circuit.verifying_key()?,
            ))
        })
    });
    let merges: [(&str, VerifyingKey); 6] = [
        ("merge_8_1", &merge_8_1::VERIFYINGKEY),
        ("merge_24_1", &merge_24_1::VERIFYINGKEY),
        ("merge_52_1", &merge_52_1::VERIFYINGKEY),
        ("merge_ring_8_1", &merge_ring_8_1::VERIFYINGKEY),
        ("merge_ring_24_1", &merge_ring_24_1::VERIFYINGKEY),
        ("merge_ring_52_1", &merge_ring_52_1::VERIFYINGKEY),
    ];
    let rings = RING_KEYS.iter().filter_map(|key| {
        Some((
            key.file_name().strip_suffix(".key")?.to_owned(),
            ring_verifying_key(key.circuit)?,
        ))
    });
    transfers
        .chain(merges.map(|(stem, key)| (stem.to_owned(), key)))
        .chain(rings)
        .collect()
}

fn proof_stems(directory: &Path) -> BTreeSet<String> {
    fs::read_dir(directory)
        .expect("PROOF_FIXTURES is a readable directory")
        .filter_map(|entry| {
            let name = entry
                .expect("readable entry")
                .file_name()
                .into_string()
                .ok()?;
            Some(name.strip_suffix(".proof.json")?.to_owned())
        })
        .collect()
}

fn verify_fixture(directory: &Path, stem: &str, key: VerifyingKey) -> anyhow::Result<()> {
    let path = directory.join(format!("{stem}.proof.json"));
    let fixture: serde_json::Value = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("no proof at {}", path.display()))?,
    )?;
    let proof = Proof::from_gnark_json(&fixture["proof"].to_string())?;
    let public_input = public_input(&fixture["publicInput"])?;
    verify_proof_statement(&proof, public_input, key)?;
    match verify_proof_statement(&proof, plus_one(public_input), key) {
        Err(ClientError::ProofVerification(_)) => Ok(()),
        other => anyhow::bail!("the public input plus one gives {other:?}"),
    }
}

fn public_input(value: &serde_json::Value) -> anyhow::Result<[u8; 32]> {
    let digits = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .context("publicInput is not 0x hex")?;
    let mut public_input = [0; 32];
    hex::decode_to_slice(digits, &mut public_input)?;
    Ok(public_input)
}

fn plus_one(mut value: [u8; 32]) -> [u8; 32] {
    for byte in value.iter_mut().rev() {
        let (sum, carried) = byte.overflowing_add(1);
        *byte = sum;
        if !carried {
            break;
        }
    }
    value
}
