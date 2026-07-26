//! Named public-input intermediates for proof certification suite P1.
//!
//! The existing prover-shapes fixture pins the final `public_input_hash` and the
//! full witness. A failing final hash then names no layer. This binary calls
//! production `assemble` / `MergeProver` / `MergeZoneProver` and records every
//! named chain element `PublicInputs::hash` (and the merge owner-binding tails)
//! fold, so TypeScript can compare each layer independently.
//!
//! Logical inputs match `client/prover-shapes-v1.json` and the merge oracle seeds
//! so the TypeScript suite rebuilds through the same public helpers.
//!
//! ```text
//! cargo run -p xtask --bin public-input-assembly            # write the fixture
//! cargo run -p xtask --bin public-input-assembly -- --check  # fail on any drift
//! ```

use std::{collections::BTreeMap, env, fs, path::PathBuf, process::ExitCode, str::FromStr};

use anyhow::{bail, Context, Result};
use num_bigint::BigUint;
use p256::SecretKey;
use serde_json::{json, Map, Value};
use solana_address::Address;
use zolana_client::{
    assemble, MergeProver, MergeZoneProver, MergeZoneWitness, MergeWitness, MerkleContext,
    MerkleProof, NonInclusionProof, ProverInputs, SpendProof, SPP_SUPPORTED_SHAPES,
};
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{
    hash::{hash_field, sha256},
    merge::merge_public_contribution,
    NullifierKey, PublicKey, ShieldedKeypair, SigningKey, ViewingKey,
};
use zolana_transaction::{
    derive_blinding,
    instructions::{
        merge::PreparedMerge,
        merge_zone::PreparedMergeZone,
        transact::{ExternalData, SppProofInputs, SppProofOutputUtxo},
        types::{InputUtxoContext, SppProofInputUtxo},
    },
    utxo::program_id_field,
    Data, Utxo, SOL_MINT,
};

const FIXTURE: &str = "sdk-libs/ts/fixtures/client/public-input-assembly-v1.json";

const P256_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
];
const ED25519_SECRET: [u8; 32] = [31; 32];
const VIEWING_SEED: [u8; 32] = [32; 32];
const BLINDING_SEED: [u8; 31] = [33; 31];

const MERGE_SIGNING_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
];
const MERGE_VIEWING_SEED: [u8; 32] = [8; 32];
const MERGE_BLINDING_SEED: [u8; 31] = [11; 31];
const MERGE_TX_VIEWING_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15,
];
const MERGE_REAL_AMOUNTS: [u64; 2] = [10, 20];
const MERGE_OUTPUT_AMOUNT: u64 = 30;
const MERGE_INPUTS: usize = 8;
const MERGE_TREE: &str = "4WnNSfDXkWSnFi1PgXxn8X8fhFwU2Jhe4Df82mL9rKmm";
const MERGE_ZONE_PROGRAM: [u8; 32] = [3; 32];

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("public-input-assembly failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut check = false;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--check" => check = true,
            "--help" | "-h" => {
                println!(
                    "Generate named public-input assembly intermediates.\n\nusage: cargo run -p xtask --bin public-input-assembly -- [--check]"
                );
                return Ok(());
            }
            other => bail!("unexpected argument {other:?}"),
        }
    }

    let path = workspace_root()?.join(FIXTURE);
    let fixture = canonicalize(&fixture()?);
    let rendered = format!("{}\n", serde_json::to_string_pretty(&fixture)?);

    if check {
        let current = fs::read_to_string(&path)
            .with_context(|| format!("{FIXTURE} is missing; run the generator without --check"))?;
        if current != rendered {
            bail!("{FIXTURE} differs from production assembly; regenerate it");
        }
        println!("verified {FIXTURE}");
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, rendered).with_context(|| format!("write {FIXTURE}"))?;
    println!("wrote {FIXTURE}");
    Ok(())
}

fn fixture() -> Result<Value> {
    Ok(json!({
        "schemaVersion": "1",
        "fixtureVersion": "1",
        "fixtureId": "fx-p1-public-input-assembly-v1",
        "canonicalSourcePath": "sdk-libs/client/src/prover/transact/p256_and_eddsa.rs; sdk-libs/client/src/prover/merge.rs; sdk-libs/client/src/prover/merge_zone.rs",
        "canonicalSourceSymbol": "PublicInputs::hash; MergeProver::build; MergeZoneProver::build",
        "specificationSection": "planning/typescript-sdk-port/proof-and-key-parity.md#p1-public-input-assembly",
        "inventoryReviewRow": "P1",
        "inputs": {
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "ed25519SecretBytes": hex(&ED25519_SECRET),
            "p256SecretBytes": hex(&P256_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "testOnlySecret": true,
            "merge": {
                "blindingSeedBytes": hex(&MERGE_BLINDING_SEED),
                "signingSecretBytes": hex(&MERGE_SIGNING_SECRET),
                "viewingSeedBytes": hex(&MERGE_VIEWING_SEED),
                "txViewingSecretBytes": hex(&MERGE_TX_VIEWING_SECRET),
                "realInputAmounts": MERGE_REAL_AMOUNTS.iter().map(u64::to_string).collect::<Vec<_>>(),
                "outputAmount": MERGE_OUTPUT_AMOUNT.to_string(),
                "tree": MERGE_TREE,
                "zoneProgramIdBytes": hex(&MERGE_ZONE_PROGRAM),
            }
        },
        "expected": {
            "confidential": confidential_cases()?,
            "mixedOwner": mixed_owner_case()?,
            "merge": merge_cases()?,
        }
    }))
}

fn confidential_cases() -> Result<Value> {
    let mut rails = Vec::new();
    for (rail, p256) in [("eddsa", false), ("p256", true)] {
        let mut shapes = Vec::new();
        for shape in SPP_SUPPORTED_SHAPES {
            let (inputs, proofs) = proof_inputs(p256, shape.n_inputs(), shape.n_outputs())?;
            let assembled = assemble(inputs, &proofs)?;
            shapes.push(json!({
                "shape": {
                    "inputs": shape.n_inputs().to_string(),
                    "outputs": shape.n_outputs().to_string(),
                },
                "chain": confidential_chain(&assembled.prover_inputs, &assembled.public_input_hash)?,
            }));
        }
        rails.push(json!({ "rail": rail, "shapes": shapes }));
    }
    Ok(json!({ "rails": rails }))
}

fn mixed_owner_case() -> Result<Value> {
    let (p256_inputs, p256_proofs) = proof_inputs(true, 2, 2)?;
    let (eddsa_inputs, _) = proof_inputs(false, 1, 1)?;
    let p256_input = p256_inputs.input_utxos[0].clone();
    let eddsa_input = eddsa_inputs.input_utxos[0].clone();
    let mut mixed = SppProofInputs::new(
        vec![p256_input, eddsa_input.clone()],
        p256_inputs.output_utxos.clone(),
        p256_inputs.external_data.clone(),
        Address::new_from_array([44; 32]),
    );
    // Assembly packs the signature coordinates as witness fields and does not
    // check them against the private-tx message, so the bytes from the pure
    // P256 case are enough to take the P256 rail.
    mixed.p256_signature = p256_inputs.p256_signature;

    let eddsa_hash = eddsa_input.hash()?;
    let eddsa_nullifier = eddsa_input.nullifier()?;
    let tree = Address::new_from_array([45; 32]);
    let proofs = vec![
        p256_proofs[0].clone(),
        SpendProof {
            state: MerkleProof {
                leaf: eddsa_hash,
                merkle_context: MerkleContext {
                    tree_type: 1,
                    tree,
                },
                path: vec![field_byte(47); 32],
                leaf_index: 1,
                root: field_byte(47),
                root_seq: 48,
                root_index: 50,
            },
            nullifier: NonInclusionProof {
                leaf: eddsa_nullifier,
                merkle_context: MerkleContext {
                    tree_type: 2,
                    tree,
                },
                path: vec![field_byte(51); 40],
                low_element: field_byte(51),
                low_element_index: 0,
                high_element: field_byte(52),
                high_element_index: 1,
                root: field_byte(53),
                root_seq: 54,
                root_index: 56,
            },
        },
    ];
    let assembled = assemble(mixed, &proofs)?;
    Ok(json!({
        "shape": { "inputs": "2", "outputs": "2" },
        "rail": "p256",
        "inputOwnerKinds": ["p256", "eddsa"],
        "chain": confidential_chain(&assembled.prover_inputs, &assembled.public_input_hash)?,
    }))
}

fn confidential_chain(inputs: &ProverInputs, public_input_hash: &[u8; 32]) -> Result<Value> {
    match inputs {
        ProverInputs::Eddsa(value) => {
            let nullifiers = fields_to_bytes(&value.inputs.iter().map(|i| &i.nullifier).collect::<Vec<_>>());
            let output_hashes = fields_to_bytes(&value.outputs.iter().map(|o| &o.hash).collect::<Vec<_>>());
            let utxo_roots =
                fields_to_bytes(&value.inputs.iter().map(|i| &i.utxo_tree_root).collect::<Vec<_>>());
            let nullifier_roots = fields_to_bytes(
                &value
                    .inputs
                    .iter()
                    .map(|i| &i.nullifier_tree_root)
                    .collect::<Vec<_>>(),
            );
            let input_owners =
                fields_to_bytes(&value.inputs.iter().map(|i| &i.owner_pk_hash).collect::<Vec<_>>());
            let output_owners =
                fields_to_bytes(&value.outputs.iter().map(|o| &o.owner_pk_hash).collect::<Vec<_>>());
            let private_tx = field_to_bytes(&value.private_tx_hash);
            let external = field_to_bytes(&value.external_data_hash);
            let p256_message_element = hash_field(&[0u8; 32])?;
            Ok(json!({
                "nullifierChain": hex(&create_hash_chain_from_slice(&nullifiers)?),
                "outputHashChain": hex(&create_hash_chain_from_slice(&output_hashes)?),
                "utxoRootChain": hex(&create_hash_chain_from_slice(&utxo_roots)?),
                "nullifierRootChain": hex(&create_hash_chain_from_slice(&nullifier_roots)?),
                "privateTxHash": value.private_tx_hash.to_string(),
                "privateTxHashBytes": hex(&private_tx),
                "p256MessageDigestField": hex(&p256_message_element),
                "externalDataHash": value.external_data_hash.to_string(),
                "externalDataHashBytes": hex(&external),
                "publicSolAmount": value.public_sol_amount.to_string(),
                "publicSplAmount": value.public_spl_amount.to_string(),
                "publicSplAssetPubkey": value.public_spl_asset_pubkey.to_string(),
                "zoneProgramId": value.zone_program_id.to_string(),
                "payerPubkeyHash": value.payer_pubkey_hash.to_string(),
                "inputOwnerChain": hex(&create_hash_chain_from_slice(&input_owners)?),
                "outputOwnerChain": hex(&create_hash_chain_from_slice(&output_owners)?),
                "p256SigningField": "0",
                "p256SigningFieldBytes": hex(&[0u8; 32]),
                "publicInputHash": value.public_input_hash.to_string(),
                "publicInputHashBytes": hex(public_input_hash),
                "inputOwnerPkHashes": value.inputs.iter().map(|i| i.owner_pk_hash.to_string()).collect::<Vec<_>>(),
                "outputOwnerPkHashes": value.outputs.iter().map(|o| o.owner_pk_hash.to_string()).collect::<Vec<_>>(),
            }))
        }
        ProverInputs::P256(value) => {
            let nullifiers = fields_to_bytes(&value.inputs.iter().map(|i| &i.nullifier).collect::<Vec<_>>());
            let output_hashes = fields_to_bytes(&value.outputs.iter().map(|o| &o.hash).collect::<Vec<_>>());
            let utxo_roots =
                fields_to_bytes(&value.inputs.iter().map(|i| &i.utxo_tree_root).collect::<Vec<_>>());
            let nullifier_roots = fields_to_bytes(
                &value
                    .inputs
                    .iter()
                    .map(|i| &i.nullifier_tree_root)
                    .collect::<Vec<_>>(),
            );
            let input_owners =
                fields_to_bytes(&value.inputs.iter().map(|i| &i.owner_pk_hash).collect::<Vec<_>>());
            let output_owners =
                fields_to_bytes(&value.outputs.iter().map(|o| &o.owner_pk_hash).collect::<Vec<_>>());
            let private_tx = field_to_bytes(&value.private_tx_hash);
            let external = field_to_bytes(&value.external_data_hash);
            let p256_message = sha256(&private_tx);
            let p256_message_element = hash_field(&p256_message)?;
            let signing = field_to_bytes(&value.p256_signing_pk_field);
            Ok(json!({
                "nullifierChain": hex(&create_hash_chain_from_slice(&nullifiers)?),
                "outputHashChain": hex(&create_hash_chain_from_slice(&output_hashes)?),
                "utxoRootChain": hex(&create_hash_chain_from_slice(&utxo_roots)?),
                "nullifierRootChain": hex(&create_hash_chain_from_slice(&nullifier_roots)?),
                "privateTxHash": value.private_tx_hash.to_string(),
                "privateTxHashBytes": hex(&private_tx),
                "p256MessageDigestField": hex(&p256_message_element),
                "p256MessageHashLow": value.p256_message_hash_low.to_string(),
                "p256MessageHashHigh": value.p256_message_hash_high.to_string(),
                "externalDataHash": value.external_data_hash.to_string(),
                "externalDataHashBytes": hex(&external),
                "publicSolAmount": value.public_sol_amount.to_string(),
                "publicSplAmount": value.public_spl_amount.to_string(),
                "publicSplAssetPubkey": value.public_spl_asset_pubkey.to_string(),
                "zoneProgramId": value.zone_program_id.to_string(),
                "payerPubkeyHash": value.payer_pubkey_hash.to_string(),
                "inputOwnerChain": hex(&create_hash_chain_from_slice(&input_owners)?),
                "outputOwnerChain": hex(&create_hash_chain_from_slice(&output_owners)?),
                "p256SigningField": value.p256_signing_pk_field.to_string(),
                "p256SigningFieldBytes": hex(&signing),
                "publicInputHash": value.public_input_hash.to_string(),
                "publicInputHashBytes": hex(public_input_hash),
                "inputOwnerPkHashes": value.inputs.iter().map(|i| i.owner_pk_hash.to_string()).collect::<Vec<_>>(),
                "outputOwnerPkHashes": value.outputs.iter().map(|o| o.owner_pk_hash.to_string()).collect::<Vec<_>>(),
            }))
        }
    }
}

fn merge_cases() -> Result<Value> {
    let (merge, _) = build_merge()?;
    let (zone, _) = build_merge_zone()?;
    Ok(json!({
        "default": merge_chain(&merge, false)?,
        "zone": merge_chain(&zone, true)?,
    }))
}

fn merge_chain(result: &zolana_client::MergeProofResult, zone: bool) -> Result<Value> {
    let nullifier_chain = create_hash_chain_from_slice(&result.nullifiers)?;
    let utxo_roots = result
        .inputs
        .inputs
        .iter()
        .map(|input| field_to_bytes(&input.utxo_tree_root))
        .collect::<Vec<_>>();
    let nullifier_roots = result
        .inputs
        .inputs
        .iter()
        .map(|input| field_to_bytes(&input.nullifier_tree_root))
        .collect::<Vec<_>>();
    let contribution = merge_public_contribution(&result.tx_viewing_pk, &result.ciphertext)?;
    let keypair = merge_keypair();
    let user_signing = keypair.signing_pubkey().owner_pk_field()?;
    let user_viewing = PublicKey::from_p256(&keypair.viewing_pubkey()).hash()?;
    let zone_field = program_id_field(&Some(Address::new_from_array(MERGE_ZONE_PROGRAM)))?;

    let head = [
        nullifier_chain,
        result.output_hash,
        create_hash_chain_from_slice(&utxo_roots)?,
        create_hash_chain_from_slice(&nullifier_roots)?,
        result.private_tx_hash,
        result.external_data_hash,
    ];

    let owner_binding_tail = if zone {
        json!({
            "kind": "zone",
            "txViewingPkLowBytes": hex(&contribution.tx_viewing_pk_lo),
            "txViewingPkHighBytes": hex(&contribution.tx_viewing_pk_hi),
            "ciphertextHashBytes": hex(&contribution.ciphertext_hash),
            "zoneProgramIdFieldBytes": hex(&zone_field),
        })
    } else {
        json!({
            "kind": "default",
            "userSigningPkHashBytes": hex(&user_signing),
            "userViewingPkHashBytes": hex(&user_viewing),
            "txViewingPkLowBytes": hex(&contribution.tx_viewing_pk_lo),
            "txViewingPkHighBytes": hex(&contribution.tx_viewing_pk_hi),
            "ciphertextHashBytes": hex(&contribution.ciphertext_hash),
        })
    };

    Ok(json!({
        "nullifierChain": hex(&nullifier_chain),
        "outputHashBytes": hex(&result.output_hash),
        "utxoRootChain": hex(&create_hash_chain_from_slice(&utxo_roots)?),
        "nullifierRootChain": hex(&create_hash_chain_from_slice(&nullifier_roots)?),
        "privateTxHashBytes": hex(&result.private_tx_hash),
        "externalDataHashBytes": hex(&result.external_data_hash),
        "headChain": hex(&create_hash_chain_from_slice(&head)?),
        "ownerBindingTail": owner_binding_tail,
        "publicInputHashBytes": hex(&result.public_input_hash),
        "zoneProgramId": result.inputs.zone_program_id.to_string(),
    }))
}

fn build_merge() -> Result<(zolana_client::MergeProofResult, String)> {
    let keypair = merge_keypair();
    let prepared = PreparedMerge {
        inputs: merge_inputs(&keypair, None),
        output: merge_output(&keypair, None),
        expiry_unix_ts: u64::MAX,
        signing_pubkey: keypair.signing_pubkey(),
        user_viewing_pk: keypair.viewing_pubkey(),
        tx_viewing_sk: SecretKey::from_slice(&MERGE_TX_VIEWING_SECRET)
            .expect("tx viewing scalar"),
    };
    let contexts = prepared.input_utxo_hashes()?;
    let result = MergeProver::try_from(MergeWitness {
        prepared,
        nullifier_key: keypair.nullifier_key.clone(),
        proofs: merge_spend_proofs(&contexts),
    })?
    .build()?;
    Ok((result, String::new()))
}

fn build_merge_zone() -> Result<(zolana_client::MergeProofResult, String)> {
    let keypair = merge_keypair();
    let zone = Address::new_from_array(MERGE_ZONE_PROGRAM);
    let prepared = PreparedMergeZone {
        inputs: merge_inputs(&keypair, Some(zone)),
        output: merge_output(&keypair, Some(zone)),
        expiry_unix_ts: u64::MAX,
        signing_pubkey: keypair.signing_pubkey(),
        user_viewing_pk: keypair.viewing_pubkey(),
        tx_viewing_sk: SecretKey::from_slice(&MERGE_TX_VIEWING_SECRET)
            .expect("tx viewing scalar"),
        zone_program_id: zone,
    };
    let contexts = prepared.input_utxo_hashes()?;
    let result = MergeZoneProver::try_from(MergeZoneWitness {
        prepared,
        nullifier_key: keypair.nullifier_key.clone(),
        proofs: merge_spend_proofs(&contexts),
    })?
    .build()?;
    Ok((result, String::new()))
}

fn merge_keypair() -> ShieldedKeypair {
    ShieldedKeypair::from_keys(
        SigningKey::from_bytes(&MERGE_SIGNING_SECRET).expect("p256 signing key"),
        ViewingKey::from_seed(&MERGE_VIEWING_SEED, 0).expect("viewing key"),
    )
    .expect("shielded keypair")
}

fn merge_inputs(keypair: &ShieldedKeypair, zone: Option<Address>) -> Vec<SppProofInputUtxo> {
    let mut inputs = MERGE_REAL_AMOUNTS
        .iter()
        .enumerate()
        .map(|(position, amount)| {
            SppProofInputUtxo::new(
                Utxo {
                    owner: keypair.signing_pubkey(),
                    asset: SOL_MINT,
                    amount: *amount,
                    blinding: derive_blinding(&MERGE_BLINDING_SEED, position as u8),
                    zone_program_id: zone,
                    data: Data::default(),
                },
                keypair,
            )
        })
        .collect::<Vec<_>>();
    // Dummies stay zone-free; PreparedMergeZone stamps the zone onto every
    // spend after attach, and a dummy with a zone fails the canonical check.
    while inputs.len() < MERGE_INPUTS {
        let position = inputs.len() as u8;
        inputs.push(SppProofInputUtxo {
            utxo: Utxo {
                owner: PublicKey::zeroed(),
                asset: SOL_MINT,
                amount: 0,
                blinding: derive_blinding(&MERGE_BLINDING_SEED, position),
                zone_program_id: None,
                data: Data::default(),
            },
            nullifier_key: NullifierKey::from_secret([0; 31]),
            data_hash: None,
            zone_data_hash: None,
        });
    }
    inputs
}

fn merge_output(keypair: &ShieldedKeypair, zone: Option<Address>) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        asset: SOL_MINT,
        amount: MERGE_OUTPUT_AMOUNT,
        blinding: derive_blinding(&MERGE_BLINDING_SEED, 2),
        owner_address: Some(keypair.shielded_address().expect("address")),
        zone_program_id: zone,
        ..Default::default()
    }
}

fn merge_spend_proofs(contexts: &[InputUtxoContext]) -> Vec<SpendProof> {
    let tree = Address::from_str(MERGE_TREE).expect("tree");
    contexts
        .iter()
        .enumerate()
        .map(|(index, context)| SpendProof {
            state: MerkleProof {
                leaf: context.utxo_hash,
                merkle_context: MerkleContext {
                    tree_type: 1,
                    tree,
                },
                path: vec![[0u8; 32]; 32],
                leaf_index: index as u64,
                root: {
                    let mut root = [0u8; 32];
                    root[31] = 20 + index as u8;
                    root
                },
                root_seq: 1,
                root_index: 40 + index as u16,
            },
            nullifier: NonInclusionProof {
                leaf: context.nullifier,
                merkle_context: MerkleContext {
                    tree_type: 1,
                    tree,
                },
                path: vec![[0u8; 32]; 40],
                low_element: [0u8; 32],
                low_element_index: index as u64,
                high_element: [1u8; 32],
                high_element_index: (index + 1) as u64,
                root: {
                    let mut root = [0u8; 32];
                    root[31] = 30 + index as u8;
                    root
                },
                root_seq: 1,
                root_index: 50 + index as u16,
            },
        })
        .collect()
}

fn proof_inputs(
    p256: bool,
    n_inputs: usize,
    n_outputs: usize,
) -> Result<(SppProofInputs, Vec<SpendProof>)> {
    let keypair = keypair(p256)?;
    let mut inputs = vec![real_input(&keypair)];
    for position in 1..n_inputs {
        inputs.push(dummy_input(position as u8));
    }
    let mut outputs = Vec::with_capacity(n_outputs);
    for position in 0..n_outputs {
        outputs.push(output(&keypair, position as u8 + 64, position != 0)?);
    }
    let resolved_tags = outputs
        .iter()
        .map(|output| output.owner_tag.expect("fixture owner tag"))
        .collect::<Vec<_>>();
    let wire_outputs = outputs
        .iter()
        .zip(&resolved_tags)
        .map(|(output, tag)| {
            Ok::<_, anyhow::Error>(TransactOutput {
                utxo_hash: output.hash()?,
                owner_tag: OwnerTag::Inline(*tag),
                data: Some(vec![1, 2, 3]),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let external = ExternalData::new([41; 33], [42; 16], wire_outputs, resolved_tags, vec![])
        .with_public_sol(-5, Address::new_from_array([43; 32]))?;
    let mut inputs = SppProofInputs::new(inputs, outputs, external, Address::new_from_array([44; 32]));
    if p256 {
        inputs.sign_p256(&keypair)?;
    }
    let contexts = inputs.input_utxo_hashes()?;
    let tree = Address::new_from_array([45; 32]);
    let proofs = contexts
        .iter()
        .enumerate()
        .map(|(index, context)| SpendProof {
            state: MerkleProof {
                leaf: context.utxo_hash,
                merkle_context: MerkleContext { tree_type: 1, tree },
                path: vec![field_byte(46 + index as u8); 32],
                leaf_index: index as u64,
                root: field_byte(47),
                root_seq: 48,
                root_index: 49 + index as u16,
            },
            nullifier: NonInclusionProof {
                leaf: context.nullifier,
                merkle_context: MerkleContext { tree_type: 2, tree },
                path: vec![field_byte(50 + index as u8); 40],
                low_element: field_byte(51),
                low_element_index: 0,
                high_element: field_byte(52),
                high_element_index: 1,
                root: field_byte(53),
                root_seq: 54,
                root_index: 55 + index as u16,
            },
        })
        .collect();
    Ok((inputs, proofs))
}

fn keypair(p256: bool) -> Result<ShieldedKeypair> {
    let signing = if p256 {
        SigningKey::from_bytes(&P256_SECRET)?
    } else {
        SigningKey::from_ed25519(&ED25519_SECRET)
    };
    Ok(ShieldedKeypair::from_keys(
        signing,
        ViewingKey::from_seed(&VIEWING_SEED, u32::from(p256))?,
    )?)
}

fn real_input(keypair: &ShieldedKeypair) -> SppProofInputUtxo {
    SppProofInputUtxo::new(
        Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount: 100,
            blinding: derive_blinding(&BLINDING_SEED, 0),
            zone_program_id: None,
            data: Data::default(),
        },
        keypair,
    )
}

fn dummy_input(position: u8) -> SppProofInputUtxo {
    SppProofInputUtxo {
        utxo: Utxo {
            owner: PublicKey::zeroed(),
            asset: SOL_MINT,
            amount: 0,
            blinding: derive_blinding(&BLINDING_SEED, position),
            zone_program_id: None,
            data: Data::default(),
        },
        nullifier_key: NullifierKey::from_secret([0; 31]),
        data_hash: None,
        zone_data_hash: None,
    }
}

fn output(keypair: &ShieldedKeypair, position: u8, dummy: bool) -> Result<SppProofOutputUtxo> {
    if dummy {
        return Ok(SppProofOutputUtxo {
            blinding: derive_blinding(&BLINDING_SEED, position),
            owner_tag: Some([position; 32]),
            ..Default::default()
        });
    }
    Ok(SppProofOutputUtxo {
        owner_address: Some(keypair.shielded_address()?),
        owner_tag: Some(keypair.signing_pubkey().confidential_view_tag()?),
        asset: SOL_MINT,
        amount: 100,
        blinding: derive_blinding(&BLINDING_SEED, position),
        ..Default::default()
    })
}

fn field_byte(value: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    bytes
}

fn field_to_bytes(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn fields_to_bytes(values: &[&BigUint]) -> Vec<[u8; 32]> {
    values.iter().map(|value| field_to_bytes(value)).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect::<Map<_, _>>(),
        ),
        _ => value.clone(),
    }
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest
        .parent()
        .map(PathBuf::from)
        .context("xtask crate has no parent")?)
}
