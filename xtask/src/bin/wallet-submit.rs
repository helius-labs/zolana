//! Generates the merge-submit rejection vectors for row W03.
//!
//! `validate_merge_submission` and `ensure_proofs_match_submit_tree` are the two
//! arms the TypeScript port claimed without a regenerable oracle. This binary
//! calls those Rust functions over a fixed seed matrix and records each
//! rejection variant so `@zolana/wallet` can replay the same inputs.
//!
//! ```text
//! cargo run -p xtask --bin wallet-submit            # write the fixture
//! cargo run -p xtask --bin wallet-submit -- --check # fail on any drift
//! ```

use std::{collections::BTreeMap, env, fs, path::PathBuf, process::ExitCode};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_client::{
    error::ClientError, MerkleContext, MerkleProof, NonInclusionProof, SpendProof,
};
use zolana_keypair::{shielded::ShieldedKeypair, ViewingKey};
use zolana_user_registry_interface::UserRecord;
use zolana_wallet::actions::submit::{
    ensure_proofs_match_submit_tree, validate_merge_submission, MergeMaterial,
};

const FIXTURE: &str = "sdk-libs/ts/vectors/wallet-submit-v1.json";

/// Deterministic ed25519 seed shared with the TypeScript replay.
/// Viewing material is derived from the same seed (`ViewingKey::from_seed(_, 0)`),
/// matching `ShieldedKeypair::from_solana_keypair` / TypeScript `fromEd25519`.
const SIGNING_SEED: [u8; 32] = {
    let mut seed = [0u8; 32];
    seed[31] = 0x15;
    seed
};

const SUBMIT_TREE: Address = Address::new_from_array([7u8; 32]);
const OTHER_TREE: Address = Address::new_from_array([8u8; 32]);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wallet-submit failed: {error:#}");
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
                    "Generate the Rust-side wallet submit rejection vectors.\n\nusage: cargo run -p xtask --bin wallet-submit -- [--check]"
                );
                return Ok(());
            }
            other => bail!("unknown argument {other}"),
        }
    }

    let fixture = canonicalize(&build()?);
    let rendered = format!("{}\n", serde_json::to_string_pretty(&fixture)?);
    let path = workspace_root()?.join(FIXTURE);

    if check {
        let current =
            fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        if current != rendered {
            bail!("{FIXTURE} is stale; rerun `cargo run -p xtask --bin wallet-submit`");
        }
        return Ok(());
    }

    fs::write(&path, rendered).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn build() -> Result<Value> {
    let (owner, keypair) = ed25519_owner()?;
    let material = MergeMaterial::from_keypair(&keypair);

    Ok(json!({
        "generator": "cargo run -p xtask --bin wallet-submit",
        "rustSource": ["sdk-libs/wallet/src/actions/submit.rs"],
        "inputs": {
            "signingSeedHex": hex(&SIGNING_SEED),
            "owner": owner.to_string(),
            "nullifierPubkeyHex": hex(&material.nullifier_key.pubkey()?),
            "viewingPubkeyHex": hex(material.viewing_pubkey.as_bytes()),
            "signingPubkeyHex": hex(material.signing_pubkey.as_bytes()),
        },
        "trees": {
            "submit": SUBMIT_TREE.to_string(),
            "other": OTHER_TREE.to_string(),
        },
        "keyMismatches": key_mismatches(&owner, &keypair)?,
        "proofTrees": proof_trees()?,
    }))
}

fn key_mismatches(owner: &Pubkey, keypair: &ShieldedKeypair) -> Result<Value> {
    let material = MergeMaterial::from_keypair(keypair);
    let cases = [
        (
            "signing-rail",
            {
                let mut record = record_for(*owner, keypair, true);
                // A P256 slot on an ed25519 owner forces the signing-rail arm.
                record.owner_p256 = Some([2u8; 33]);
                record
            },
            "MergeSigningKeyMismatch",
        ),
        (
            "nullifier",
            {
                let mut record = record_for(*owner, keypair, true);
                record.nullifier_pubkey = [0xffu8; 32];
                record
            },
            "MergeNullifierKeyMismatch",
        ),
        (
            "viewing",
            {
                let mut record = record_for(*owner, keypair, true);
                record.viewing_pubkey = [0xffu8; 33];
                record
            },
            "MergeViewingKeyMismatch",
        ),
    ];

    let mut out = Vec::with_capacity(cases.len());
    for (name, record, expected) in cases {
        let error = validate_merge_submission(&record, *owner, &material)
            .err()
            .with_context(|| format!("{name} must reject"))?;
        let variant = client_variant(&error);
        if variant != expected {
            bail!("{name}: rust returned {variant}, expected {expected}");
        }
        out.push(json!({
            "name": name,
            "mutation": name,
            "error": variant,
            "ownerDetail": matches!(error, ClientError::MergeViewingKeyMismatch { .. }),
        }));
    }

    // Matching material must still pass — pins the seed against a false reject.
    validate_merge_submission(&record_for(*owner, keypair, true), *owner, &material)
        .context("matching ed25519 material must accept")?;

    Ok(Value::Array(out))
}

fn proof_trees() -> Result<Value> {
    let cases = [
        ("matching", SUBMIT_TREE, SUBMIT_TREE, None),
        (
            "wrong-state-tree",
            OTHER_TREE,
            SUBMIT_TREE,
            Some(("MergeTreeMismatch", OTHER_TREE)),
        ),
        (
            "wrong-nullifier-tree",
            SUBMIT_TREE,
            OTHER_TREE,
            Some(("MergeTreeMismatch", OTHER_TREE)),
        ),
    ];

    let mut out = Vec::with_capacity(cases.len());
    for (name, state_tree, nullifier_tree, expected) in cases {
        let result = ensure_proofs_match_submit_tree(
            &[spend_proof_on(state_tree, nullifier_tree)],
            SUBMIT_TREE,
        );
        match (result, expected) {
            (Ok(()), None) => out.push(json!({
                "name": name,
                "stateTree": state_tree.to_string(),
                "nullifierTree": nullifier_tree.to_string(),
                "arm": "ok",
            })),
            (Err(error), Some((variant, proof_tree))) => {
                let got = client_variant(&error);
                if got != variant {
                    bail!("{name}: rust returned {got}, expected {variant}");
                }
                let ClientError::MergeTreeMismatch {
                    proof_tree: got_proof,
                    submit_tree: got_submit,
                } = error
                else {
                    bail!("{name}: expected MergeTreeMismatch");
                };
                if got_proof != proof_tree.to_bytes() || got_submit != SUBMIT_TREE.to_bytes() {
                    bail!("{name}: tree detail mismatch");
                }
                out.push(json!({
                    "name": name,
                    "stateTree": state_tree.to_string(),
                    "nullifierTree": nullifier_tree.to_string(),
                    "arm": "err",
                    "error": variant,
                    "proofTree": proof_tree.to_string(),
                    "submitTree": SUBMIT_TREE.to_string(),
                }));
            }
            (Ok(()), Some(_)) => bail!("{name}: expected rejection"),
            (Err(error), None) => bail!("{name}: unexpected {}", client_variant(&error)),
        }
    }
    Ok(Value::Array(out))
}

fn ed25519_owner() -> Result<(Pubkey, ShieldedKeypair)> {
    let viewing = ViewingKey::from_seed(&SIGNING_SEED, 0).context("viewing key")?;
    let keypair =
        ShieldedKeypair::from_ed25519(&SIGNING_SEED, viewing).context("ed25519 keypair")?;
    let owner = Pubkey::new_from_array(
        keypair
            .signing_pubkey()
            .as_ed25519()
            .context("ed25519 signing pubkey")?,
    );
    Ok((owner, keypair))
}

fn record_for(owner: Pubkey, keypair: &ShieldedKeypair, merging_enabled: bool) -> UserRecord {
    UserRecord {
        owner: owner.to_bytes().into(),
        bump: 255,
        owner_p256: None,
        nullifier_pubkey: keypair.nullifier_key.pubkey().unwrap(),
        viewing_pubkey: *keypair.viewing_pubkey().as_bytes(),
        sync_delegate: None,
        entries: Vec::new(),
        merging_enabled,
    }
}

fn spend_proof_on(state_tree: Address, nullifier_tree: Address) -> SpendProof {
    SpendProof {
        state: MerkleProof {
            leaf: [1u8; 32],
            merkle_context: MerkleContext {
                tree_type: 0,
                tree: state_tree,
            },
            path: Vec::new(),
            leaf_index: 0,
            root: [2u8; 32],
            root_seq: 0,
            root_index: 0,
        },
        nullifier: NonInclusionProof {
            leaf: [3u8; 32],
            merkle_context: MerkleContext {
                tree_type: 0,
                tree: nullifier_tree,
            },
            path: Vec::new(),
            low_element: [0u8; 32],
            low_element_index: 0,
            high_element: [4u8; 32],
            high_element_index: 0,
            root: [5u8; 32],
            root_seq: 0,
            root_index: 0,
        },
    }
}

fn client_variant(error: &ClientError) -> &'static str {
    match error {
        ClientError::MergeSigningKeyMismatch => "MergeSigningKeyMismatch",
        ClientError::MergeNullifierKeyMismatch => "MergeNullifierKeyMismatch",
        ClientError::MergeViewingKeyMismatch { .. } => "MergeViewingKeyMismatch",
        ClientError::MergeTreeMismatch { .. } => "MergeTreeMismatch",
        ClientError::MergeDisabled { .. } => "MergeDisabled",
        _ => "Other",
    }
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
    manifest
        .parent()
        .map(PathBuf::from)
        .context("xtask has no parent directory")
}
