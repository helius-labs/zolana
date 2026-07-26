//! Generates the Merkle semantics vectors that `@zolana/merkle-tree` checks
//! itself against.
//!
//! Rows M01 and M02 turn on four questions that the existing frozen fixture
//! answers only at a single end state: whether the sentinel closes the indexed
//! range from above, whether a rejected mutation leaves the tree untouched,
//! whether `get_next_index` carries the root-history offset, and what
//! `get_history_root_index_v2` counts. Each is a property of a *sequence* of
//! operations, so this binary records a step-by-step trace of one: the outcome
//! of every call and the whole observable state after it. The TypeScript test
//! replays the same steps and compares each snapshot, which fails on a
//! divergence at the step that introduced it rather than at the end.
//!
//! ```text
//! cargo run -p xtask --bin merkle-semantics            # write the fixture
//! cargo run -p xtask --bin merkle-semantics -- --check  # fail on any drift
//! ```

use std::{env, fs, path::PathBuf, process::ExitCode};

use anyhow::{bail, Context, Result};
use num_bigint::BigUint;
use num_traits::Num;
use serde_json::{json, Map, Value};
use zolana_hasher::Poseidon;
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};

const FIXTURE: &str = "sdk-libs/ts/vectors/merkle-semantics-v1.json";

/// `zolana_indexed_array::HIGHEST_ADDRESS_PLUS_ONE`, the sentinel every indexed
/// tree gets from `IndexedMerkleTree::new`.
const HIGHEST_ADDRESS_PLUS_ONE: &str =
    "452312848583266388373324160190187140051835877600158453279131187530910662655";

type Tree = MerkleTree<Poseidon>;
type Indexed = IndexedMerkleTree<Poseidon, usize>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("merkle-semantics failed: {error:#}");
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
                    "Generate the Rust-side Merkle semantics vectors.\n\nusage: cargo run -p xtask --bin merkle-semantics -- [--check]"
                );
                return Ok(());
            }
            other => bail!("unknown argument {other}"),
        }
    }

    let fixture = canonicalize(&build());
    let rendered = format!("{}\n", serde_json::to_string_pretty(&fixture)?);
    let path = workspace_root()?.join(FIXTURE);

    if check {
        let current =
            fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        if current != rendered {
            bail!("{FIXTURE} is stale; rerun `cargo run -p xtask --bin merkle-semantics`");
        }
        return Ok(());
    }

    fs::write(&path, rendered).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn build() -> Value {
    json!({
        "generator": "cargo run -p xtask --bin merkle-semantics",
        "rustSource": [
            "sdk-libs/merkle-tree/src/lib.rs",
            "sdk-libs/merkle-tree/src/indexed.rs",
        ],
        "hasher": "poseidon",
        "highestAddressPlusOne": HIGHEST_ADDRESS_PLUS_ONE,
        "scenarios": [
            history_offset_scenario(),
            rejected_mutations_scenario(),
            unset_history_scenario(),
            sentinel_scenario(),
            indexed_rejection_scenario(),
        ],
    })
}

/// `get_next_index` returns `rightmost_index`, the count of appended leaves,
/// with no root-history offset applied, and neither `update` nor `insert_leaf`
/// advances it. `get_history_root_index_v2` counts root updates instead, so an
/// `update` moves it and an `insert_leaf`, which recomputes nothing, does not.
fn history_offset_scenario() -> Value {
    let mut tree = Tree::new_with_history(3, 0, 2, 3);
    let mut steps = vec![observed(json!({ "op": "construct" }), Ok(()), &tree)];
    for byte in 1u8..=3 {
        let outcome = tree
            .append(&[byte; 32])
            .map_err(|error| format!("{error:?}"));
        steps.push(observed(
            json!({ "op": "append", "leafHex": hex(&[byte; 32]) }),
            outcome,
            &tree,
        ));
    }
    let outcome = tree
        .update(&[9; 32], 0)
        .map_err(|error| format!("{error:?}"));
    steps.push(observed(
        json!({ "op": "update", "index": "0", "leafHex": hex(&[9; 32]) }),
        outcome,
        &tree,
    ));
    tree.insert_leaf(5, [8; 32]);
    steps.push(observed(
        json!({ "op": "insertLeaf", "index": "5", "leafHex": hex(&[8; 32]) }),
        Ok(()),
        &tree,
    ));

    json!({
        "id": "history-offset-does-not-shift-next-index",
        "tree": tree_config(3, 0, Some((2, 3))),
        "steps": steps,
    })
}

/// `append`, `update`, and `replace_and_append` mutate a clone and adopt it
/// only on success, so a capacity or missing-leaf rejection leaves the root,
/// the leaf count, the root history, and the sequence number where they were.
fn rejected_mutations_scenario() -> Value {
    let mut tree = Tree::new_with_history(2, 0, 0, 3);
    let mut steps = vec![observed(json!({ "op": "construct" }), Ok(()), &tree)];
    for byte in 1u8..=4 {
        let outcome = tree
            .append(&[byte; 32])
            .map_err(|error| format!("{error:?}"));
        steps.push(observed(
            json!({ "op": "append", "leafHex": hex(&[byte; 32]) }),
            outcome,
            &tree,
        ));
    }
    let outcome = tree.append(&[5; 32]).map_err(|error| format!("{error:?}"));
    steps.push(observed(
        json!({ "op": "append", "leafHex": hex(&[5; 32]) }),
        outcome,
        &tree,
    ));
    let outcome = tree
        .update(&[6; 32], 9)
        .map_err(|error| format!("{error:?}"));
    steps.push(observed(
        json!({ "op": "update", "index": "9", "leafHex": hex(&[6; 32]) }),
        outcome,
        &tree,
    ));

    json!({
        "id": "rejected-mutations-leave-the-tree-unchanged",
        "tree": tree_config(2, 0, Some((0, 3))),
        "steps": steps,
    })
}

/// A tree built without history rejects both accessors rather than answering
/// with a default index.
fn unset_history_scenario() -> Value {
    let mut tree = Tree::new(3, 0);
    let mut steps = vec![observed(json!({ "op": "construct" }), Ok(()), &tree)];
    let outcome = tree.append(&[1; 32]).map_err(|error| format!("{error:?}"));
    steps.push(observed(
        json!({ "op": "append", "leafHex": hex(&[1; 32]) }),
        outcome,
        &tree,
    ));

    json!({
        "id": "history-accessors-reject-an-unconfigured-tree",
        "tree": tree_config(3, 0, None),
        "steps": steps,
    })
}

/// The exclusion ranges tile `(0, highest_value)`, so the sentinel and
/// everything above it is outside the indexed range for both entry points, and
/// the value one below still proves and verifies.
fn sentinel_scenario() -> Value {
    let sentinel = BigUint::from_str_radix(HIGHEST_ADDRESS_PLUS_ONE, 10).expect("sentinel");
    let mut tree = Indexed::new(4, 0).expect("indexed tree");
    let mut steps = vec![indexed_observed(
        json!({ "op": "construct" }),
        Ok(None),
        &tree,
    )];
    for value in [BigUint::from(30u32), BigUint::from(10u32)] {
        steps.push(indexed_append(&mut tree, &value));
    }
    for value in [
        sentinel.clone(),
        &sentinel + 1u32,
        &sentinel * 2u32,
        &sentinel - 1u32,
    ] {
        steps.push(indexed_proof(&tree, &value));
        steps.push(indexed_append(&mut tree, &value));
    }

    json!({
        "id": "sentinel-closes-the-indexed-range",
        "tree": tree_config(4, 0, None),
        "steps": steps,
    })
}

/// A rejected indexed append restores the element list, so the tree keeps
/// proving from the same root afterwards. Zero is excluded from below by
/// `zolana_indexed_array`, and an existing value has no exclusion range.
fn indexed_rejection_scenario() -> Value {
    let custom = BigUint::from(100u32);
    let mut tree = Indexed::new_with_next_value(4, 0, custom.clone()).expect("indexed tree");
    let mut steps = vec![indexed_observed(
        json!({ "op": "construct" }),
        Ok(None),
        &tree,
    )];
    steps.push(indexed_append(&mut tree, &BigUint::from(30u32)));
    for value in [BigUint::from(0u32), custom.clone(), BigUint::from(150u32)] {
        steps.push(indexed_append(&mut tree, &value));
    }
    steps.push(indexed_proof(&tree, &BigUint::from(30u32)));
    steps.push(indexed_proof(&tree, &BigUint::from(35u32)));
    steps.push(indexed_append(&mut tree, &BigUint::from(35u32)));

    json!({
        "id": "rejected-indexed-appends-leave-the-tree-provable",
        "tree": tree_config(4, 0, None),
        "sentinel": custom.to_str_radix(10),
        "steps": steps,
    })
}

fn indexed_append(tree: &mut Indexed, value: &BigUint) -> Value {
    let outcome = tree
        .append(value)
        .map(|()| None)
        .map_err(|error| format!("{error:?}"));
    indexed_observed(
        json!({ "op": "append", "valueDecimal": value.to_str_radix(10) }),
        outcome,
        tree,
    )
}

fn indexed_proof(tree: &Indexed, value: &BigUint) -> Value {
    let outcome = tree
        .get_non_inclusion_proof(value)
        .map(|proof| Some(tree.verify_non_inclusion_proof(&proof).is_ok()))
        .map_err(|error| format!("{error:?}"));
    indexed_observed(
        json!({ "op": "nonInclusionProof", "valueDecimal": value.to_str_radix(10) }),
        outcome,
        tree,
    )
}

fn tree_config(height: usize, canopy_depth: usize, history: Option<(usize, usize)>) -> Value {
    match history {
        Some((offset, length)) => json!({
            "height": height.to_string(),
            "canopyDepth": canopy_depth.to_string(),
            "rootHistoryStartOffset": offset.to_string(),
            "rootHistoryArrayLength": length.to_string(),
        }),
        None => json!({
            "height": height.to_string(),
            "canopyDepth": canopy_depth.to_string(),
        }),
    }
}

fn observed(step: Value, outcome: Result<(), String>, tree: &Tree) -> Value {
    merge(
        step,
        json!({
            "outcome": arm(outcome.map(|()| Value::Null)),
            "state": {
                "rootHex": hex(&tree.root()),
                "nextIndex": tree.get_next_index().to_string(),
                "leafCount": tree.leaves().len().to_string(),
                "rootHistoryLength": tree.roots.len().to_string(),
                "sequenceNumber": tree.sequence_number.to_string(),
                "historyRootIndex": arm(
                    tree.get_history_root_index()
                        .map(|index| Value::String(index.to_string()))
                        .map_err(|error| format!("{error:?}")),
                ),
                "historyRootIndexV2": arm(
                    tree.get_history_root_index_v2()
                        .map(|index| Value::String(index.to_string()))
                        .map_err(|error| format!("{error:?}")),
                ),
            },
        }),
    )
}

fn indexed_observed(step: Value, outcome: Result<Option<bool>, String>, tree: &Indexed) -> Value {
    merge(
        step,
        json!({
            "outcome": arm(outcome.map(|verified| match verified {
                Some(verified) => json!({ "verified": verified }),
                None => Value::Null,
            })),
            "state": {
                "rootHex": hex(&tree.root()),
                "elementCount": tree.indexed_array.elements.len().to_string(),
                "nextIndex": tree.merkle_tree.get_next_index().to_string(),
                "highestValue": tree.indexed_array.highest_value.to_str_radix(10),
            },
        }),
    )
}

/// A rejection travels as its Rust `Debug` form. The two languages do not share
/// an error taxonomy, so the TypeScript test maps each name to the code it
/// expects rather than comparing the strings.
fn arm(outcome: Result<Value, String>) -> Value {
    match outcome {
        Ok(Value::Null) => json!({ "arm": "ok" }),
        Ok(value) => json!({ "arm": "ok", "value": value }),
        Err(error) => json!({ "arm": "err", "error": error }),
    }
}

fn merge(left: Value, right: Value) -> Value {
    let mut merged = left.as_object().cloned().unwrap_or_default();
    for (key, value) in right.as_object().cloned().unwrap_or_default() {
        merged.insert(key, value);
    }
    Value::Object(merged)
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
