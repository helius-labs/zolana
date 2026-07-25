//! W-07: Merkle path, root, subtree, canopy, and indexed-array operations.
//!
//! `MerkleTree` and `IndexedMerkleTree` are stateful, and the oracle boundary
//! carries no handles, so each entry point rebuilds a tree from the leaves it is
//! given and answers one query. Rebuilding is not a simplification of the Rust
//! API: append order is the only way tree state is reached in Rust either.

use serde::Deserialize;
use wasm_bindgen::prelude::wasm_bindgen;
use zolana_hasher::{zero_bytes::MAX_HEIGHT, Hasher, Keccak, Poseidon, Sha256};
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};

use crate::{
    codec::{decode_biguint, decode_exact, decode_usize, BAD_HEX, BAD_INTEGER},
    outcome::{err, err_boundary, ok, ok_hex, ok_hex_list},
};

/// `MerkleTree::new` reads `H::zero_bytes()[height]`, and `zero_bytes` holds
/// `MAX_HEIGHT + 1` entries, so height 41 and above indexes out of bounds. The
/// TypeScript constructor accepts up to 63 because it derives its zero hashes
/// instead of reading a table.
const ORACLE_MAX_HEIGHT: usize = MAX_HEIGHT;

/// `get_history_root_index` casts its result with `try_into().unwrap()`, so a
/// history length above `u16::MAX` can panic, and `% len` divides by zero at 0.
const ORACLE_MAX_HISTORY_LEN: usize = u16::MAX as usize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TreeRequest {
    hasher: String,
    height: String,
    canopy_depth: String,
    leaves: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexQuery {
    #[serde(flatten)]
    tree: TreeRequest,
    index: String,
    full: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerifyQuery {
    #[serde(flatten)]
    tree: TreeRequest,
    leaf: String,
    proof: Vec<String>,
    index: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HistoryQuery {
    #[serde(flatten)]
    tree: TreeRequest,
    root_history_start_offset: String,
    root_history_array_len: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexedRequest {
    hasher: String,
    height: String,
    canopy_depth: String,
    /// Decimal values appended through `IndexedMerkleTree::append`.
    values: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexedQuery {
    #[serde(flatten)]
    tree: IndexedRequest,
    value: String,
}

#[wasm_bindgen]
pub fn merkle_root(request: &str) -> String {
    dispatch(request, |tree: MerkleTree<Poseidon>| ok_hex(&tree.root()))
}

#[wasm_bindgen]
pub fn merkle_subtrees(request: &str) -> String {
    dispatch(request, |tree: MerkleTree<Poseidon>| {
        ok_hex_list(tree.get_subtrees().iter())
    })
}

#[wasm_bindgen]
pub fn merkle_canopy(request: &str) -> String {
    dispatch(request, |tree: MerkleTree<Poseidon>| {
        match tree.get_canopy() {
            Ok(canopy) => ok_hex_list(canopy.iter()),
            Err(error) => err(error),
        }
    })
}

#[wasm_bindgen]
pub fn merkle_proof(request: &str) -> String {
    index_query(request, |tree, index, full| {
        match tree.get_proof_of_leaf(index, full) {
            Ok(proof) => ok_hex_list(proof.iter()),
            Err(error) => err(error),
        }
    })
}

#[wasm_bindgen]
pub fn merkle_path(request: &str) -> String {
    index_query(request, |tree, index, full| {
        match tree.get_path_of_leaf(index, full) {
            Ok(path) => ok_hex_list(path.iter()),
            Err(error) => err(error),
        }
    })
}

#[wasm_bindgen]
pub fn merkle_leaf(request: &str) -> String {
    index_query(request, |tree, index, _full| match tree.get_leaf(index) {
        Ok(leaf) => ok_hex(&leaf),
        Err(error) => err(error),
    })
}

#[wasm_bindgen]
pub fn merkle_verify(request: &str) -> String {
    let query: VerifyQuery = match serde_json::from_str(request) {
        Ok(query) => query,
        Err(error) => return err_boundary("OracleMalformedRequest", error.to_string()),
    };
    let leaf = match decode_exact::<32>(&query.leaf) {
        Ok(leaf) => leaf,
        Err(details) => return err_boundary(BAD_HEX, details),
    };
    let mut proof = Vec::with_capacity(query.proof.len());
    for (position, element) in query.proof.iter().enumerate() {
        match decode_exact::<32>(element) {
            Ok(node) => proof.push(node),
            Err(details) => {
                return err_boundary(BAD_HEX, format!("proof[{position}]: {details}"));
            }
        }
    }
    let index = match decode_usize(&query.index) {
        Ok(index) => index,
        Err(details) => return err_boundary(BAD_INTEGER, details),
    };
    with_tree(&query.tree, move |tree: MerkleTree<Poseidon>| {
        match tree.verify(&leaf, &proof, index) {
            Ok(matched) => ok(serde_json::Value::Bool(matched)),
            Err(error) => err(error),
        }
    })
}

#[wasm_bindgen]
pub fn merkle_history_root_index(request: &str) -> String {
    history_query(request, false)
}

#[wasm_bindgen]
pub fn merkle_history_root_index_v2(request: &str) -> String {
    history_query(request, true)
}

#[wasm_bindgen]
pub fn indexed_root(request: &str) -> String {
    indexed_tree(request, |tree| ok_hex(&tree.root()))
}

#[wasm_bindgen]
pub fn indexed_non_inclusion_proof(request: &str) -> String {
    let query: IndexedQuery = match serde_json::from_str(request) {
        Ok(query) => query,
        Err(error) => return err_boundary("OracleMalformedRequest", error.to_string()),
    };
    let value = match decode_biguint(&query.value) {
        Ok(value) => value,
        Err(details) => return err_boundary(BAD_INTEGER, details),
    };
    with_indexed_tree(&query.tree, move |tree| {
        match tree.get_non_inclusion_proof(&value) {
            Ok(proof) => ok(serde_json::json!({
                "root": crate::outcome::hex(&proof.root),
                "value": crate::outcome::hex(&proof.value),
                "leafLowerRangeValue": crate::outcome::hex(&proof.leaf_lower_range_value),
                "leafHigherRangeValue": crate::outcome::hex(&proof.leaf_higher_range_value),
                "leafIndex": proof.leaf_index.to_string(),
                "nextIndex": proof.next_index.to_string(),
                "merkleProof": proof
                    .merkle_proof
                    .iter()
                    .map(|node| crate::outcome::hex(node))
                    .collect::<Vec<_>>(),
            })),
            Err(error) => err(error),
        }
    })
}

/// Feeds `get_non_inclusion_proof`'s own output straight back into
/// `verify_non_inclusion_proof` on the same tree. Nothing crosses the boundary
/// between the two calls, so a rejection here is Rust disagreeing with itself
/// rather than a boundary artifact.
#[wasm_bindgen]
pub fn indexed_non_inclusion_proof_round_trip(request: &str) -> String {
    let query: IndexedQuery = match serde_json::from_str(request) {
        Ok(query) => query,
        Err(error) => return err_boundary("OracleMalformedRequest", error.to_string()),
    };
    let value = match decode_biguint(&query.value) {
        Ok(value) => value,
        Err(details) => return err_boundary(BAD_INTEGER, details),
    };
    with_indexed_tree(&query.tree, move |tree| {
        let proof = match tree.get_non_inclusion_proof(&value) {
            Ok(proof) => proof,
            Err(error) => return err(error),
        };
        match tree.verify_non_inclusion_proof(&proof) {
            Ok(()) => ok(serde_json::Value::String("verified".to_string())),
            Err(error) => err(error),
        }
    })
}

fn history_query(request: &str, v2: bool) -> String {
    let query: HistoryQuery = match serde_json::from_str(request) {
        Ok(query) => query,
        Err(error) => return err_boundary("OracleMalformedRequest", error.to_string()),
    };
    let offset = match decode_usize(&query.root_history_start_offset) {
        Ok(offset) => offset,
        Err(details) => return err_boundary(BAD_INTEGER, details),
    };
    let length = match decode_usize(&query.root_history_array_len) {
        Ok(length) => length,
        Err(details) => return err_boundary(BAD_INTEGER, details),
    };
    if length == 0 || length > ORACLE_MAX_HISTORY_LEN {
        return err_boundary(
            "OracleUnrepresentableHistoryLength",
            format!("root_history_array_len {length} is outside 1..={ORACLE_MAX_HISTORY_LEN}"),
        );
    }
    let leaf_count = query.tree.leaves.len();
    if !v2 && offset > leaf_count {
        return err_boundary(
            "OracleHistoryOffsetAboveIndex",
            format!("root_history_start_offset {offset} exceeds rightmost index {leaf_count}"),
        );
    }
    let bounds = match tree_bounds(&query.tree) {
        Ok(bounds) => bounds,
        Err(rejection) => return rejection,
    };
    let leaves = match decode_leaves(&query.tree.leaves) {
        Ok(leaves) => leaves,
        Err(rejection) => return rejection,
    };
    fn run<H: Hasher>(
        bounds: (usize, usize),
        leaves: &[[u8; 32]],
        offset: usize,
        length: usize,
        v2: bool,
    ) -> String {
        let mut tree = MerkleTree::<H>::new_with_history(bounds.0, bounds.1, offset, length);
        for leaf in leaves {
            if let Err(error) = tree.append(leaf) {
                return err(error);
            }
        }
        let result = if v2 {
            tree.get_history_root_index_v2()
        } else {
            tree.get_history_root_index()
        };
        match result {
            Ok(index) => ok(serde_json::Value::String(index.to_string())),
            Err(error) => err(error),
        }
    }
    match query.tree.hasher.as_str() {
        "poseidon" => run::<Poseidon>(bounds, &leaves, offset, length, v2),
        "sha256" => run::<Sha256>(bounds, &leaves, offset, length, v2),
        "keccak" => run::<Keccak>(bounds, &leaves, offset, length, v2),
        other => err_boundary("OracleUnknownHasher", other.to_string()),
    }
}

fn index_query<F>(request: &str, run: F) -> String
where
    F: FnOnce(MerkleTree<Poseidon>, usize, bool) -> String,
{
    let query: IndexQuery = match serde_json::from_str(request) {
        Ok(query) => query,
        Err(error) => return err_boundary("OracleMalformedRequest", error.to_string()),
    };
    let index = match decode_usize(&query.index) {
        Ok(index) => index,
        Err(details) => return err_boundary(BAD_INTEGER, details),
    };
    let full = query.full;
    with_tree(&query.tree, move |tree| run(tree, index, full))
}

fn dispatch<F>(request: &str, run: F) -> String
where
    F: FnOnce(MerkleTree<Poseidon>) -> String,
{
    let query: TreeRequest = match serde_json::from_str(request) {
        Ok(query) => query,
        Err(error) => return err_boundary("OracleMalformedRequest", error.to_string()),
    };
    with_tree(&query, run)
}

fn with_tree<F>(request: &TreeRequest, run: F) -> String
where
    F: FnOnce(MerkleTree<Poseidon>) -> String,
{
    let (height, canopy_depth) = match tree_bounds(request) {
        Ok(bounds) => bounds,
        Err(rejection) => return rejection,
    };
    if request.hasher != "poseidon" {
        return err_boundary("OracleUnknownHasher", request.hasher.clone());
    }
    let leaves = match decode_leaves(&request.leaves) {
        Ok(leaves) => leaves,
        Err(rejection) => return rejection,
    };
    let mut tree = MerkleTree::<Poseidon>::new(height, canopy_depth);
    for leaf in &leaves {
        if let Err(error) = tree.append(leaf) {
            return err(error);
        }
    }
    run(tree)
}

fn indexed_tree<F>(request: &str, run: F) -> String
where
    F: FnOnce(IndexedMerkleTree<Poseidon, usize>) -> String,
{
    let query: IndexedRequest = match serde_json::from_str(request) {
        Ok(query) => query,
        Err(error) => return err_boundary("OracleMalformedRequest", error.to_string()),
    };
    with_indexed_tree(&query, run)
}

fn with_indexed_tree<F>(request: &IndexedRequest, run: F) -> String
where
    F: FnOnce(IndexedMerkleTree<Poseidon, usize>) -> String,
{
    if request.hasher != "poseidon" {
        return err_boundary("OracleUnknownHasher", request.hasher.clone());
    }
    let height = match bounded_height(&request.height) {
        Ok(height) => height,
        Err(rejection) => return rejection,
    };
    let canopy_depth = match bounded_canopy(&request.canopy_depth, height) {
        Ok(canopy_depth) => canopy_depth,
        Err(rejection) => return rejection,
    };
    let mut values = Vec::with_capacity(request.values.len());
    for value in &request.values {
        match decode_biguint(value) {
            Ok(value) => values.push(value),
            Err(details) => return err_boundary(BAD_INTEGER, details),
        }
    }
    let mut tree = match IndexedMerkleTree::<Poseidon, usize>::new(height, canopy_depth) {
        Ok(tree) => tree,
        Err(error) => return err(error),
    };
    for value in &values {
        if let Err(error) = tree.append(value) {
            return err(error);
        }
    }
    run(tree)
}

fn tree_bounds(request: &TreeRequest) -> Result<(usize, usize), String> {
    let height = bounded_height(&request.height)?;
    let canopy_depth = bounded_canopy(&request.canopy_depth, height)?;
    Ok((height, canopy_depth))
}

fn bounded_height(value: &str) -> Result<usize, String> {
    let height = decode_usize(value).map_err(|details| err_boundary(BAD_INTEGER, details))?;
    if height == 0 || height > ORACLE_MAX_HEIGHT {
        return Err(err_boundary(
            "OracleUnrepresentableHeight",
            format!("height {height} is outside 1..={ORACLE_MAX_HEIGHT}"),
        ));
    }
    Ok(height)
}

fn bounded_canopy(value: &str, height: usize) -> Result<usize, String> {
    let canopy_depth = decode_usize(value).map_err(|details| err_boundary(BAD_INTEGER, details))?;
    if canopy_depth > height {
        return Err(err_boundary(
            "OracleCanopyAboveHeight",
            format!("canopy_depth {canopy_depth} exceeds height {height}"),
        ));
    }
    Ok(canopy_depth)
}

fn decode_leaves(leaves: &[String]) -> Result<Vec<[u8; 32]>, String> {
    let mut decoded = Vec::with_capacity(leaves.len());
    for (position, leaf) in leaves.iter().enumerate() {
        let node = decode_exact::<32>(leaf)
            .map_err(|details| err_boundary(BAD_HEX, format!("leaves[{position}]: {details}")))?;
        decoded.push(node);
    }
    Ok(decoded)
}
