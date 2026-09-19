#![cfg(feature = "indexer-api")]
//! The witness reader's tree handling, pinned through its public surface.
//!
//! `WitnessReader::input_witnesses` takes no tree: each input names the raw id
//! it was published under, so the reader groups the inputs by that id, asks one
//! `pda::tree(tree_id)` per group, and puts the answers back in the caller's
//! order. Two things can go wrong silently and are what this target exists for:
//!
//! - **Order.** `InputWitnesses::spend_proofs` is consumed positionally by
//!   `attach_input_proofs`, so a reader that concatenated its per-tree answers
//!   would bind every witness to the wrong input and report nothing. Only
//!   inputs whose trees *interleave* expose that: a single-tree transaction, or
//!   one where tree A's inputs all precede tree B's, passes either way.
//! - **Tree.** A proof from a tree the input does not name must be refused, and
//!   the refusal has to come from the input's own id rather than from something
//!   the caller passed alongside.
//!
//! The indexer here answers every request out of the request itself, so
//! per-group validation succeeds whatever order the reader fetched in. That
//! leaves the returned order as the only thing an assertion can fail on.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
};

use serde_json::{json, Value};
use solana_address::Address;
use zolana_client::{
    AsyncWitnessReader, AsyncZolanaIndexer, ClientError, InputWitnesses, WitnessReader,
    ZolanaIndexer, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_interface::pda;
use zolana_transaction::utxo::SppProofInputUtxo;

/// Two trees whose inputs alternate. Fetching per tree and concatenating
/// returns tree 7's two witnesses first, which `attach_input_proofs` would then
/// bind to inputs 1 and 2.
const INTERLEAVED: [(u16, u8); 4] = [(7, 10), (9, 11), (7, 12), (9, 13)];

fn input(_index: usize, tree_id: u16, seed: u8) -> SppProofInputUtxo {
    SppProofInputUtxo {
        utxo_hash: [seed; 32],
        nullifier: [seed | 0x80; 32],
        tree_id,
        ..SppProofInputUtxo::dummy(tree_id).unwrap()
    }
}

fn interleaved_inputs() -> Vec<SppProofInputUtxo> {
    INTERLEAVED
        .iter()
        .enumerate()
        .map(|(index, (tree_id, seed))| input(index, *tree_id, *seed))
        .collect()
}

fn assert_in_input_order(witnesses: &InputWitnesses, inputs: &[SppProofInputUtxo]) {
    let leaves: Vec<[u8; 32]> = witnesses
        .spend_proofs
        .iter()
        .map(|proof| proof.state.leaf)
        .collect();
    assert_eq!(
        leaves,
        inputs
            .iter()
            .map(|input| input.utxo_hash)
            .collect::<Vec<_>>()
    );

    let nullifiers: Vec<[u8; 32]> = witnesses
        .spend_proofs
        .iter()
        .map(|proof| proof.nullifier.leaf)
        .collect();
    assert_eq!(
        nullifiers,
        inputs
            .iter()
            .map(|input| input.nullifier)
            .collect::<Vec<_>>()
    );

    let trees: Vec<Address> = witnesses
        .spend_proofs
        .iter()
        .map(|proof| proof.state.merkle_context.tree)
        .collect();
    assert_eq!(
        trees,
        inputs
            .iter()
            .map(|input| pda::tree(input.tree_id))
            .collect::<Vec<_>>()
    );
}

#[test]
fn witnesses_from_interleaved_trees_come_back_in_input_order() {
    let indexer = ZolanaIndexer::new(spawn_echo_indexer(TreeAnswer::AsAsked));
    let inputs = interleaved_inputs();

    let witnesses = WitnessReader::input_witnesses(
        &indexer,
        &inputs.iter().collect::<Vec<_>>(),
        &[[0x55; 32]],
        None,
    )
    .expect("witnesses");

    assert_in_input_order(&witnesses, &inputs);
    // Padding is hashed under the first input tree, so its non-inclusion
    // witness has to come from that tree rather than from whichever tree
    // happened to be fetched last.
    assert_eq!(witnesses.dummy_nullifier_proofs.len(), 1);
    let dummy = witnesses
        .dummy_nullifier_proofs
        .first()
        .expect("one padding witness");
    assert_eq!(dummy.leaf, [0x55; 32]);
    assert_eq!(dummy.merkle_context.tree, pda::tree(7));
}

#[tokio::test]
async fn async_witnesses_from_interleaved_trees_come_back_in_input_order() {
    let indexer = AsyncZolanaIndexer::new(spawn_echo_indexer(TreeAnswer::AsAsked));
    let inputs = interleaved_inputs();

    let witnesses = AsyncWitnessReader::input_witnesses(
        &indexer,
        &inputs.iter().collect::<Vec<_>>(),
        &[],
        None,
    )
    .await
    .expect("witnesses");

    assert_in_input_order(&witnesses, &inputs);
    assert!(witnesses.dummy_nullifier_proofs.is_empty());
}

/// The tree a proof must come from is the one the input names.
#[test]
fn a_proof_from_another_tree_is_refused() {
    let indexer = ZolanaIndexer::new(spawn_echo_indexer(TreeAnswer::AlwaysTreeZero));
    let inputs = [input(0, 7, 10)];

    assert!(matches!(
        WitnessReader::input_witnesses(&indexer, &inputs.iter().collect::<Vec<_>>(), &[], None),
        Err(ClientError::StateProofTreeMismatch { index: 0 })
    ));
}

/// Padding names no tree of its own, so without a real input there is nothing
/// to prove it against.
#[test]
fn padding_without_a_real_input_is_refused() {
    let indexer = ZolanaIndexer::new(spawn_echo_indexer(TreeAnswer::AsAsked));

    assert!(matches!(
        WitnessReader::input_witnesses(&indexer, &[], &[[0x55; 32]], None),
        Err(ClientError::NoInputs)
    ));
}

// ---------------------------------------------------------------------------
// A loopback indexer that answers out of the request.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum TreeAnswer {
    /// Name the tree account the request asked for.
    AsAsked,
    /// Name tree 0 whatever was asked for, so a reader that does not check the
    /// tree against the input's own id lets a foreign proof through.
    AlwaysTreeZero,
}

fn encode(bytes: [u8; 32]) -> String {
    bs58::encode(bytes).into_string()
}

fn echo_proofs(path: &str, body: &Value, answer: TreeAnswer) -> Value {
    let params = &body["params"];
    let asked = params["treeAccount"]
        .as_str()
        .expect("request names a tree account")
        .to_string();
    let tree = match answer {
        TreeAnswer::AsAsked => asked,
        TreeAnswer::AlwaysTreeZero => bs58::encode(pda::tree(0).to_bytes()).into_string(),
    };
    let leaves = params["leaves"]
        .as_array()
        .cloned()
        .expect("request names leaves");
    let proofs: Vec<Value> = leaves
        .iter()
        .map(|leaf| match path {
            "/getMerkleProofs" => json!({
                "leaf": leaf,
                "merkleContext": { "treeType": 1, "tree": tree },
                "path": vec![encode([0u8; 32]); STATE_TREE_HEIGHT],
                "leafIndex": 0,
                "root": encode([3u8; 32]),
                "rootSeq": 1,
                "rootIndex": 0,
            }),
            "/getNonInclusionProofs" => json!({
                "leaf": leaf,
                "merkleContext": { "treeType": 2, "tree": tree },
                "path": vec![encode([0u8; 32]); NULLIFIER_TREE_HEIGHT],
                "lowElement": encode([0u8; 32]),
                "lowElementIndex": 0,
                "highElement": encode([u8::MAX; 32]),
                "highElementIndex": 1,
                "root": encode([4u8; 32]),
                "rootSeq": 1,
                "rootIndex": 0,
            }),
            other => panic!("the witness reader asked for {other}"),
        })
        .collect();

    json!({
        "id": body["id"].clone(),
        "jsonrpc": "2.0",
        "result": {
            "context": { "blockTime": 1, "slot": 1 },
            "proofs": proofs,
        },
    })
}

/// Serves for as long as a test keeps asking. Each connection is handled on its
/// own thread because the reader fetches concurrently, and nothing joins them:
/// the listener lives until the test binary exits.
fn spawn_echo_indexer(answer: TreeAnswer) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock indexer");
    let url = format!(
        "http://{}",
        listener.local_addr().expect("mock indexer port")
    );
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                while let Some((path, body)) = read_request(&mut stream) {
                    let response = echo_proofs(&path, &body, answer);
                    write_response(&mut stream, &response);
                }
            });
        }
    });
    url
}

/// `None` once the peer closes the connection.
fn read_request(stream: &mut TcpStream) -> Option<(String, Value)> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];
    let mut body_start = None;
    let mut content_length = None;
    loop {
        let read = stream.read(&mut buffer).ok()?;
        if read == 0 {
            return None;
        }
        data.extend_from_slice(buffer.get(..read)?);
        if body_start.is_none() {
            if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                body_start = Some(index.saturating_add(4));
                let headers = String::from_utf8_lossy(data.get(..index)?).to_string();
                content_length = headers.lines().find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                });
            }
        }
        if let (Some(start), Some(length)) = (body_start, content_length) {
            if data.len() >= start.saturating_add(length) {
                break;
            }
        }
    }

    let start = body_start?;
    let headers = String::from_utf8_lossy(data.get(..start)?).to_string();
    let path = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))?
        .to_string();
    let body = serde_json::from_slice(data.get(start..)?).ok()?;
    Some((path, body))
}

fn write_response(stream: &mut TcpStream, body: &Value) {
    let body = serde_json::to_string(body).expect("serialize mock response");
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .expect("write mock response");
}
