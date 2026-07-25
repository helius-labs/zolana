//! Generates the wallet action vectors that `@zolana/wallet` checks itself
//! against.
//!
//! Row W04 turns on which inputs `create_withdrawal` and `create_split` accept
//! and which rejection each refusal carries. Both answers live in Rust control
//! flow that no fixture froze: `create_withdrawal` performs no amount check at
//! all, `select_inputs` stops at the first note that covers the request, and
//! `select_split_utxo` distinguishes a zone-bound note from a data-carrying one.
//! Reading the two languages for that is how a strictness regression got past
//! review once already, so this binary calls the real entry points over a matrix
//! of wallets and requests and records the decision each one reaches.
//!
//! The wallets are described declaratively rather than by their hashes, because
//! the port has to build the same wallet to replay a case. A note's commitment
//! hash is `[index + 1; 32]` and its nullifier `[index + 20; 32]`, which the
//! `input` field of a case refers to by index.
//!
//! ```text
//! cargo run -p xtask --bin wallet-actions            # write the fixture
//! cargo run -p xtask --bin wallet-actions -- --check # fail on any drift
//! ```

use std::{collections::BTreeMap, env, fs, path::PathBuf, process::ExitCode};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_keypair::shielded::ShieldedKeypair;
use zolana_transaction::{AssetRegistry, Data, OutputContext, Utxo, Wallet, WalletUtxo, SOL_MINT};
use zolana_wallet::{create_split, create_withdrawal, SplitParams, WithdrawalParams};

const FIXTURE: &str = "sdk-libs/ts/vectors/wallet-actions-v1.json";

const PRIMARY_TREE: Address = Address::new_from_array([17u8; 32]);
const SECONDARY_TREE: Address = Address::new_from_array([9u8; 32]);
const ZONE_PROGRAM: Address = Address::new_from_array([7u8; 32]);
const U64_MAX: u64 = u64::MAX;

/// A note as the fixture describes it, so the port can rebuild the same wallet.
#[derive(Clone, Copy)]
struct Note {
    amount: u64,
    tree: &'static str,
    kind: &'static str,
}

const fn plain(amount: u64) -> Note {
    Note {
        amount,
        tree: "primary",
        kind: "plain",
    }
}

const fn on_secondary(amount: u64) -> Note {
    Note {
        amount,
        tree: "secondary",
        kind: "plain",
    }
}

const fn zone_bound(amount: u64) -> Note {
    Note {
        amount,
        tree: "primary",
        kind: "zoneBound",
    }
}

const fn with_data(amount: u64) -> Note {
    Note {
        amount,
        tree: "primary",
        kind: "withData",
    }
}

/// Every wallet a case can name. Kept in one table so the fixture can publish
/// the descriptions and the port can build each one exactly once.
fn wallets() -> BTreeMap<&'static str, Vec<Note>> {
    BTreeMap::from([
        ("empty", vec![]),
        ("ascending", vec![plain(3), plain(8), plain(12)]),
        ("indivisible", vec![plain(11)]),
        ("two-trees", vec![plain(4), on_secondary(10)]),
        ("overflowing", vec![plain(1), plain(U64_MAX)]),
        ("zone-bound", vec![zone_bound(12)]),
        ("data-carrying", vec![with_data(12)]),
        (
            "zone-bound-beside-plain",
            vec![plain(12), zone_bound(1_000)],
        ),
    ])
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wallet-actions failed: {error:#}");
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
                    "Generate the Rust-side wallet action vectors.\n\nusage: cargo run -p xtask --bin wallet-actions -- [--check]"
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
            bail!("{FIXTURE} is stale; rerun `cargo run -p xtask --bin wallet-actions`");
        }
        return Ok(());
    }

    fs::write(&path, rendered).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn build() -> Result<Value> {
    let described = wallets()
        .into_iter()
        .map(|(id, notes)| {
            let notes: Vec<Value> = notes
                .iter()
                .map(|note| {
                    json!({
                        "amount": note.amount.to_string(),
                        "tree": note.tree,
                        "kind": note.kind,
                    })
                })
                .collect();
            (id.to_string(), Value::Array(notes))
        })
        .collect::<Map<_, _>>();

    Ok(json!({
        "generator": "cargo run -p xtask --bin wallet-actions",
        "rustSource": ["sdk-libs/wallet/src/actions/transaction.rs"],
        "trees": {
            "primary": PRIMARY_TREE.to_string(),
            "secondary": SECONDARY_TREE.to_string(),
        },
        "zoneProgram": ZONE_PROGRAM.to_string(),
        "wallets": Value::Object(described),
        "withdrawals": withdrawals()?,
        "splits": splits()?,
    }))
}

/// `create_withdrawal` has no amount guard, so the accepted amounts are exactly
/// those `select_inputs` can cover, zero included, and the note count is where
/// its first-fit loop stopped.
fn withdrawals() -> Result<Value> {
    let cases = [
        ("ascending", 0u64),
        ("ascending", 1),
        ("ascending", 3),
        ("ascending", 4),
        ("ascending", 11),
        ("ascending", 12),
        ("ascending", 23),
        ("ascending", 24),
        ("ascending", U64_MAX),
        ("empty", 0),
        ("two-trees", 4),
        ("overflowing", U64_MAX),
        ("zone-bound", 12),
    ];

    cases
        .into_iter()
        .map(|(wallet_id, amount)| {
            let (keypair, wallet) = build_wallet(wallet_id)?;
            let outcome = create_withdrawal(WithdrawalParams {
                wallet: &wallet,
                payer: Address::default(),
                recipient: Pubkey::new_from_array([5u8; 32]),
                asset: SOL_MINT,
                amount,
            })
            .map(|created| json!({ "inputCount": created.transaction.input_count().to_string() }))
            .map_err(|error| format!("{error:?}"));
            drop(keypair);
            Ok(json!({
                "wallet": wallet_id,
                "amount": amount.to_string(),
                "outcome": arm(outcome),
            }))
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

/// `create_split` rejects an arity outside `2..=8` before it looks at any note,
/// auto-selects the largest plain note that divides evenly, and separates a
/// zone-bound refusal from a data-carrying one.
fn splits() -> Result<Value> {
    let cases: [(&str, u8, Option<usize>); 15] = [
        ("ascending", 0, None),
        ("ascending", 1, None),
        ("ascending", 2, None),
        ("ascending", 3, None),
        ("ascending", 4, None),
        ("ascending", 8, None),
        ("ascending", 9, None),
        ("indivisible", 2, None),
        ("empty", 2, None),
        ("zone-bound", 2, None),
        ("data-carrying", 2, None),
        ("zone-bound-beside-plain", 2, None),
        ("zone-bound-beside-plain", 2, Some(1)),
        // A data-carrying note is only reachable by name: the auto-select filter
        // drops it, so the wallet looks empty instead.
        ("data-carrying", 2, Some(0)),
        ("ascending", 2, Some(9)),
    ];

    cases
        .into_iter()
        .map(|(wallet_id, parts, input)| {
            let (keypair, wallet) = build_wallet(wallet_id)?;
            let outcome = create_split(SplitParams {
                wallet: &wallet,
                payer: Address::default(),
                asset: SOL_MINT,
                parts,
                input: input.map(note_hash),
            })
            .map(|created| {
                json!({
                    "numOutputs": created.num_outputs.to_string(),
                    "perOutputAmount": created.per_output_amount.to_string(),
                    "inputCount": created.transaction.input_count().to_string(),
                })
            })
            .map_err(|error| format!("{error:?}"));
            drop(keypair);
            Ok(json!({
                "wallet": wallet_id,
                "parts": parts.to_string(),
                "input": input.map_or(Value::Null, |index| Value::String(index.to_string())),
                "outcome": arm(outcome),
            }))
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

/// The commitment hash of the note at `index`. Case `input` fields name a note
/// by index, and an index past the end names a hash the wallet does not hold.
fn note_hash(index: usize) -> [u8; 32] {
    [u8::try_from(index + 1).expect("note index fits a byte"); 32]
}

fn build_wallet(id: &str) -> Result<(ShieldedKeypair, Wallet)> {
    let notes = wallets()
        .remove(id)
        .with_context(|| format!("no wallet named {id}"))?;
    let keypair = ShieldedKeypair::new().context("shielded keypair")?;
    let mut wallet = Wallet::new(
        keypair.shielded_address().context("shielded address")?,
        AssetRegistry::new(Vec::new()).context("asset registry")?,
    )
    .context("wallet")?;
    for (index, note) in notes.iter().enumerate() {
        let mut blinding = [0u8; 31];
        blinding[30] = u8::try_from(index + 1).expect("note index fits a byte");
        wallet.utxos.push(WalletUtxo {
            utxo: Utxo {
                owner: keypair.signing_pubkey(),
                asset: SOL_MINT,
                amount: note.amount,
                blinding,
                zone_program_id: (note.kind == "zoneBound").then_some(ZONE_PROGRAM),
                data: Data::new(Vec::new()),
            },
            output_context: OutputContext {
                hash: note_hash(index),
                tree: match note.tree {
                    "primary" => PRIMARY_TREE,
                    "secondary" => SECONDARY_TREE,
                    other => bail!("no tree named {other}"),
                },
                leaf_index: u64::try_from(index).expect("note index fits a u64"),
            },
            nullifier: [u8::try_from(index + 20).expect("note index fits a byte"); 32],
            data_hash: (note.kind == "withData").then_some([3u8; 32]),
            zone_data_hash: None,
            spent: false,
        });
    }
    Ok((keypair, wallet))
}

/// A rejection travels as its Rust `Debug` form. The two languages do not share
/// an error taxonomy, so the port maps each variant to the code it raises rather
/// than comparing the strings.
fn arm(outcome: Result<Value, String>) -> Value {
    match outcome {
        Ok(value) => json!({ "arm": "ok", "value": value }),
        Err(error) => json!({ "arm": "err", "error": error }),
    }
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
