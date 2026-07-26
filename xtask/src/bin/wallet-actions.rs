//! Generates the wallet action vectors that `@zolana/wallet` checks itself
//! against.
//!
//! Row W04 turns on which inputs `create_withdrawal`, `create_split`, and
//! `create_merge` accept and which rejection each refusal carries. Those answers
//! live in Rust control flow that no fixture froze: `create_withdrawal` performs
//! no amount check at all, `select_inputs` stops at the first note that covers
//! the request, `select_split_utxo` distinguishes a zone-bound note from a
//! data-carrying one, and `create_merge` needs an optional tree selector once
//! holdings straddle a rollover. Reading the two languages for that is how a
//! strictness regression got past review once already, so this binary calls the
//! real entry points over a matrix of wallets and requests and records the
//! decision each one reaches.
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
use zolana_keypair::{shielded::ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::{
    AssetRegistry, LocalWalletAuthority, OutputContext, OutputData, Utxo, Wallet, WalletUtxo,
    SOL_MINT,
};
use zolana_wallet::{
    create_merge, create_split, create_withdrawal, sign_shielded_transaction_sync, MergeParams,
    SplitParams, WithdrawalParams,
};

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
        // Two plain notes on each tree: enough to merge either side of a rollover.
        (
            "rollover",
            vec![plain(3), plain(5), on_secondary(7), on_secondary(11)],
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
        "merges": merges()?,
        "rails": rails()?,
        "substitutions": substitutions()?,
    }))
}

/// Which rail `apply_p256_signature` reads. It consults the authority's own
/// shielded address and never the notes being spent, so the two mixed cases are
/// what discriminate that rule from reading the rail off the inputs: they are
/// the only ones the two rules answer differently. Rust accepts an input owned
/// by a key other than the spending authority, which is what makes them
/// buildable at all.
fn rails() -> Result<Value> {
    [
        ("p256", "p256", true),
        ("ed25519", "ed25519", true),
        ("p256", "ed25519", false),
        ("ed25519", "p256", false),
    ]
    .into_iter()
    .map(|(authority_rail, note_rail, same_key)| {
        let authority_keypair = rail_keypair(authority_rail, 61)?;
        let note_keypair = if same_key {
            rail_keypair(authority_rail, 61)?
        } else {
            rail_keypair(note_rail, 62)?
        };
        let wallet = rail_wallet(&authority_keypair, &note_keypair)?;
        let outcome = sign_once(&wallet, &authority_keypair)
            .map(|signed| json!({ "p256Signature": signed.transaction.p256_signature.is_some() }))
            .map_err(|error| format!("{error:?}"));
        Ok(json!({
            "authorityRail": authority_rail,
            "noteRail": note_rail,
            "sameKey": same_key,
            "outcome": arm(outcome),
        }))
    })
    .collect::<Result<Vec<_>>>()
    .map(Value::Array)
}

/// Which single-field substitution between build and sign `validate_unsigned_inputs`
/// rejects. It compares the whole `Utxo` alongside the four context fields, so
/// every entry here but `none` is a refusal; a re-check narrowed to the
/// commitment, nullifier, asset, amount, and blinding would let the rest pass.
fn substitutions() -> Result<Value> {
    const CASES: [&str; 12] = [
        "none",
        "spent",
        "tree",
        "commitment",
        "nullifier",
        "dataHash",
        "zoneDataHash",
        "utxo.owner",
        "utxo.asset",
        "utxo.amount",
        "utxo.blinding",
        "utxo.zoneProgramId",
    ];

    CASES
        .into_iter()
        .map(|substitution| {
            let keypair = rail_keypair("ed25519", 63)?;
            let mut wallet = rail_wallet(&keypair, &keypair)?;
            let unsigned = create_withdrawal(WithdrawalParams {
                wallet: &wallet,
                payer: Address::default(),
                recipient: Pubkey::new_from_array([5u8; 32]),
                asset: SOL_MINT,
                amount: 5,
            })?
            .transaction;
            substitute(&mut wallet, substitution)?;
            let authority = LocalWalletAuthority::new(Address::default(), &keypair);
            let outcome = sign_shielded_transaction_sync(unsigned, &wallet, &authority)
                .map(|_| json!({}))
                .map_err(|error| format!("{error:?}"));
            Ok(json!({
                "substitution": substitution,
                "outcome": arm(outcome),
            }))
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

/// Replace one field of the wallet's only note, leaving every other field as the
/// unsigned transaction recorded it.
fn substitute(wallet: &mut Wallet, substitution: &str) -> Result<()> {
    let entry = wallet.utxos.first_mut().context("wallet has no note")?;
    match substitution {
        "none" => {}
        "spent" => entry.spent = true,
        "tree" => entry.output_context.tree = SECONDARY_TREE,
        "commitment" => entry.output_context.hash = [99u8; 32],
        "nullifier" => entry.nullifier = [99u8; 32],
        "dataHash" => entry.data_hash = Some([99u8; 32]),
        "zoneDataHash" => entry.zone_data_hash = Some([99u8; 32]),
        "utxo.owner" => entry.utxo.owner = rail_keypair("ed25519", 64)?.signing_pubkey(),
        "utxo.asset" => entry.utxo.asset = SECONDARY_TREE,
        "utxo.amount" => entry.utxo.amount += 1,
        "utxo.blinding" => entry.utxo.blinding = [9u8; 31],
        "utxo.zoneProgramId" => entry.utxo.zone_program_id = Some(ZONE_PROGRAM),
        other => bail!("no substitution named {other}"),
    }
    Ok(())
}

/// A keypair on `rail`, seeded so the fixture is reproducible run to run. The
/// port builds its own keypairs on the same rails rather than these bytes: only
/// the rail is load-bearing for either family of cases.
fn rail_keypair(rail: &str, seed: u8) -> Result<ShieldedKeypair> {
    let viewing = ViewingKey::from_seed(&[seed; 32], 0).context("viewing key")?;
    match rail {
        "p256" => ShieldedKeypair::from_keys(
            SigningKey::from_bytes(&[seed; 32]).context("p256 signing key")?,
            viewing,
        )
        .context("p256 keypair"),
        "ed25519" => ShieldedKeypair::from_ed25519(&[seed; 32], viewing).context("ed25519 keypair"),
        other => bail!("no rail named {other}"),
    }
}

/// A wallet whose identity is `authority`'s shielded address holding one plain
/// note owned by `note_owner`, so the two rails can be set independently.
fn rail_wallet(authority: &ShieldedKeypair, note_owner: &ShieldedKeypair) -> Result<Wallet> {
    let mut wallet = Wallet::new(
        authority.shielded_address().context("shielded address")?,
        AssetRegistry::new(Vec::new()).context("asset registry")?,
    )
    .context("wallet")?;
    wallet.utxos.push(WalletUtxo {
        utxo: Utxo {
            owner: note_owner.signing_pubkey(),
            asset: SOL_MINT,
            amount: 10,
            blinding: [1u8; 31],
            zone_program_id: None,
            data: OutputData::new(Vec::new()),
        },
        output_context: OutputContext {
            hash: note_hash(0),
            tree: PRIMARY_TREE,
            leaf_index: 0,
        },
        nullifier: [20u8; 32],
        data_hash: None,
        zone_data_hash: None,
        spent: false,
    });
    Ok(wallet)
}

fn sign_once(
    wallet: &Wallet,
    keypair: &ShieldedKeypair,
) -> Result<zolana_client::SignedPrivateTransaction, zolana_client::error::ClientError> {
    let unsigned = create_withdrawal(WithdrawalParams {
        wallet,
        payer: Address::default(),
        recipient: Pubkey::new_from_array([5u8; 32]),
        asset: SOL_MINT,
        amount: 5,
    })?
    .transaction;
    let authority = LocalWalletAuthority::new(Address::default(), keypair);
    sign_shielded_transaction_sync(unsigned, wallet, &authority)
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

/// Optional tree selector for merge: omit it, or name one of the fixture trees.
#[derive(Clone, Copy)]
enum MergeTree {
    Omit,
    Named(&'static str),
}

/// `create_merge` refuses a multi-tree auto-sweep without a selector, merges each
/// tree when named, and reports a wrong-tree named hash with both trees.
fn merges() -> Result<Value> {
    let cases: [(&str, MergeTree, Option<&'static [usize]>); 5] = [
        ("rollover", MergeTree::Omit, None),
        ("rollover", MergeTree::Named("primary"), None),
        ("rollover", MergeTree::Named("secondary"), None),
        ("ascending", MergeTree::Omit, None),
        ("rollover", MergeTree::Named("primary"), Some(&[0usize, 2])),
    ];

    cases
        .into_iter()
        .map(|(wallet_id, tree, inputs)| {
            let (keypair, wallet) = build_wallet(wallet_id)?;
            let tree_address = match tree {
                MergeTree::Omit => None,
                MergeTree::Named(name) => Some(match name {
                    "primary" => PRIMARY_TREE,
                    "secondary" => SECONDARY_TREE,
                    other => bail!("no tree named {other}"),
                }),
            };
            let outcome = create_merge(MergeParams {
                wallet: &wallet,
                keypair: &keypair,
                asset: SOL_MINT,
                inputs: inputs.map(|indexes| indexes.iter().copied().map(note_hash).collect()),
                tree: tree_address,
            })
            .map(|created| {
                json!({
                    "numInputs": created.num_inputs.to_string(),
                    "mergedAmount": created.merged_amount.to_string(),
                    "tree": created.tree.to_string(),
                })
            })
            .map_err(|error| format!("{error:?}"));
            Ok(json!({
                "wallet": wallet_id,
                "tree": match tree {
                    MergeTree::Omit => Value::Null,
                    MergeTree::Named(name) => Value::String(name.to_string()),
                },
                "inputs": match inputs {
                    None => Value::Null,
                    Some(indexes) => Value::Array(
                        indexes
                            .iter()
                            .map(|index| Value::String(index.to_string()))
                            .collect(),
                    ),
                },
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
                data: OutputData::new(Vec::new()),
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
