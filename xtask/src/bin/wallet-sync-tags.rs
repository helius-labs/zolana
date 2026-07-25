//! Generates the wallet sync tag vectors that `@zolana/wallet` checks itself
//! against.
//!
//! Row W08 turns on which view tags a sync asks the indexer for. That set is
//! built by `wallet_query_tags`, which is private, so this binary observes it
//! the only way a caller can: it runs the real `sync_wallet_with_config` against
//! an indexer that answers every tag query with nothing and records the tags it
//! was handed. A wallet whose tag set is too small silently misses its own
//! funds, and reading the two languages side by side cannot tell a missing
//! family from a differently ordered one.
//!
//! Rust collects the tags through a `HashSet`, so their order is not part of the
//! contract and the fixture publishes the set sorted. Chunk composition is
//! unordered for the same reason; what is fixed is how many queries a chunk size
//! produces and how large each one is.
//!
//! Keys are derived from constant secrets rather than generated, because the
//! port has to arrive at the same tags. The fixture publishes each secret so the
//! TypeScript side can rebuild the same keys.
//!
//! ```text
//! cargo run -p xtask --bin wallet-sync-tags            # write the fixture
//! cargo run -p xtask --bin wallet-sync-tags -- --check # fail on any drift
//! ```

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    env, fs,
    path::PathBuf,
    process::ExitCode,
};

use anyhow::{bail, Context as _, Result};
use serde_json::{json, Map, Value};
use solana_address::Address;
use zolana_client::{
    error::ClientError,
    retry::IndexerRpcConfig,
    rpc::{Context, GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByTagsResponse, Rpc},
};
use zolana_keypair::{
    nullifier_key::NullifierKey,
    pubkey::P256Pubkey,
    shielded::{ShieldedAddress, ShieldedKeypair},
    viewing_key::{ViewTag, ViewingKey},
};
use zolana_transaction::{
    serialization::{anonymous::AnonymousTransferSenderPlaintext, split::SplitBundlePlaintext},
    AnonymousRecipientSlot, AssetRegistry, EncryptedSplit, EncryptedTransfer, P256Signature,
    SppProofOutputUtxo, SyncWalletAuthority, TransactionError, ViewingKeyEntry, Wallet,
    WalletSyncMaterial,
};
use zolana_wallet::{sync_wallet_with_config, SyncWalletConfig};

const FIXTURE: &str = "sdk-libs/ts/vectors/wallet-sync-tags-v1.json";

const SIGNING_SECRET: [u8; 32] = [3u8; 32];
const OTHER_SIGNING_SECRET: [u8; 32] = [4u8; 32];
const CURRENT_VIEWING_SECRET: [u8; 32] = [5u8; 32];
const ROTATED_VIEWING_SECRET: [u8; 32] = [6u8; 32];
const ALICE_VIEWING_SECRET: [u8; 32] = [9u8; 32];
const BOB_VIEWING_SECRET: [u8; 32] = [11u8; 32];

/// `58^43`, the smallest 32-byte value whose base58 encoding needs 44 characters.
const AT_BASE58_LENGTH_BOUNDARY: [u8; 32] = [
    0x0e, 0xdb, 0xaf, 0xda, 0x67, 0xca, 0x37, 0x18, 0x8c, 0xf2, 0x82, 0x63, 0x57, 0x1f, 0x03, 0xb9,
    0x71, 0x68, 0x79, 0xe4, 0xac, 0xc9, 0xc5, 0x14, 0xab, 0x67, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// One below it, and so one character shorter once encoded.
const BELOW_BASE58_LENGTH_BOUNDARY: [u8; 32] = [
    0x0e, 0xdb, 0xaf, 0xda, 0x67, 0xca, 0x37, 0x18, 0x8c, 0xf2, 0x82, 0x63, 0x57, 0x1f, 0x03, 0xb9,
    0x71, 0x68, 0x79, 0xe4, 0xac, 0xc9, 0xc5, 0x14, 0xab, 0x67, 0x27, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// How a case describes one entry of the wallet's viewing key history.
struct History {
    key: &'static str,
    tx_count: u64,
    request_count: u64,
    known_senders: Vec<(&'static str, u64)>,
    known_recipients: Vec<(&'static str, u64)>,
}

fn counters(key: &'static str, tx_count: u64, request_count: u64) -> History {
    History {
        key,
        tx_count,
        request_count,
        known_senders: Vec::new(),
        known_recipients: Vec::new(),
    }
}

/// One scenario: a wallet, the key material the authority hands over, and the
/// sync config. Everything is named so the port can rebuild it.
struct Case {
    id: &'static str,
    history: Vec<History>,
    viewing_keys: Vec<&'static str>,
    identity: &'static str,
    tag_window: u64,
    tag_query_chunk: usize,
}

const DEFAULT_CHUNK: usize = 64;

fn case(id: &'static str, history: Vec<History>, tag_window: u64) -> Case {
    Case {
        id,
        history,
        viewing_keys: vec!["current"],
        identity: "self",
        tag_window,
        tag_query_chunk: DEFAULT_CHUNK,
    }
}

fn cases() -> Vec<Case> {
    vec![
        // A wallet that has never synced still asks for a full window of both
        // owner-side families, which is what lets a first deposit be found.
        case("fresh-default-window", Vec::new(), 64),
        // Window zero is legal: `normalized_config` clamps every other field but
        // passes `tag_window` through, leaving only the two unwindowed tags.
        case("fresh-zero-window", Vec::new(), 0),
        case("fresh-window-one", Vec::new(), 1),
        case("counters-window-two", vec![counters("current", 2, 3)], 2),
        // History for a key the material does not carry contributes nothing.
        case(
            "history-for-rotated-only",
            vec![counters("rotated", 4, 4)],
            1,
        ),
        Case {
            id: "counterparties-window-two",
            history: vec![History {
                key: "current",
                tx_count: 1,
                request_count: 1,
                known_senders: vec![("alice", 1)],
                known_recipients: vec![("bob", 2)],
            }],
            viewing_keys: vec!["current"],
            identity: "self",
            tag_window: 2,
            tag_query_chunk: DEFAULT_CHUNK,
        },
        // A rotated key stays scannable: both keys contribute their families,
        // each windowed by its own counters.
        Case {
            id: "rotated-key-still-scanned",
            history: vec![counters("current", 1, 0), counters("rotated", 2, 0)],
            viewing_keys: vec!["current", "rotated"],
            identity: "self",
            tag_window: 1,
            tag_query_chunk: DEFAULT_CHUNK,
        },
        // Chunking splits one round into several queries, and each chunk is
        // asked of both the transaction and the deposit endpoint.
        Case {
            id: "chunked-queries",
            history: vec![counters("current", 2, 2)],
            viewing_keys: vec!["current"],
            identity: "self",
            tag_window: 1,
            tag_query_chunk: 3,
        },
        // Both guards run before any query, so a mismatch costs no round trip.
        Case {
            id: "identity-mismatch",
            history: Vec::new(),
            viewing_keys: vec!["current"],
            identity: "other",
            tag_window: 64,
            tag_query_chunk: DEFAULT_CHUNK,
        },
        Case {
            id: "missing-current-viewing-key",
            history: Vec::new(),
            viewing_keys: vec!["rotated"],
            identity: "self",
            tag_window: 64,
            tag_query_chunk: DEFAULT_CHUNK,
        },
    ]
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wallet-sync-tags failed: {error:#}");
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
                    "Generate the Rust-side wallet sync tag vectors.\n\nusage: cargo run -p xtask --bin wallet-sync-tags -- [--check]"
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
            bail!("{FIXTURE} is stale; rerun `cargo run -p xtask --bin wallet-sync-tags`");
        }
        return Ok(());
    }

    fs::write(&path, rendered).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Records every tag query a sync makes and answers each with an empty page.
#[derive(Default)]
struct RecordingIndexer {
    shielded: RefCell<Vec<usize>>,
    deposits: RefCell<Vec<usize>>,
    tags: RefCell<Vec<[u8; 32]>>,
}

impl Rpc for RecordingIndexer {
    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.shielded.borrow_mut().push(tags.len());
        self.tags.borrow_mut().extend(tags);
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context { block_time: 0 },
            transactions: Vec::new(),
            next_cursor: None,
        })
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        self.deposits.borrow_mut().push(tags.len());
        Ok(GetEncryptedUtxosByTagsResponse {
            context: Context { block_time: 0 },
            matches: Vec::new(),
            next_cursor: None,
        })
    }
}

/// Hands over exactly the material a case names. The bundled authorities carry
/// one viewing key each, so a rotated-key wallet needs an authority that can
/// carry several; everything the sync path does not touch defers to the keypair.
struct FixedAuthority {
    keypair: ShieldedKeypair,
    material: WalletSyncMaterial,
}

impl SyncWalletAuthority for FixedAuthority {
    fn solana_pubkey(&self) -> Address {
        SyncWalletAuthority::solana_pubkey(&self.keypair)
    }

    fn shielded_address(&self) -> Result<ShieldedAddress, TransactionError> {
        Ok(self.material.identity)
    }

    fn viewing_keys(&self) -> Result<Vec<ViewingKey>, TransactionError> {
        Ok(self.material.viewing_keys.clone())
    }

    fn sync_material(&self) -> Result<WalletSyncMaterial, TransactionError> {
        Ok(self.material.clone())
    }

    fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        outputs: &[SppProofOutputUtxo],
        assets: &AssetRegistry,
    ) -> Result<EncryptedTransfer, TransactionError> {
        self.keypair
            .encrypt_confidential_transfer(first_nullifier, outputs, assets)
    }

    fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, TransactionError> {
        self.keypair.encrypt_anonymous_transfer(
            first_nullifier,
            sender_view_tag,
            sender,
            recipients,
        )
    }

    fn encrypt_split(
        &self,
        first_nullifier: &[u8; 32],
        view_tag: ViewTag,
        bundle: &SplitBundlePlaintext,
    ) -> Result<EncryptedSplit, TransactionError> {
        self.keypair
            .encrypt_split(first_nullifier, view_tag, bundle)
    }

    fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, TransactionError> {
        self.keypair.sign_p256(message_hash)
    }

    fn spend_nullifier_key(&self) -> Result<NullifierKey, TransactionError> {
        self.keypair.spend_nullifier_key()
    }
}

fn viewing_key(name: &str) -> Result<ViewingKey> {
    let secret = match name {
        "current" => CURRENT_VIEWING_SECRET,
        "rotated" => ROTATED_VIEWING_SECRET,
        "alice" => ALICE_VIEWING_SECRET,
        "bob" => BOB_VIEWING_SECRET,
        other => bail!("no viewing key named {other}"),
    };
    ViewingKey::from_bytes(&secret).context("viewing key from bytes")
}

fn keypair(identity: &str) -> Result<ShieldedKeypair> {
    let secret = match identity {
        "self" => SIGNING_SECRET,
        "other" => OTHER_SIGNING_SECRET,
        other => bail!("no identity named {other}"),
    };
    let viewing = match identity {
        // The mismatching identity also carries a different viewing key, which
        // is what a wallet built by another authority looks like.
        "self" => viewing_key("current")?,
        _ => viewing_key("rotated")?,
    };
    ShieldedKeypair::from_ed25519(&secret, viewing).context("shielded keypair")
}

fn build() -> Result<Value> {
    let owner = keypair("self")?;
    let described: Vec<Value> = cases().iter().map(observe).collect::<Result<Vec<_>>>()?;

    Ok(json!({
        "generator": "cargo run -p xtask --bin wallet-sync-tags",
        "rustSource": ["sdk-libs/wallet/src/wallet_sync.rs"],
        "secrets": {
            "signing": hex(&SIGNING_SECRET),
            "otherSigning": hex(&OTHER_SIGNING_SECRET),
            "current": hex(&CURRENT_VIEWING_SECRET),
            "rotated": hex(&ROTATED_VIEWING_SECRET),
            "alice": hex(&ALICE_VIEWING_SECRET),
            "bob": hex(&BOB_VIEWING_SECRET),
        },
        "counterparties": {
            "alice": hex(counterparty("alice")?.as_bytes()),
            "bob": hex(counterparty("bob")?.as_bytes()),
        },
        // Published so a port that derives a different signing pubkey from the
        // same secret fails on the identity rather than on every tag.
        "signingPublicKey": hex(owner.signing_pubkey().as_bytes()),
        "defaults": {
            "tagWindow": SyncWalletConfig::default().tag_window.to_string(),
            "tagQueryChunk": SyncWalletConfig::default().tag_query_chunk,
            "pageLimit": SyncWalletConfig::default().page_limit,
            "rounds": SyncWalletConfig::default().rounds,
            "waitForIndexerBlocking": SyncWalletConfig::new().wait_for_indexer,
            "waitForIndexerDefault": SyncWalletConfig::default().wait_for_indexer,
        },
        "cases": Value::Array(described),
        "depositTreeOrder": deposit_tree_order(),
    }))
}

/// Rust orders deposits by their tree, which is an `Address` and so sorts by its
/// 32 bytes. These three are in that order. The first two straddle the base58
/// length boundary at `58^43`, where the larger number encodes one character
/// longer and starts with the lowest digit, so their encoded strings sort the
/// opposite way round and a port comparing strings orders them backwards.
fn deposit_tree_order() -> Value {
    let mut trees = [
        Address::new_from_array(AT_BASE58_LENGTH_BOUNDARY),
        Address::new_from_array(BELOW_BASE58_LENGTH_BOUNDARY),
        Address::new_from_array([17u8; 32]),
    ];
    trees.sort();
    Value::Array(
        trees
            .iter()
            .map(|tree| json!({ "address": tree.to_string(), "bytes": hex(tree.as_ref()) }))
            .collect(),
    )
}

fn counterparty(name: &str) -> Result<P256Pubkey> {
    Ok(viewing_key(name)?.pubkey())
}

fn observe(case: &Case) -> Result<Value> {
    let owner = keypair(case.identity)?;
    let mut wallet = Wallet::new(
        keypair("self")?
            .shielded_address()
            .context("shielded address")?,
        AssetRegistry::new(Vec::new()).context("asset registry")?,
    )
    .context("wallet")?;

    wallet.viewing_key_history.clear();
    for entry in &case.history {
        let mut known_senders = HashMap::new();
        for (name, count) in &entry.known_senders {
            known_senders.insert(counterparty(name)?, *count);
        }
        let mut known_recipients = HashMap::new();
        for (name, count) in &entry.known_recipients {
            known_recipients.insert(counterparty(name)?, *count);
        }
        wallet.viewing_key_history.push(ViewingKeyEntry {
            viewing_pubkey: viewing_key(entry.key)?.pubkey(),
            created_at: 0,
            tx_count: entry.tx_count,
            request_count: entry.request_count,
            known_senders,
            known_recipients,
        });
    }

    let mut viewing_keys = Vec::new();
    for name in &case.viewing_keys {
        viewing_keys.push(viewing_key(name)?);
    }
    let material = WalletSyncMaterial {
        identity: owner.shielded_address().context("shielded address")?,
        viewing_keys,
        nullifier_key: owner.nullifier_key.clone(),
    };
    let authority = FixedAuthority {
        keypair: owner,
        material,
    };

    let indexer = RecordingIndexer::default();
    let outcome = sync_wallet_with_config(
        &mut wallet,
        &authority,
        &indexer,
        SyncWalletConfig {
            tag_window: case.tag_window,
            tag_query_chunk: case.tag_query_chunk,
            ..SyncWalletConfig::new()
        },
    )
    .map(|_| ())
    .map_err(|error| format!("{error:?}"));

    let mut tags: Vec<String> = indexer.tags.borrow().iter().map(|tag| hex(tag)).collect();
    tags.sort();
    tags.dedup();
    let mut shielded = indexer.shielded.borrow().clone();
    shielded.sort_unstable_by(|left, right| right.cmp(left));
    let mut deposits = indexer.deposits.borrow().clone();
    deposits.sort_unstable_by(|left, right| right.cmp(left));

    Ok(json!({
        "id": case.id,
        "history": case.history.iter().map(describe).collect::<Vec<_>>(),
        "viewingKeys": case.viewing_keys,
        "identity": case.identity,
        "tagWindow": case.tag_window.to_string(),
        "tagQueryChunk": case.tag_query_chunk,
        "outcome": match outcome {
            Ok(()) => json!({ "arm": "ok" }),
            Err(error) => json!({ "arm": "err", "error": error }),
        },
        "tags": tags,
        "shieldedChunkSizes": shielded,
        "depositChunkSizes": deposits,
    }))
}

fn describe(entry: &History) -> Value {
    json!({
        "key": entry.key,
        "txCount": entry.tx_count.to_string(),
        "requestCount": entry.request_count.to_string(),
        "knownSenders": entry
            .known_senders
            .iter()
            .map(|(name, count)| (name.to_string(), Value::String(count.to_string())))
            .collect::<Map<_, _>>(),
        "knownRecipients": entry
            .known_recipients
            .iter()
            .map(|(name, count)| (name.to_string(), Value::String(count.to_string())))
            .collect::<Map<_, _>>(),
    })
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
