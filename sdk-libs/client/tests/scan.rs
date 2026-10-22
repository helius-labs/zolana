//! `UtxoScan::fetch` against an in-memory indexer that pages as Photon
//! does, and `fetch_asset_id` against in-memory accounts.

use std::{
    cell::RefCell,
    collections::{BTreeSet, HashMap},
};

use solana_account::Account;

use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{
    fetch_asset_id, fetch_spl_asset_registrations,
    rpc::GetShieldedTransactionsByNullifiersResponse, ChainPosition, ClientError, Context,
    EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByTagsResponse,
    IndexerRpcConfig, OutputContext, OutputSlot, ProgramAccountsFilter, Rpc, ShieldedTransaction,
    UtxoScan,
};
use zolana_event::{
    encode_merge_output_data, EncryptedRingDepositOutput, MergeOutputDataRef, OutputDataEncoding,
};
use zolana_interface::{pda, state::SplAssetRegistry, PROGRAM_ID_PUBKEY};
use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::{
    instructions::merge::{
        merge_dummy_nullifier, merge_output_blinding, merge_output_key, MergeOutputPlaintext,
        MERGE_DEFAULT_INPUT_COUNT,
    },
    owner_utxo_hash,
    serialization::{
        confidential::{Confidential, ConfidentialEncode},
        proofless::{Proofless, ProoflessEncode},
    },
    AssetRegistry, Data, EncryptedScheme, HistoryKind, Mint, OwnerCx, RingDepositPlaintext,
    ShieldedKeys, TransactionError, TransactionKeyRequest, Utxo, UtxoSerialization, SOL_ASSET_ID,
    SOL_MINT,
};

const TREE: u16 = 2;

#[derive(Default)]
struct Indexer {
    registrations: Vec<(Address, Account)>,
    registry_reads: RefCell<usize>,
    registry_required_slots: RefCell<Vec<Option<u64>>>,
    /// When set, registry reads fail until this node reaches the required slot.
    registry_slot: Option<u64>,
    registry_fails: bool,
    /// Served by the view tags of their outputs.
    tagged: Vec<ShieldedTransaction>,
    deposits: Vec<EncryptedUtxoMatch>,
    /// Served by the nullifiers they publish.
    spends: Vec<ShieldedTransaction>,
    queried_tags: RefCell<Vec<Vec<[u8; 32]>>>,
    queried_nullifiers: RefCell<Vec<[u8; 32]>>,
    required_slots: RefCell<Vec<Option<u64>>>,
    /// Each request's method.
    reads: RefCell<Vec<&'static str>>,
    /// Rows per page; one when zero.
    page_size: usize,
    /// Answers every page as full, with the cursor it was given.
    stuck_cursor: bool,
}

impl Indexer {
    fn read(&self, method: &'static str, config: Option<IndexerRpcConfig>) {
        self.reads.borrow_mut().push(method);
        self.required_slots
            .borrow_mut()
            .push(config.and_then(|config| config.require_slot));
    }

    fn reads_of(&self, method: &str) -> usize {
        self.reads
            .borrow()
            .iter()
            .filter(|read| **read == method)
            .count()
    }

    /// Pages never split the matching rows of one transaction.
    fn page<T>(
        &self,
        mut items: Vec<T>,
        after: Option<ChainPosition>,
        position: impl Fn(&T) -> ChainPosition,
    ) -> Page<T> {
        let size = self.page_size.max(1);
        items.sort_by_key(&position);
        let latest = items.last().map(&position);
        if self.stuck_cursor {
            return Page {
                rows: items.into_iter().take(size).collect(),
                next: Some(after.or(latest).unwrap_or(ChainPosition {
                    slot: 0,
                    signature: Signature::default(),
                })),
                latest: None,
            };
        }
        let mut remaining = items
            .into_iter()
            .filter(|item| after.is_none_or(|after| position(item) > after));
        let mut rows: Vec<T> = remaining.by_ref().take(size).collect();
        let next = if rows.len() >= size {
            let boundary = position(rows.last().unwrap());
            rows.extend(remaining.take_while(|item| position(item) == boundary));
            Some(boundary)
        } else {
            None
        };
        Page {
            rows,
            next,
            latest: latest.filter(|_| next.is_none()),
        }
    }
}

struct Page<T> {
    rows: Vec<T>,
    next: Option<ChainPosition>,
    latest: Option<ChainPosition>,
}

const CONTEXT: Context = Context {
    block_time: 0,
    slot: 0,
};

impl Rpc for Indexer {
    fn get_program_accounts_filtered(
        &self,
        program_id: Address,
        filter: &ProgramAccountsFilter,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        assert_eq!(program_id, PROGRAM_ID_PUBKEY);
        assert_eq!(filter.data_size(), SplAssetRegistry::SIZE);
        assert_eq!(
            filter.memcmp_filters().collect::<Vec<_>>(),
            vec![(
                0,
                &[zolana_interface::state::discriminator::SPL_ASSET_REGISTRY][..]
            )]
        );
        *self.registry_reads.borrow_mut() += 1;
        self.registry_required_slots
            .borrow_mut()
            .push(filter.min_context_slot());
        if self
            .registry_slot
            .zip(filter.min_context_slot())
            .is_some_and(|(slot, required)| slot < required)
        {
            return Err(ClientError::Rpc(
                "minimum context slot has not been reached".into(),
            ));
        }
        if self.registry_fails {
            return Err(ClientError::Rpc("registry unavailable".into()));
        }
        Ok(self.registrations.clone())
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<ChainPosition>,
        _limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.read("get_shielded_transactions_by_tags", config);
        self.queried_tags.borrow_mut().push(tags.clone());
        let matching = self
            .tagged
            .iter()
            .filter(|tx| {
                tx.output_slots
                    .iter()
                    .any(|slot| tags.contains(&slot.view_tag))
            })
            .cloned()
            .collect();
        let Page {
            rows: transactions,
            next,
            latest,
        } = self.page(matching, cursor, |item| ChainPosition {
            slot: item.slot,
            signature: item.tx_signature,
        });
        Ok(GetShieldedTransactionsByTagsResponse {
            context: CONTEXT,
            output_tree_id: Some(TREE),
            transactions,
            next,
            latest,
        })
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<ChainPosition>,
        _limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        self.read("get_encrypted_utxos_by_tags", config);
        let matching = self
            .deposits
            .iter()
            .filter(|deposit| tags.contains(&deposit.output_slot.view_tag))
            .cloned()
            .collect();
        let Page {
            rows: matches,
            next,
            latest,
        } = self.page(matching, cursor, |item| ChainPosition {
            slot: item.slot,
            signature: item.tx_signature,
        });
        Ok(GetEncryptedUtxosByTagsResponse {
            context: CONTEXT,
            output_tree_id: Some(TREE),
            matches,
            next,
            latest,
        })
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<ChainPosition>,
        _limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        self.read("get_shielded_transactions_by_nullifiers", config);
        if cursor.is_none() {
            self.queried_nullifiers
                .borrow_mut()
                .extend(nullifiers.iter().copied());
        }
        let matching = self
            .spends
            .iter()
            .filter(|tx| tx.nullifiers.iter().any(|n| nullifiers.contains(n)))
            .cloned()
            .collect();
        let Page {
            rows: transactions,
            next,
            latest,
        } = self.page(matching, cursor, |item| ChainPosition {
            slot: item.slot,
            signature: item.tx_signature,
        });
        Ok(GetShieldedTransactionsByNullifiersResponse {
            context: CONTEXT,
            output_tree_id: Some(TREE),
            transactions,
            next,
            latest,
        })
    }
}

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

/// A note as the tests track it: the UTXO, its commitment and nullifier.
struct Note {
    utxo: Utxo,
    hash: [u8; 32],
    nullifier: [u8; 32],
}

fn note(owner: &ShieldedKeypair, utxo: Utxo, ring_data_hash: [u8; 32]) -> Note {
    let nullifier_pubkey = owner.nullifier_key.pubkey().unwrap();
    let hash = utxo
        .hash(&nullifier_pubkey, &[0; 32], &ring_data_hash, TREE)
        .unwrap();
    Note {
        nullifier: owner.nullifier(&hash, &utxo.blinding).unwrap(),
        hash,
        utxo,
    }
}

fn sol(owner: &ShieldedKeypair, amount: u64, nonce: u8) -> Utxo {
    let mut blinding = [0; 32];
    blinding[31] = nonce;
    Utxo {
        owner: owner.signing_pubkey(),
        asset: Mint::SOL,
        amount,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    }
}

fn output_slot(
    view_tag: [u8; 32],
    hash: [u8; 32],
    leaf_index: u64,
    payload: Vec<u8>,
) -> OutputSlot {
    OutputSlot {
        view_tag,
        output_context: OutputContext {
            hash,
            tree_id: TREE,
            leaf_index,
        },
        payload,
    }
}

/// A proofless deposit of `amount` SOL, tagged with the owner's viewing key.
fn deposit(owner: &ShieldedKeypair, amount: u64, nonce: u8) -> (EncryptedUtxoMatch, Note) {
    asset_deposit(owner, Mint::SOL, amount, nonce)
}

fn asset_deposit(
    owner: &ShieldedKeypair,
    mint: Mint,
    amount: u64,
    nonce: u8,
) -> (EncryptedUtxoMatch, Note) {
    let address = owner.shielded_address().unwrap();
    let mut assets = AssetRegistry::default();
    if mint != Mint::SOL {
        assets.insert(mint.asset_id, mint.asset).unwrap();
    }
    let mut utxo = sol(owner, amount, nonce);
    utxo.asset = mint;
    let deposited = note(owner, utxo, [0; 32]);
    let message = Proofless::encode(
        std::slice::from_ref(&deposited.utxo),
        &OwnerCx {
            owner: address.signing_pubkey,
            assets: &assets,
            ring_program_id: None,
            first_nullifier: None,
        },
        [0; 32],
        &ProoflessEncode {
            owner_hash: address.owner_hash().unwrap(),
            data_hash: None,
            ring_data_hash: None,
        },
    )
    .unwrap();
    let matched = EncryptedUtxoMatch {
        slot: u64::from(nonce),
        tx_signature: Signature::from([nonce; 64]),
        output_slot: output_slot(
            address.viewing_pubkey.u(),
            deposited.hash,
            u64::from(nonce),
            message.data,
        ),
        tx_viewing_pk: None,
        salt: None,
    };
    (matched, deposited)
}

/// A merge of `inputs`, its output tagged with `view_tag` and published with
/// the ciphertext of its amount and mint under the owner's per-merge key.
fn merge(
    owner: &ShieldedKeypair,
    inputs: &[&Note],
    view_tag: [u8; 32],
    nonce: u8,
) -> (ShieldedTransaction, Note) {
    let first = inputs[0].nullifier;
    let mut nullifiers: Vec<_> = inputs.iter().map(|input| input.nullifier).collect();
    nullifiers
        .extend((inputs.len()..MERGE_DEFAULT_INPUT_COUNT).map(|index| {
            merge_dummy_nullifier(&owner.nullifier_key, &first, index as u8).unwrap()
        }));
    let mut utxo = inputs[0].utxo.clone();
    utxo.amount = inputs.iter().map(|input| input.utxo.amount).sum();
    utxo.blinding = merge_output_blinding(&owner.nullifier_key, &first).unwrap();
    let salt = [nonce; 16];
    let ciphertext = MergeOutputPlaintext {
        amount: utxo.amount,
        mint: utxo.asset.asset,
    }
    .encrypt(
        &merge_output_key(&owner.nullifier_key, &first).unwrap(),
        &salt,
    )
    .unwrap();
    let payload = encode_merge_output_data(MergeOutputDataRef {
        salt: &salt,
        ciphertext: &ciphertext,
        prefix: &[],
    });
    let merged = note(owner, utxo, [0; 32]);
    let tx = ShieldedTransaction {
        slot: u64::from(nonce),
        tx_signature: Signature::from([nonce; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![output_slot(
            view_tag,
            merged.hash,
            u64::from(nonce),
            payload,
        )],
        messages: Vec::new(),
        nullifiers,
        proofless: false,
        ring_config: None,
        ring_program_id: None,
    };
    (tx, merged)
}

/// Another client's spend of `input`, carrying none of the owner's tags.
fn spend(owner: &ShieldedKeypair, input: &Note, nonce: u8) -> ShieldedTransaction {
    ShieldedTransaction {
        slot: u64::from(nonce),
        tx_signature: Signature::from([nonce; 64]),
        event_index: Some(0),
        tx_viewing_pk: Some(owner.viewing_pubkey()),
        salt: Some([nonce; 16]),
        output_slots: Vec::new(),
        messages: Vec::new(),
        nullifiers: vec![input.nullifier],
        proofless: false,
        ring_config: None,
        ring_program_id: None,
    }
}

#[test]
fn fetch_follows_spends_the_wallet_tags_do_not_reach() {
    let owner = keypair(7);
    let address = owner.shielded_address().unwrap();
    let owner_tag = address.signing_pubkey.confidential_view_tag().unwrap();
    let (first_deposit, first) = deposit(&owner, 30, 1);
    let (second_deposit, second) = deposit(&owner, 12, 2);
    // Owner-tagged, and returned again by the nullifier query.
    let (tagged_merge, merged) = merge(&owner, &[&first], owner_tag, 3);
    // Tagged by its first nullifier, as a ring merge is: only its nullifier
    // finds it, and only a second round finds the spend of its output.
    let (untagged_merge, untagged_output) = merge(&owner, &[&second], second.nullifier, 4);
    let indexer = Indexer {
        tagged: vec![tagged_merge.clone()],
        deposits: vec![first_deposit, second_deposit],
        spends: vec![
            tagged_merge,
            untagged_merge,
            spend(&owner, &untagged_output, 5),
        ],
        ..Indexer::default()
    };

    let assets = AssetRegistry::default();
    let spendable = UtxoScan::new(&owner, &assets)
        .fetch(&indexer)
        .unwrap()
        .spendable;

    let utxos: Vec<_> = spendable.utxos().map(|utxo| utxo.utxo_hash).collect();
    assert_eq!(utxos, vec![merged.hash]);
    // Every spendable UTXO carries the output tree the indexer's pages name.
    assert!(spendable
        .utxos()
        .all(|utxo| utxo.latest_tree_id == Some(TREE)));
    // And, as `ShieldedKeys::spendable_utxos` attaches it, the transaction
    // viewing key of a transaction it is the first input of.
    let viewing_pubkey = address.viewing_pubkey;
    let expected_keys: Vec<_> = spendable
        .utxos()
        .map(|utxo| {
            owner
                .transaction_keys(&[TransactionKeyRequest {
                    viewing_pubkey,
                    first_nullifier: utxo.nullifier,
                }])
                .unwrap()
                .first()
                .map(|key| *key.secret_bytes())
        })
        .collect();
    let synced_keys: Vec<_> = spendable.utxos().map(|utxo| utxo.tx_viewing_key).collect();
    assert_eq!(synced_keys, expected_keys);
    assert_eq!(
        spendable
            .balances
            .get_balance(Mint::SOL.asset)
            .unwrap()
            .amount,
        30
    );
    assert_eq!(
        indexer.queried_tags.borrow().first(),
        Some(&vec![owner_tag, address.viewing_pubkey.u()])
    );
    // Each round queries only the UTXOs found since the last one.
    let queried = indexer.queried_nullifiers.borrow();
    let mut unique = queried.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), queried.len(), "a nullifier was queried twice");
}

#[test]
fn a_stream_ends_at_a_page_short_of_the_page_size() {
    let owner = keypair(9);
    let owner_tag = owner
        .shielded_address()
        .unwrap()
        .signing_pubkey
        .confidential_view_tag()
        .unwrap();
    let (first_deposit, first) = deposit(&owner, 10, 1);
    let (second_deposit, second) = deposit(&owner, 20, 2);
    let (third_deposit, _) = deposit(&owner, 30, 3);
    let (first_merge, _) = merge(&owner, &[&first], owner_tag, 4);
    let (second_merge, _) = merge(&owner, &[&second], owner_tag, 5);
    let indexer = Indexer {
        // Two tagged transactions fill a page exactly, three deposits take one
        // more, and no transaction spends what they hold.
        tagged: vec![first_merge, second_merge],
        deposits: vec![first_deposit, second_deposit, third_deposit],
        page_size: 2,
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    let scan = UtxoScan::new(&owner, &assets).fetch(&indexer).unwrap();
    assert_eq!(scan.spendable.utxos().count(), 3);

    // A full page is followed to the empty page that ends the stream; a
    // shorter page ends it.
    assert_eq!(indexer.reads_of("get_shielded_transactions_by_tags"), 2);
    assert_eq!(indexer.reads_of("get_encrypted_utxos_by_tags"), 2);
    assert_eq!(
        indexer.reads_of("get_shielded_transactions_by_nullifiers"),
        1
    );
}

/// An indexer that hands back the cursor it was given would be paged
/// forever.
#[test]
fn a_cursor_that_does_not_advance_fails_instead_of_paging_forever() {
    let owner = keypair(7);
    let (first_deposit, _) = deposit(&owner, 30, 1);
    let indexer = Indexer {
        deposits: vec![first_deposit],
        stuck_cursor: true,
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();

    assert!(matches!(
        UtxoScan::new(&owner, &assets).fetch(&indexer),
        Err(ClientError::IndexerCursorNotAdvanced)
    ));
}

#[test]
fn every_read_requires_the_slot_of_the_indexer_config() {
    let owner = keypair(7);
    let (first_deposit, first) = deposit(&owner, 30, 1);
    let indexer = Indexer {
        deposits: vec![first_deposit],
        spends: vec![spend(&owner, &first, 2)],
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();

    UtxoScan::new(&owner, &assets).fetch(&indexer).unwrap();
    assert!(indexer.required_slots.take().iter().all(Option::is_none));

    let spendable = UtxoScan::new(&owner, &assets)
        .with_indexer_config(IndexerRpcConfig::at_slot(42))
        .fetch(&indexer)
        .unwrap()
        .spendable;
    assert_eq!(spendable.utxos().count(), 0);
    let required = indexer.required_slots.take();
    assert!(required.len() >= 3, "{required:?}");
    assert!(
        required.iter().all(|slot| *slot == Some(42)),
        "{required:?}"
    );
}

#[test]
fn fetch_keeps_the_spent_utxos_and_the_transactions_that_spent_them() {
    let owner = keypair(10);
    let address = owner.shielded_address().unwrap();
    let owner_tag = address.signing_pubkey.confidential_view_tag().unwrap();
    let (first_deposit, first) = deposit(&owner, 30, 1);
    let (second_deposit, second) = deposit(&owner, 12, 2);
    let (tagged_merge, merged) = merge(&owner, &[&first], owner_tag, 3);
    let (untagged_merge, untagged_output) = merge(&owner, &[&second], second.nullifier, 4);
    // Withdraws all of the untagged merge's output. Its one output is a dummy,
    // which a spend publishes under the owner's tag.
    let mut withdrawal = spend(&owner, &untagged_output, 5);
    withdrawal
        .output_slots
        .push(output_slot(owner_tag, [5; 32], 5, vec![5; 64]));
    let indexer = Indexer {
        tagged: vec![tagged_merge.clone()],
        deposits: vec![first_deposit, second_deposit],
        spends: vec![tagged_merge, untagged_merge, withdrawal],
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    let scan = UtxoScan::new(&owner, &assets).fetch(&indexer).unwrap();
    let (spendable, history) = (scan.spendable, scan.history);

    assert_eq!(
        history.view_tags,
        BTreeSet::from([owner_tag, address.viewing_pubkey.u()])
    );
    let unspent: Vec<_> = spendable.utxos().map(|utxo| utxo.utxo_hash).collect();
    assert_eq!(unspent, [merged.hash]);
    let owned: Vec<_> = history.utxos.iter().map(|utxo| utxo.utxo_hash).collect();
    assert_eq!(
        owned,
        [first.hash, second.hash, merged.hash, untagged_output.hash]
    );
    let mut signatures: Vec<_> = history
        .transactions
        .iter()
        .map(|tx| tx.tx_signature)
        .collect();
    signatures.sort();
    assert_eq!(
        signatures,
        [1, 2, 3, 4, 5].map(|nonce| Signature::from([nonce; 64]))
    );
    for spent in [&first, &second, &untagged_output] {
        assert!(history
            .transactions
            .iter()
            .any(|tx| tx.nullifiers.contains(&spent.nullifier)));
    }

    let entries: Vec<_> = history
        .entries()
        .into_iter()
        .map(|entry| (entry.slot, entry.kind, entry.amount))
        .collect();
    assert_eq!(
        entries,
        [
            (5, HistoryKind::Withdrawal, 12),
            (4, HistoryKind::SelfTransfer, 12),
            (3, HistoryKind::SelfTransfer, 30),
            (2, HistoryKind::Deposit, 12),
            (1, HistoryKind::Deposit, 30),
        ]
    );
}

#[test]
fn a_merge_found_before_one_of_its_inputs_decrypts_from_its_own_transaction() {
    let owner = keypair(8);
    let (first_deposit, first) = deposit(&owner, 30, 1);
    let (second_deposit, second) = deposit(&owner, 12, 2);
    // Merges tagged only by their first nullifier, as ring merges are. M1
    // spends `first` and Y, and the query for `first` finds it in the same
    // round as M0, a round before M0' produces Y. M1 decrypts with the whole
    // total from its own ciphertext, and Y, found later, is already spent.
    let (m0, x) = merge(&owner, &[&second], second.nullifier, 3);
    let (m0_prime, y) = merge(&owner, &[&x], x.nullifier, 4);
    let (m1, merged) = merge(&owner, &[&first, &y], first.nullifier, 5);
    let indexer = Indexer {
        deposits: vec![first_deposit, second_deposit],
        spends: vec![m0, m0_prime, m1],
        ..Indexer::default()
    };

    let assets = AssetRegistry::default();
    let spendable = UtxoScan::new(&owner, &assets)
        .fetch(&indexer)
        .unwrap()
        .spendable;

    let utxos: Vec<_> = spendable.utxos().map(|utxo| utxo.utxo_hash).collect();
    assert_eq!(utxos, vec![merged.hash]);
    // Every spendable UTXO carries the output tree the indexer's pages name.
    assert!(spendable
        .utxos()
        .all(|utxo| utxo.latest_tree_id == Some(TREE)));
    assert_eq!(
        spendable
            .balances
            .get_balance(Mint::SOL.asset)
            .unwrap()
            .amount,
        42
    );
}

/// A framing that marks framed ciphertexts with `frame`.
fn unframe(ciphertext: &[u8]) -> Result<Option<&[u8]>, TransactionError> {
    Ok(ciphertext.strip_prefix(b"frame"))
}

#[test]
fn a_framed_ring_deposit_opens_only_with_its_own_rings_payload() {
    let owner = keypair(9);
    let address = owner.shielded_address().unwrap();
    let ring = Address::new_from_array([4; 32]);
    let plaintext = RingDepositPlaintext {
        blinding: [3; 32],
        utxo_data: None,
        memo: None,
        ring_data: Vec::new(),
    };
    let deposited = note(
        &owner,
        plaintext
            .clone()
            .into_utxo(address.signing_pubkey, Mint::SOL, 50, ring),
        [0; 32],
    );
    let mut encrypted = plaintext.encrypt(&address.viewing_pubkey).unwrap();
    encrypted.ciphertext = [&b"frame"[..], &encrypted.ciphertext].concat();
    let output = EncryptedRingDepositOutput {
        owner_utxo_hash: owner_utxo_hash(&address.owner_hash().unwrap(), &plaintext.blinding)
            .unwrap(),
        asset: *Mint::SOL.asset.as_array(),
        amount: 50,
        data_hash: None,
        ring_program_id: *ring.as_array(),
        ring_data_hash: [0; 32],
        encrypted,
    };
    let blob = [
        &[EncryptedScheme::RingDeposit.as_byte()][..],
        &borsh::to_vec(&output).unwrap(),
    ]
    .concat();
    let indexer = Indexer {
        deposits: vec![EncryptedUtxoMatch {
            slot: 1,
            tx_signature: Signature::from([1; 64]),
            output_slot: output_slot(
                address.viewing_pubkey.u(),
                deposited.hash,
                1,
                borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).unwrap(),
            ),
            tx_viewing_pk: None,
            salt: None,
        }],
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();

    let framed = UtxoScan::new(&owner, &assets)
        .fetch(&indexer)
        .unwrap()
        .spendable;
    assert_eq!(framed.utxos().count(), 0);

    // Another ring's framing never reads this ring's deposits.
    let other_ring = UtxoScan::new(&owner, &assets)
        .with_ring_deposit_payload(Address::new_from_array([5; 32]), unframe)
        .fetch(&indexer)
        .unwrap()
        .spendable;
    assert_eq!(other_ring.utxos().count(), 0);

    let unframed = UtxoScan::new(&owner, &assets)
        .with_ring_deposit_payload(ring, unframe)
        .fetch(&indexer)
        .unwrap()
        .spendable;
    let utxos: Vec<_> = unframed.utxos().collect();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].utxo_hash, deposited.hash);
    assert_eq!(utxos[0].utxo.ring_program_id, Some(ring));

    // Framing that does not parse fails the fetch instead of hiding the deposit.
    let reject = |_: &[u8]| -> Result<Option<&[u8]>, TransactionError> {
        Err(TransactionError::Deserialize("bad frame".into()))
    };
    assert!(matches!(
        UtxoScan::new(&owner, &assets)
            .with_ring_deposit_payload(ring, reject)
            .fetch(&indexer),
        Err(ClientError::Transaction(TransactionError::Deserialize(_)))
    ));
}

const MINT: Address = Address::new_from_array([7; 32]);
const OTHER_PROGRAM: Address = Address::new_from_array([9; 32]);

fn registration(mint: Mint) -> (Address, Account) {
    (
        pda::spl_asset_registry(&mint.asset),
        Account {
            lamports: 1,
            data: SplAssetRegistry::account_bytes(mint.asset, mint.asset_id).to_vec(),
            owner: PROGRAM_ID_PUBKEY,
            executable: false,
            rent_epoch: 0,
        },
    )
}

fn confidential(owner: &ShieldedKeypair, mint: Mint, nonce: u8) -> (ShieldedTransaction, Note) {
    let mut utxo = sol(owner, 19, nonce);
    utxo.asset = mint;
    let received = note(owner, utxo, [0; 32]);
    let tx = ViewingKey::from_bytes(&[nonce; 32]);
    let salt = [nonce; 16];
    let assets = AssetRegistry::default();
    let message = Confidential::encode(
        std::slice::from_ref(&received.utxo),
        &OwnerCx {
            owner: owner.signing_pubkey(),
            assets: &assets,
            ring_program_id: None,
            first_nullifier: None,
        },
        [0; 32],
        &ConfidentialEncode {
            tx: tx.clone(),
            recipient_pubkey: owner.viewing_pubkey(),
            salt,
            slot_index: 0,
        },
    )
    .unwrap();
    (
        ShieldedTransaction {
            slot: u64::from(nonce),
            tx_signature: Signature::from([nonce; 64]),
            event_index: Some(0),
            tx_viewing_pk: Some(tx.pubkey()),
            salt: Some(salt),
            output_slots: vec![output_slot(
                owner.signing_pubkey().confidential_view_tag().unwrap(),
                received.hash,
                u64::from(nonce),
                message.data,
            )],
            messages: Vec::new(),
            nullifiers: Vec::new(),
            proofless: false,
            ring_config: None,
            ring_program_id: None,
        },
        received,
    )
}

#[test]
fn discovery_reuses_pages_and_follows_newly_resolved_nullifiers() {
    let owner = keypair(7);
    let first_mint = Mint::new(MINT, 2);
    let second_mint = Mint::new(OTHER_PROGRAM, 3);
    let (deposit, first) = asset_deposit(&owner, first_mint, 30, 1);
    let (mut transfer, second) = confidential(&owner, second_mint, 2);
    // Reached by the first note's nullifier rather than an owner tag. Its
    // asset was not present in the first batch, but one registry read covers
    // every subsequent round as well.
    transfer.output_slots[0].view_tag = [99; 32];
    transfer.nullifiers = vec![first.nullifier];
    let indexer = Indexer {
        deposits: vec![deposit],
        spends: vec![transfer, spend(&owner, &second, 3)],
        registrations: vec![registration(first_mint), registration(second_mint)],
        page_size: 100,
        ..Indexer::default()
    };
    let original = AssetRegistry::default();
    let scan = UtxoScan::new(&owner, &original)
        .with_indexer_config(IndexerRpcConfig::at_slot(42))
        .with_asset_discovery()
        .fetch(&indexer)
        .unwrap();
    assert!(
        scan.spendable.utxos().next().is_none(),
        "both discovered notes were already spent"
    );
    assert_eq!(scan.history.utxos.len(), 2);
    assert_eq!(scan.history.transactions.len(), 3);
    assert!(scan.history.unknown_asset_ids.is_empty());
    assert!(scan.history.unknown_mints.is_empty());
    assert_eq!(scan.asset_registry.asset_id(&MINT).unwrap(), 2);
    assert_eq!(scan.asset_registry.asset_id(&OTHER_PROGRAM).unwrap(), 3);
    assert!(
        original.asset_id(&MINT).is_err(),
        "the caller owns its registry"
    );
    assert_eq!(*indexer.registry_reads.borrow(), 1);
    assert_eq!(*indexer.registry_required_slots.borrow(), vec![Some(42)]);
    assert_eq!(indexer.reads_of("get_shielded_transactions_by_tags"), 1);
    assert_eq!(indexer.reads_of("get_encrypted_utxos_by_tags"), 1);
    assert_eq!(
        *indexer.queried_nullifiers.borrow(),
        vec![first.nullifier, second.nullifier]
    );
    assert!(indexer
        .required_slots
        .borrow()
        .iter()
        .all(|slot| *slot == Some(42)));
    UtxoScan::new(&owner, &scan.asset_registry)
        .with_asset_discovery()
        .fetch(&indexer)
        .unwrap();
    assert_eq!(
        *indexer.registry_reads.borrow(),
        1,
        "the returned registry avoids another lookup"
    );
}

#[test]
fn discovery_requires_the_scan_slot_and_all_fetched_transaction_slots() {
    for (required_slot, newest_slot, expected) in
        [(None, 90, 90), (Some(120), 90, 120), (Some(42), 90, 90)]
    {
        let owner = keypair(7);
        let mint = Mint::new(MINT, 2);
        let (unknown, _) = asset_deposit(&owner, mint, 30, 1);
        let (mut known, _) = deposit(&owner, 7, 2);
        known.slot = newest_slot;
        let indexer = Indexer {
            deposits: vec![unknown, known],
            registrations: vec![registration(mint)],
            page_size: 100,
            ..Indexer::default()
        };
        let assets = AssetRegistry::default();
        let scan = UtxoScan::new(&owner, &assets).with_asset_discovery();
        let scan = match required_slot {
            Some(slot) => scan.with_indexer_config(IndexerRpcConfig::at_slot(slot)),
            None => scan,
        }
        .fetch(&indexer)
        .unwrap();
        assert_eq!(
            *indexer.registry_required_slots.borrow(),
            vec![Some(expected)]
        );
        assert_eq!(
            scan.spendable.balances.get_balance(MINT).unwrap().amount,
            30
        );
        assert_eq!(
            scan.spendable
                .balances
                .get_balance(SOL_MINT)
                .unwrap()
                .amount,
            7
        );
    }
}

#[test]
fn discovery_in_a_nullifier_round_requires_that_transactions_slot() {
    let owner = keypair(7);
    let (initial, first) = deposit(&owner, 30, 1);
    let mint = Mint::new(MINT, 2);
    let (mut transfer, _) = confidential(&owner, mint, 2);
    transfer.slot = 97;
    transfer.output_slots[0].view_tag = [99; 32];
    transfer.nullifiers = vec![first.nullifier];
    let indexer = Indexer {
        deposits: vec![initial],
        spends: vec![transfer],
        registrations: vec![registration(mint)],
        page_size: 100,
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    let scan = UtxoScan::new(&owner, &assets)
        .with_indexer_config(IndexerRpcConfig::at_slot(42))
        .with_asset_discovery()
        .fetch(&indexer)
        .unwrap();
    assert_eq!(*indexer.registry_required_slots.borrow(), vec![Some(97)]);
    assert_eq!(
        scan.spendable.balances.get_balance(MINT).unwrap().amount,
        19
    );
    assert!(scan.history.unknown_asset_ids.is_empty());
    assert_eq!(indexer.reads_of("get_shielded_transactions_by_tags"), 1);
    assert_eq!(indexer.reads_of("get_encrypted_utxos_by_tags"), 1);
}

#[test]
fn a_lagging_registry_node_cannot_return_a_successful_partial_scan() {
    let owner = keypair(7);
    let (mut deposit, _) = asset_deposit(&owner, Mint::new(MINT, 2), 30, 1);
    deposit.slot = 90;
    let indexer = Indexer {
        deposits: vec![deposit],
        registry_slot: Some(89),
        page_size: 100,
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    assert!(matches!(
        UtxoScan::new(&owner, &assets).with_asset_discovery().fetch(&indexer),
        Err(ClientError::Rpc(message)) if message == "minimum context slot has not been reached"
    ));
    assert_eq!(*indexer.registry_required_slots.borrow(), vec![Some(90)]);
    assert_eq!(assets, AssetRegistry::default());
}

#[test]
fn discovery_reports_unresolved_assets_without_hiding_known_balances_or_spends() {
    let owner = keypair(7);
    let mint = Mint::new(MINT, 2);
    let (unknown_deposit, _) = asset_deposit(&owner, mint, 30, 1);
    let (mut transfer, _) = confidential(&owner, mint, 2);
    // An unresolved id is sender-provided and cannot yet be checked against
    // the commitment. Even a bogus output must not prevent scanning real funds.
    transfer.output_slots[0].output_context.hash = [0; 32];
    let known_mint = Mint::new(OTHER_PROGRAM, 3);
    let (known_deposit, known) = asset_deposit(&owner, known_mint, 41, 3);
    let (sol_deposit, sol) = deposit(&owner, 7, 4);
    let indexer = Indexer {
        deposits: vec![unknown_deposit, known_deposit, sol_deposit],
        tagged: vec![transfer],
        spends: vec![spend(&owner, &known, 5)],
        registrations: vec![registration(known_mint)],
        page_size: 100,
        ..Indexer::default()
    };
    let original = AssetRegistry::default();
    let scan = UtxoScan::new(&owner, &original)
        .with_asset_discovery()
        .fetch(&indexer)
        .unwrap();
    assert_eq!(scan.history.unknown_asset_ids, BTreeSet::from([2]));
    assert_eq!(scan.history.unknown_mints, BTreeSet::from([MINT]));
    assert_eq!(scan.spendable.unknown_asset_ids, BTreeSet::from([2]));
    assert_eq!(scan.spendable.unknown_mints, BTreeSet::from([MINT]));
    assert_eq!(
        scan.spendable
            .balances
            .get_balance(SOL_MINT)
            .unwrap()
            .amount,
        7
    );
    assert_eq!(
        scan.spendable
            .utxos()
            .map(|utxo| utxo.utxo_hash)
            .collect::<Vec<_>>(),
        vec![sol.hash]
    );
    assert_eq!(scan.history.utxos.len(), 2);
    assert_eq!(scan.history.transactions.len(), 5);
    assert_eq!(scan.asset_registry.asset_id(&OTHER_PROGRAM).unwrap(), 3);
    assert_eq!(*indexer.registry_reads.borrow(), 1);
    assert_eq!(indexer.reads_of("get_shielded_transactions_by_tags"), 1);
    assert_eq!(indexer.reads_of("get_encrypted_utxos_by_tags"), 1);
    assert!(original.asset_id(&MINT).is_err());
    assert!(original.asset_id(&OTHER_PROGRAM).is_err());
}

#[test]
fn a_registry_failure_is_not_a_successful_partial_scan() {
    let owner = keypair(7);
    let (deposit, _) = asset_deposit(&owner, Mint::new(MINT, 2), 30, 1);
    let indexer = Indexer {
        deposits: vec![deposit],
        registry_fails: true,
        page_size: 100,
        ..Indexer::default()
    };
    let original = AssetRegistry::default();
    assert!(
        matches!(UtxoScan::new(&owner, &original).with_asset_discovery().fetch(&indexer), Err(ClientError::Rpc(message)) if message == "registry unavailable")
    );
}

#[test]
fn an_unknown_asset_in_a_later_round_does_not_stop_following_known_nullifiers() {
    let owner = keypair(7);
    let first_mint = Mint::new(MINT, 2);
    let (first_deposit, first) = asset_deposit(&owner, first_mint, 30, 1);
    let (mut transfer, _) = confidential(&owner, Mint::new(OTHER_PROGRAM, 3), 2);
    transfer.output_slots[0].view_tag = [99; 32];
    transfer.nullifiers = vec![first.nullifier];
    let (sol_deposit, sol) = deposit(&owner, 7, 3);
    let (merged_tx, merged) = merge(&owner, &[&sol], sol.nullifier, 4);
    let indexer = Indexer {
        deposits: vec![first_deposit, sol_deposit],
        spends: vec![transfer, merged_tx, spend(&owner, &merged, 5)],
        registrations: vec![registration(first_mint)],
        page_size: 100,
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    let scan = UtxoScan::new(&owner, &assets)
        .with_asset_discovery()
        .fetch(&indexer)
        .unwrap();
    assert_eq!(scan.history.unknown_asset_ids, BTreeSet::from([3]));
    assert!(scan.history.unknown_mints.is_empty());
    assert_eq!(scan.spendable.unknown_asset_ids, BTreeSet::from([3]));
    assert!(scan.spendable.unknown_mints.is_empty());
    assert!(scan.spendable.utxos().next().is_none());
    assert_eq!(scan.history.utxos.len(), 3);
    assert_eq!(scan.history.transactions.len(), 5);
    let queried = indexer.queried_nullifiers.borrow();
    assert_eq!(queried.len(), 3);
    assert_eq!(
        queried.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([first.nullifier, sol.nullifier, merged.nullifier])
    );
    assert_eq!(*indexer.registry_reads.borrow(), 1);
    assert_eq!(indexer.reads_of("get_shielded_transactions_by_tags"), 1);
    assert_eq!(indexer.reads_of("get_encrypted_utxos_by_tags"), 1);
}

#[test]
fn discovery_does_not_overwrite_a_conflicting_cached_mapping() {
    let owner = keypair(7);
    let (deposit, _) = asset_deposit(&owner, Mint::new(OTHER_PROGRAM, 3), 30, 1);
    let indexer = Indexer {
        deposits: vec![deposit],
        registrations: vec![registration(Mint::new(MINT, 2))],
        page_size: 100,
        ..Indexer::default()
    };
    let assets = AssetRegistry::new([(4, MINT)]).unwrap();
    assert!(matches!(
        UtxoScan::new(&owner, &assets).with_asset_discovery().fetch(&indexer),
        Err(ClientError::InvalidSplAssetRegistry { mint }) if mint == MINT
    ));
    assert_eq!(assets.asset_id(&MINT).unwrap(), 4);
}

#[test]
fn explicit_assets_stay_an_allowlist_and_known_assets_need_no_lookup() {
    let owner = keypair(7);
    let (deposit, _) = asset_deposit(&owner, Mint::new(MINT, 2), 30, 1);
    let indexer = Indexer {
        deposits: vec![deposit],
        page_size: 100,
        ..Indexer::default()
    };
    let original = AssetRegistry::default();
    let scan = UtxoScan::new(&owner, &original).fetch(&indexer).unwrap();
    assert_eq!(scan.history.unknown_mints, BTreeSet::from([MINT]));
    assert!(scan.spendable.utxos().next().is_none());
    assert_eq!(*indexer.registry_reads.borrow(), 0);
    let known = AssetRegistry::new([(2, MINT)]).unwrap();
    let scan = UtxoScan::new(&owner, &known)
        .with_asset_discovery()
        .fetch(&indexer)
        .unwrap();
    assert_eq!(
        scan.spendable.balances.get_balance(MINT).unwrap().amount,
        30
    );
    assert_eq!(*indexer.registry_reads.borrow(), 0);
}

#[test]
fn invalid_or_conflicting_registry_listings_fail() {
    let mint = Mint::new(MINT, 2);
    let valid = registration(mint);
    let mut wrong_owner = valid.clone();
    wrong_owner.1.owner = OTHER_PROGRAM;
    let mut wrong_pda = valid.clone();
    wrong_pda.0 = OTHER_PROGRAM;
    let mut truncated = valid.clone();
    truncated.1.data.pop();
    let mut wrong_discriminator = valid.clone();
    wrong_discriminator.1.data[0] ^= 1;
    let mut invalid_data = valid.clone();
    invalid_data.1.data[8] ^= 1;
    for registrations in [
        vec![wrong_owner],
        vec![wrong_pda],
        vec![truncated],
        vec![wrong_discriminator],
        vec![invalid_data],
        vec![registration(Mint::new(MINT, SOL_ASSET_ID))],
        vec![valid.clone(), registration(Mint::new(OTHER_PROGRAM, 2))],
        vec![valid.clone(), registration(Mint::new(MINT, 3))],
    ] {
        let indexer = Indexer {
            registrations,
            ..Indexer::default()
        };
        assert!(matches!(
            fetch_spl_asset_registrations(&indexer, None),
            Err(ClientError::InvalidSplAssetRegistration { .. })
        ));
    }
    let indexer = Indexer {
        registrations: vec![valid],
        ..Indexer::default()
    };
    assert_eq!(
        fetch_spl_asset_registrations(&indexer, Some(42)).unwrap(),
        vec![mint]
    );
    assert_eq!(*indexer.registry_required_slots.borrow(), vec![Some(42)]);
}

#[test]
fn filtered_registry_reads_cannot_fall_back_to_an_unfiltered_listing() {
    struct Unfiltered;
    impl Rpc for Unfiltered {
        fn get_program_accounts(&self, _: Address) -> Result<Vec<(Address, Account)>, ClientError> {
            panic!("asset discovery must send a filtered query")
        }
    }
    assert!(matches!(
        fetch_spl_asset_registrations(&Unfiltered, Some(42)),
        Err(ClientError::UnsupportedRpcMethod(
            "get_program_accounts_filtered"
        ))
    ));
}

/// Accounts by address; `get_account` is the only request it answers.
#[derive(Default)]
struct Accounts(HashMap<Address, Account>);

impl Accounts {
    fn with(mut self, address: Address, owner: Address, data: Vec<u8>) -> Self {
        self.0.insert(
            address,
            Account {
                lamports: 1,
                data,
                owner,
                executable: false,
                rent_epoch: 0,
            },
        );
        self
    }

    fn registry(self, owner: Address, mint: Address, asset_id: u64) -> Self {
        self.with(
            pda::spl_asset_registry(&MINT),
            owner,
            SplAssetRegistry::account_bytes(mint, asset_id).to_vec(),
        )
    }
}

impl Rpc for Accounts {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        Ok(self.0.get(&address).cloned())
    }
}

/// An `Rpc` that fails every request, so a lookup that succeeds with it made
/// none.
struct Offline;

impl Rpc for Offline {}

#[test]
fn sol_has_the_reserved_asset_id_without_a_request() {
    assert_eq!(fetch_asset_id(&Offline, SOL_MINT).unwrap(), SOL_ASSET_ID);
}

#[test]
fn asset_id_is_read_from_the_pool_registry_account_of_the_mint() {
    let rpc = Accounts::default().registry(PROGRAM_ID_PUBKEY, MINT, 5);
    assert_eq!(fetch_asset_id(&rpc, MINT).unwrap(), 5);
}

#[test]
fn a_mint_without_a_pool_owned_registry_account_is_not_registered() {
    let not_registered = |rpc: &Accounts| {
        matches!(
            fetch_asset_id(rpc, MINT),
            Err(ClientError::SplAssetNotRegistered { mint }) if mint == MINT
        )
    };
    assert!(not_registered(&Accounts::default()));
    // Lamports sent to the registry address make a system-owned account.
    assert!(not_registered(&Accounts::default().with(
        pda::spl_asset_registry(&MINT),
        Address::default(),
        Vec::new(),
    )));
    assert!(not_registered(&Accounts::default().registry(
        OTHER_PROGRAM,
        MINT,
        5
    )));
}

#[test]
fn a_pool_registry_account_that_does_not_parse_or_names_another_mint_is_invalid() {
    let invalid = |rpc: &Accounts| {
        matches!(
            fetch_asset_id(rpc, MINT),
            Err(ClientError::InvalidSplAssetRegistry { mint }) if mint == MINT
        )
    };
    let mut truncated = SplAssetRegistry::account_bytes(MINT, 5).to_vec();
    truncated.pop();
    assert!(invalid(&Accounts::default().with(
        pda::spl_asset_registry(&MINT),
        PROGRAM_ID_PUBKEY,
        truncated,
    )));
    assert!(invalid(&Accounts::default().registry(
        PROGRAM_ID_PUBKEY,
        OTHER_PROGRAM,
        5
    )));
}
