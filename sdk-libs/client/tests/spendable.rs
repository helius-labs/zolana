//! `SpendableUtxos::fetch` against an in-memory indexer that pages one result
//! at a time.

use std::cell::RefCell;

use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, ClientError, Context, EncryptedUtxoMatch,
    GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig,
    OutputContext, OutputSlot, Rpc, ShieldedTransaction, SpendableUtxos,
};
use zolana_event::{EncryptedRingDepositOutput, OutputDataEncoding};
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_transaction::{
    instructions::merge::{
        merge_dummy_nullifier, merge_output_blinding, MERGE_DEFAULT_INPUT_COUNT,
    },
    owner_utxo_hash,
    serialization::proofless::{Proofless, ProoflessEncode},
    AssetRegistry, Data, EncryptedScheme, HistoryKind, Mint, OwnerCx, RingDepositPlaintext,
    TransactionError, Utxo, UtxoSerialization,
};

const TREE: u16 = 2;

#[derive(Default)]
struct Indexer {
    /// Served by the view tags of their outputs.
    tagged: Vec<ShieldedTransaction>,
    deposits: Vec<EncryptedUtxoMatch>,
    /// Served by the nullifiers they publish.
    spends: Vec<ShieldedTransaction>,
    queried_tags: RefCell<Vec<Vec<[u8; 32]>>>,
    queried_nullifiers: RefCell<Vec<[u8; 32]>>,
}

fn page<T: Clone>(items: Vec<T>, cursor: Option<Vec<u8>>) -> (Vec<T>, Option<Vec<u8>>) {
    let start = cursor.map_or(0, |cursor| usize::from(cursor[0]));
    let next = (start + 1 < items.len()).then(|| vec![start as u8 + 1]);
    (items.into_iter().skip(start).take(1).collect(), next)
}

const CONTEXT: Context = Context {
    block_time: 0,
    slot: 0,
};

impl Rpc for Indexer {
    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
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
        let (transactions, next_cursor) = page(matching, cursor);
        Ok(GetShieldedTransactionsByTagsResponse {
            context: CONTEXT,
            output_tree_id: Some(TREE),
            transactions,
            next_cursor,
            scanned_through: None,
        })
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        let matching = self
            .deposits
            .iter()
            .filter(|deposit| tags.contains(&deposit.output_slot.view_tag))
            .cloned()
            .collect();
        let (matches, next_cursor) = page(matching, cursor);
        Ok(GetEncryptedUtxosByTagsResponse {
            context: CONTEXT,
            output_tree_id: Some(TREE),
            matches,
            next_cursor,
            scanned_through: None,
        })
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
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
        let (transactions, next_cursor) = page(matching, cursor);
        Ok(GetShieldedTransactionsByNullifiersResponse {
            context: CONTEXT,
            output_tree_id: Some(TREE),
            transactions,
            next_cursor,
            scanned_through: None,
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
    let address = owner.shielded_address().unwrap();
    let assets = AssetRegistry::default();
    let deposited = note(owner, sol(owner, amount, nonce), [0; 32]);
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
            address.viewing_pubkey.x(),
            deposited.hash,
            u64::from(nonce),
            message.data,
        ),
        tx_viewing_pk: None,
        salt: None,
    };
    (matched, deposited)
}

/// A merge of `inputs`, its output tagged with `view_tag`.
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
            Vec::new(),
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
    let spendable = SpendableUtxos::new(&owner, &assets)
        .fetch(&indexer)
        .unwrap();

    let utxos: Vec<_> = spendable.utxos().map(|utxo| utxo.utxo_hash).collect();
    assert_eq!(utxos, vec![merged.hash]);
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
        Some(&vec![owner_tag, address.viewing_pubkey.x()])
    );
    // Each round queries only the UTXOs found since the last one.
    let queried = indexer.queried_nullifiers.borrow();
    let mut unique = queried.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), queried.len(), "a nullifier was queried twice");
}

#[test]
fn fetch_history_keeps_the_spent_utxos_and_the_transactions_that_spent_them() {
    let owner = keypair(10);
    let owner_tag = owner
        .shielded_address()
        .unwrap()
        .signing_pubkey
        .confidential_view_tag()
        .unwrap();
    let (first_deposit, first) = deposit(&owner, 30, 1);
    let (second_deposit, second) = deposit(&owner, 12, 2);
    let (tagged_merge, merged) = merge(&owner, &[&first], owner_tag, 3);
    let (untagged_merge, untagged_output) = merge(&owner, &[&second], second.nullifier, 4);
    // Spends the untagged merge's output and pays out nothing private.
    let withdrawal = spend(&owner, &untagged_output, 5);
    let indexer = || Indexer {
        tagged: vec![tagged_merge.clone()],
        deposits: vec![first_deposit.clone(), second_deposit.clone()],
        spends: vec![
            tagged_merge.clone(),
            untagged_merge.clone(),
            withdrawal.clone(),
        ],
        ..Indexer::default()
    };
    let assets = AssetRegistry::default();
    let utxos = SpendableUtxos::new(&owner, &assets);
    let (spendable_indexer, history_indexer) = (indexer(), indexer());

    let spendable = utxos.fetch(&spendable_indexer).unwrap();
    let history = utxos.fetch_history(&history_indexer).unwrap();

    assert_eq!(history_indexer.queried_tags, spendable_indexer.queried_tags);
    assert_eq!(
        history_indexer.queried_nullifiers,
        spendable_indexer.queried_nullifiers
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
fn a_merge_found_before_one_of_its_inputs_rebuilds_in_a_later_round() {
    let owner = keypair(8);
    let (first_deposit, first) = deposit(&owner, 30, 1);
    let (second_deposit, second) = deposit(&owner, 12, 2);
    // Ring merges, tagged only by their first nullifier. M1 spends `first` and
    // Y, and the query for `first` finds it in the same round as M0, a round
    // before M0' produces Y.
    let (m0, x) = merge(&owner, &[&second], second.nullifier, 3);
    let (m0_prime, y) = merge(&owner, &[&x], x.nullifier, 4);
    let (m1, merged) = merge(&owner, &[&first, &y], first.nullifier, 5);
    let indexer = Indexer {
        deposits: vec![first_deposit, second_deposit],
        spends: vec![m0, m0_prime, m1],
        ..Indexer::default()
    };

    let assets = AssetRegistry::default();
    let spendable = SpendableUtxos::new(&owner, &assets)
        .fetch(&indexer)
        .unwrap();

    let utxos: Vec<_> = spendable.utxos().map(|utxo| utxo.utxo_hash).collect();
    assert_eq!(utxos, vec![merged.hash]);
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
                address.viewing_pubkey.x(),
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

    let framed = SpendableUtxos::new(&owner, &assets)
        .fetch(&indexer)
        .unwrap();
    assert_eq!(framed.utxos().count(), 0);

    // Another ring's framing never reads this ring's deposits.
    let other_ring = SpendableUtxos::new(&owner, &assets)
        .with_ring_deposit_payload(Address::new_from_array([5; 32]), unframe)
        .fetch(&indexer)
        .unwrap();
    assert_eq!(other_ring.utxos().count(), 0);

    let unframed = SpendableUtxos::new(&owner, &assets)
        .with_ring_deposit_payload(ring, unframe)
        .fetch(&indexer)
        .unwrap();
    let utxos: Vec<_> = unframed.utxos().collect();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].utxo_hash, deposited.hash);
    assert_eq!(utxos[0].utxo.ring_program_id, Some(ring));

    // Framing that does not parse fails the fetch instead of hiding the deposit.
    let reject = |_: &[u8]| -> Result<Option<&[u8]>, TransactionError> {
        Err(TransactionError::Deserialize("bad frame".into()))
    };
    assert!(matches!(
        SpendableUtxos::new(&owner, &assets)
            .with_ring_deposit_payload(ring, reject)
            .fetch(&indexer),
        Err(ClientError::Transaction(TransactionError::Deserialize(_)))
    ));
}
