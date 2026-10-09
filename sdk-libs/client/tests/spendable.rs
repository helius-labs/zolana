//! `SpendableUtxos::fetch` against an in-memory indexer that pages one result
//! at a time, and `fetch_asset_id` against in-memory accounts.

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeSet, HashMap},
};

use solana_account::Account;

use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{
    fetch_asset_id, rpc::GetShieldedTransactionsByNullifiersResponse, ClientError, Context,
    EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByTagsResponse,
    IndexerRpcConfig, OutputContext, OutputSlot, Rpc, ShieldedTransaction, SpendableUtxos,
};
use zolana_event::{EncryptedRingDepositOutput, OutputDataEncoding};
use zolana_interface::{pda, state::SplAssetRegistry, PROGRAM_ID_PUBKEY};
use zolana_keypair::{P256Pubkey, ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::{
    instructions::merge::{
        merge_dummy_nullifier, merge_output_blinding, MERGE_DEFAULT_INPUT_COUNT,
    },
    owner_utxo_hash,
    serialization::proofless::{Proofless, ProoflessEncode},
    AssetRegistry, Data, DecryptRequest, DeriveRequest, EncryptedScheme, HistoryKind, Mint,
    OwnerCx, RingDepositPlaintext, ShieldedKeys, TransactionError, TransactionKeyRequest, Utxo,
    UtxoSerialization, SOL_ASSET_ID, SOL_MINT,
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

/// A keypair that counts the derivation batches it answers, each a round
/// trip with a remote key holder.
struct CountingKeys<'a> {
    keypair: &'a ShieldedKeypair,
    derivations: Cell<usize>,
}

impl ShieldedKeys for CountingKeys<'_> {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        self.keypair.address()
    }

    fn viewing_public_keys(&self) -> Vec<P256Pubkey> {
        self.keypair.viewing_public_keys()
    }

    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        self.keypair.decrypt(requests)
    }

    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.derivations.set(self.derivations.get() + 1);
        self.keypair.derive(requests)
    }

    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        self.keypair.transaction_keys(requests)
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
    let counting = || CountingKeys {
        keypair: &owner,
        derivations: Cell::new(0),
    };
    let (spendable_keys, history_keys) = (counting(), counting());
    let (spendable_indexer, history_indexer) = (indexer(), indexer());

    let spendable = SpendableUtxos::new(&spendable_keys, &assets)
        .fetch(&spendable_indexer)
        .unwrap();
    let history = SpendableUtxos::new(&history_keys, &assets)
        .fetch_history(&history_indexer)
        .unwrap();

    // The history reuses the last round's owned UTXOs: the key holder derives
    // no more nullifiers than for `fetch`.
    assert_eq!(
        history_keys.derivations.get(),
        spendable_keys.derivations.get()
    );
    assert_eq!(history_indexer.queried_tags, spendable_indexer.queried_tags);
    assert_eq!(
        history_indexer.queried_nullifiers,
        spendable_indexer.queried_nullifiers
    );
    assert_eq!(
        history.view_tags,
        BTreeSet::from([owner_tag, address.viewing_pubkey.x()])
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

const MINT: Address = Address::new_from_array([7; 32]);
const OTHER_PROGRAM: Address = Address::new_from_array([9; 32]);

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
