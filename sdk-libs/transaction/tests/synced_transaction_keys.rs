mod common;

use std::cell::RefCell;

use common::{keypair, wallet_utxo};
use zolana_keypair::{P256Pubkey, ShieldedAddress, ShieldedKeypair, ViewingKey};
use zolana_transaction::{
    decrypt_spendable,
    instructions::{merge::MergeTransaction, transact::ConfidentialTransaction},
    serialization::proofless::{Proofless, ProoflessEncode},
    Address, AssetAmount, AssetRegistry, DecryptRequest, DeriveRequest, LocalShieldedKeys, Mint,
    OutputContext, OutputSlot, OwnerCx, ShieldedKeys, ShieldedTransaction, ShieldedView,
    SpendableDecryptionResult, TransactionError, TransactionKeyRequest, UtxoSerialization,
    WalletUtxo,
};

struct CountingKeys {
    local: LocalShieldedKeys,
    transaction_key_calls: RefCell<Vec<Vec<TransactionKeyRequest>>>,
    drop_keys: bool,
}

impl CountingKeys {
    fn new(owner: &ShieldedKeypair) -> Self {
        Self {
            local: LocalShieldedKeys::from_keypair(owner).unwrap(),
            transaction_key_calls: RefCell::new(vec![]),
            drop_keys: false,
        }
    }

    fn calls(&self) -> Vec<Vec<TransactionKeyRequest>> {
        self.transaction_key_calls.borrow().clone()
    }
}

impl ShieldedKeys for CountingKeys {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        self.local.address()
    }

    fn viewing_public_keys(&self) -> Vec<P256Pubkey> {
        self.local.viewing_public_keys()
    }

    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        self.local.decrypt(requests)
    }

    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.local.derive(requests)
    }

    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        self.transaction_key_calls
            .borrow_mut()
            .push(requests.to_vec());
        if self.drop_keys {
            return Ok(vec![]);
        }
        self.local.transaction_keys(requests)
    }
}

fn published(owner: &ShieldedKeypair, note: &WalletUtxo) -> ShieldedTransaction {
    let assets = AssetRegistry::default();
    let message = Proofless::encode(
        std::slice::from_ref(&note.utxo),
        &OwnerCx {
            owner: owner.signing_pubkey(),
            assets: &assets,
            ring_program_id: None,
            first_nullifier: None,
        },
        [0; 32],
        &ProoflessEncode {
            owner_hash: owner.shielded_address().unwrap().owner_hash().unwrap(),
            data_hash: note.data_hash,
            ring_data_hash: note.ring_data_hash,
        },
    )
    .unwrap();
    ShieldedTransaction {
        slot: note.slot,
        tx_signature: note.tx_signature,
        event_index: None,
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: [0; 32],
            output_context: OutputContext {
                hash: note.utxo_hash,
                tree_id: note.tree_id,
                leaf_index: note.leaf_index,
            },
            payload: message.data,
        }],
        messages: vec![],
        nullifiers: vec![],
        proofless: false,
        ring_config: None,
        ring_program_id: None,
    }
}

fn data_note(owner: &ShieldedKeypair, amount: u64, nonce: u8) -> WalletUtxo {
    let mut note = wallet_utxo(owner, Mint::SOL, amount, 3, nonce);
    note.data_hash = Some([1; 32]);
    note.utxo_hash = note
        .utxo
        .hash(&note.nullifier_pubkey, &[1; 32], &[0; 32], note.tree_id)
        .unwrap();
    note.nullifier = owner
        .nullifier(&note.utxo_hash, &note.utxo.blinding)
        .unwrap();
    note
}

fn spl() -> Mint {
    Mint::new(Address::new_from_array([17; 32]), 9)
}

fn assets() -> AssetRegistry {
    AssetRegistry::new([(spl().asset_id, spl().asset)]).unwrap()
}

fn synced_publications(owner: &ShieldedKeypair) -> Vec<ShieldedTransaction> {
    vec![
        published(owner, &wallet_utxo(owner, Mint::SOL, 10, 3, 1)),
        published(owner, &wallet_utxo(owner, spl(), 7, 3, 2)),
        published(owner, &data_note(owner, 5, 3)),
        published(owner, &wallet_utxo(owner, Mint::SOL, 20, 3, 4)),
    ]
}

fn spendable_notes(result: &mut SpendableDecryptionResult) -> Vec<&mut WalletUtxo> {
    result
        .balances
        .assets
        .iter_mut()
        .flat_map(|balance| balance.utxos.iter_mut())
        .chain(result.utxos_with_data.iter_mut())
        .collect()
}

fn transaction_key_secret(owner: &ShieldedKeypair, first_nullifier: &[u8; 32]) -> [u8; 32] {
    *owner
        .get_transaction_viewing_key(first_nullifier)
        .unwrap()
        .secret_bytes()
}

#[test]
fn spendable_utxos_attach_every_notes_first_input_key_in_one_request() {
    let owner = keypair(40);
    let viewing_pubkey = owner.shielded_address().unwrap().viewing_pubkey;
    let transactions = synced_publications(&owner);
    let assets = assets();
    let keys = CountingKeys::new(&owner);

    let synced = keys.spendable_utxos(&transactions, &assets).unwrap();

    let mut expected = decrypt_spendable(&owner, &transactions, &assets).unwrap();
    let mut expected_requests = vec![];
    for note in spendable_notes(&mut expected) {
        note.tx_viewing_key = Some(transaction_key_secret(&owner, &note.nullifier));
        expected_requests.push(TransactionKeyRequest {
            viewing_pubkey,
            first_nullifier: note.nullifier,
        });
    }
    assert_eq!(expected_requests.len(), 4);
    assert_eq!(expected.utxos_with_data.len(), 1);
    assert_eq!(synced, expected);
    assert_eq!(keys.calls(), vec![expected_requests]);
}

#[test]
fn spendable_utxos_skip_the_key_request_when_nothing_is_spendable() {
    let owner = keypair(41);
    let keys = CountingKeys::new(&owner);

    let synced = keys
        .spendable_utxos(&[], &AssetRegistry::default())
        .unwrap();

    assert_eq!(synced, SpendableDecryptionResult::default());
    assert!(keys.calls().is_empty());
}

#[test]
fn spendable_utxos_reject_a_key_response_missing_keys() {
    let owner = keypair(42);
    let transactions = synced_publications(&owner);
    let mut keys = CountingKeys::new(&owner);
    keys.drop_keys = true;

    assert_eq!(
        keys.spendable_utxos(&transactions, &assets()).err(),
        Some(TransactionError::IncompleteDerivation { got: 0, want: 4 })
    );
}

#[test]
fn spendable_balance_reports_amounts_without_transaction_keys() {
    let owner = keypair(43);
    let transactions = synced_publications(&owner);
    let keys = CountingKeys::new(&owner);

    let amounts = keys.spendable_balance(&transactions, &assets()).unwrap();

    assert_eq!(
        amounts,
        vec![
            AssetAmount {
                asset_id: Mint::SOL.asset_id,
                mint: Mint::SOL.asset,
                amount: 30,
            },
            AssetAmount {
                asset_id: spl().asset_id,
                mint: spl().asset,
                amount: 7,
            },
        ]
    );
    assert!(keys.calls().is_empty());
}

#[test]
fn a_transfer_encrypts_with_the_synced_key_of_its_first_input() {
    let owner = keypair(44);
    let receiver = keypair(45).shielded_address().unwrap();
    let payer = owner.shielded_address().unwrap().solana_address().unwrap();
    let keys = CountingKeys::new(&owner);
    let synced_key = keypair(46).viewing_key;
    let mut input = wallet_utxo(&owner, Mint::SOL, 3, 7, 1);
    input.tx_viewing_key = Some(*synced_key.secret_bytes());

    let mut transaction = ConfidentialTransaction::new(vec![input], payer).unwrap();
    transaction.transfer_sol(&receiver, 2).unwrap();
    let proof_inputs = transaction.encrypt(&keys).unwrap();

    assert_eq!(
        proof_inputs.external_data.tx_viewing_pk,
        *synced_key.pubkey().as_bytes()
    );
    assert!(keys.calls().is_empty());
}

#[test]
fn a_transfer_without_a_synced_key_requests_one_for_its_first_input() {
    let owner = keypair(47);
    let sender = owner.shielded_address().unwrap();
    let receiver = keypair(48).shielded_address().unwrap();
    let keys = CountingKeys::new(&owner);
    let input = wallet_utxo(&owner, Mint::SOL, 3, 7, 1);
    let first_nullifier = input.nullifier;

    let mut transaction =
        ConfidentialTransaction::new(vec![input], sender.solana_address().unwrap()).unwrap();
    transaction.transfer_sol(&receiver, 2).unwrap();
    let proof_inputs = transaction.encrypt(&keys).unwrap();

    assert_eq!(
        proof_inputs.external_data.tx_viewing_pk,
        *owner
            .get_transaction_viewing_key(&first_nullifier)
            .unwrap()
            .pubkey()
            .as_bytes()
    );
    assert_eq!(
        keys.calls(),
        vec![vec![TransactionKeyRequest {
            viewing_pubkey: sender.viewing_pubkey,
            first_nullifier,
        }]]
    );
}

#[test]
fn a_synced_transfer_needs_no_key_request_after_sync() {
    let owner = keypair(49);
    let receiver = keypair(50).shielded_address().unwrap();
    let payer = owner.shielded_address().unwrap().solana_address().unwrap();
    let keys = CountingKeys::new(&owner);
    let transactions = vec![published(
        &owner,
        &wallet_utxo(&owner, Mint::SOL, 9, 3, 1),
    )];

    let synced = keys
        .spendable_utxos(&transactions, &AssetRegistry::default())
        .unwrap();
    let input = synced
        .balances
        .assets
        .first()
        .and_then(|balance| balance.utxos.first())
        .cloned()
        .unwrap();
    let first_nullifier = input.nullifier;
    let mut transaction = ConfidentialTransaction::new(vec![input], payer).unwrap();
    transaction.transfer_sol(&receiver, 4).unwrap();
    let proof_inputs = transaction.encrypt(&keys).unwrap();

    assert_eq!(keys.calls().len(), 1);
    assert_eq!(
        proof_inputs.external_data.tx_viewing_pk,
        *owner
            .get_transaction_viewing_key(&first_nullifier)
            .unwrap()
            .pubkey()
            .as_bytes()
    );
}

#[test]
fn a_merge_encrypts_with_the_synced_key_of_its_first_input() {
    let owner = keypair(51);
    let keys = CountingKeys::new(&owner);
    let synced_key = keypair(52).viewing_key;
    let mut inputs: Vec<WalletUtxo> = (1..=2)
        .map(|nonce| wallet_utxo(&owner, Mint::SOL, 2, 0, nonce))
        .collect();
    if let Some(first) = inputs.first_mut() {
        first.tx_viewing_key = Some(*synced_key.secret_bytes());
    }

    let merged = MergeTransaction::new(inputs).unwrap().encrypt(&keys).unwrap();

    assert_eq!(merged.tx_viewing_pk, *synced_key.pubkey().as_bytes());
    assert!(keys.calls().is_empty());
}

#[test]
fn a_synced_key_that_is_not_a_p256_scalar_is_rejected() {
    let owner = keypair(53);
    let receiver = keypair(54).shielded_address().unwrap();
    let payer = owner.shielded_address().unwrap().solana_address().unwrap();
    let keys = CountingKeys::new(&owner);
    let mut input = wallet_utxo(&owner, Mint::SOL, 3, 7, 1);
    input.tx_viewing_key = Some([0; 32]);

    let mut transaction = ConfidentialTransaction::new(vec![input], payer).unwrap();
    transaction.transfer_sol(&receiver, 2).unwrap();

    assert!(matches!(
        transaction.encrypt(&keys).err(),
        Some(TransactionError::Keypair(_))
    ));
    assert!(keys.calls().is_empty());
}
