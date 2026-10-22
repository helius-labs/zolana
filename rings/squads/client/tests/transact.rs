//! Rail-selection and input-validation tests for `request_transact` /
//! `request_transact_probe`. The full probe/finalize needs indexer proofs and the
//! SPP prover server and is exercised by the integration suite; these paths all fail
//! before any proof is fetched.

use solana_account::Account;
use solana_keypair::Keypair;
use zolana_client::{ClientError, Rpc};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_keypair::X25519Keypair;
use zolana_keypair::X25519Pubkey;
use zolana_squads_client::{
    seed_viewing_key_account, DecryptedUtxo, OutputUtxo, PrivateTransactionIntent,
    RequestTransactRequest, SquadsBackend, SquadsBackendError, TransactionType,
    ViewingKeyAccountSeed, SOL_ASSET_ID,
};
use zolana_squads_interface::types::Address;

const SENDER: Address = Address::new_from_array([10u8; 32]);
const RECIPIENT: Address = Address::new_from_array([20u8; 32]);

#[derive(Clone)]
struct MockRpc {
    accounts: Vec<(Address, Account)>,
}

impl Rpc for MockRpc {
    fn get_account(&self, address: Address) -> core::result::Result<Option<Account>, ClientError> {
        Ok(self
            .accounts
            .iter()
            .find(|(a, _)| *a == address)
            .map(|(_, account)| account.clone()))
    }
}

fn account(data: Vec<u8>) -> Account {
    Account {
        lamports: 1,
        data,
        owner: Address::default(),
        executable: false,
        rent_epoch: 0,
    }
}

fn seeded(owner: [u8; 32], auditor_pk: X25519Pubkey) -> Vec<u8> {
    let owner = solana_owner_identity(&owner).expect("owner identity");
    seed_viewing_key_account(
        ViewingKeyAccountSeed {
            owner: Address::new_from_array(owner),
            owner_kind: 2,
            state: 1,
            encryption_scheme: zolana_squads_interface::constants::ENCRYPTION_SCHEME_X25519_AES,
            key_nonce: 0,
        },
        &X25519Keypair::new(),
        &X25519Keypair::new(),
        &[3u8; 32],
        &[],
        &[auditor_pk],
    )
    .expect("seed account")
    .serialize()
    .expect("serialize vka")
}

/// A backend whose RPC serves a sender and a recipient viewing key account.
fn backend_with_accounts() -> SquadsBackend<MockRpc, MockRpc> {
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let rpc = MockRpc {
        accounts: vec![
            (SENDER, account(seeded([1u8; 32], auditor_pk))),
            (RECIPIENT, account(seeded([2u8; 32], auditor_pk))),
        ],
    };
    SquadsBackend::new(
        auditor,
        Keypair::new(),
        Address::default(),
        0,
        "http://127.0.0.1:3001",
        rpc.clone(),
        rpc,
    )
}

fn empty_backend() -> SquadsBackend<MockRpc, MockRpc> {
    let rpc = MockRpc {
        accounts: Vec::new(),
    };
    SquadsBackend::new(
        X25519Keypair::new(),
        Keypair::new(),
        Address::default(),
        0,
        "http://127.0.0.1:3001",
        rpc.clone(),
        rpc,
    )
}

fn input(asset_id: u64, leaf_index: u64) -> DecryptedUtxo {
    DecryptedUtxo {
        utxo_hash: [7u8; 32],
        asset_id,
        amount: 1_000,
        blinding: [0u8; 32],
        tree_id: 0,
        leaf_index,
    }
}

fn intent(inputs: Vec<DecryptedUtxo>, outputs: Vec<OutputUtxo>) -> PrivateTransactionIntent {
    PrivateTransactionIntent {
        sender_viewing_key_account: SENDER,
        inputs,
        outputs,
        expiry: 0,
    }
}

fn withdraw() -> TransactionType {
    TransactionType::Withdraw {
        public_amount: 1,
        recipient_account: Address::default(),
    }
}

fn smart_account_request(
    transaction_type: TransactionType,
    intent: PrivateTransactionIntent,
) -> RequestTransactRequest {
    RequestTransactRequest {
        transaction_type,
        intent,
        sender_owner_pubkey: None,
        owner_signature: None,
    }
}

fn owner_pubkey() -> [u8; 32] {
    zolana_keypair::SigningKey::new_ed25519()
        .pubkey()
        .as_ed25519()
        .expect("Ed25519 owner")
}

fn unsupported_message(err: SquadsBackendError) -> String {
    match err {
        SquadsBackendError::Unsupported(message) => message,
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn ed25519_rail_requires_owner_signature() {
    let request = RequestTransactRequest {
        transaction_type: withdraw(),
        intent: intent(vec![input(SOL_ASSET_ID, 0)], Vec::new()),
        sender_owner_pubkey: Some(owner_pubkey()),
        owner_signature: None,
    };
    let err = backend_with_accounts()
        .request_transact(request)
        .unwrap_err();
    assert_eq!(
        unsupported_message(err),
        "Ed25519 keypair rail requires owner_signature over transact_message_hash(private_tx_hash, external_data_hash); obtain it via request_transact_probe"
    );
}

#[test]
fn probe_requires_sender_owner_pubkey() {
    let request = smart_account_request(withdraw(), intent(Vec::new(), Vec::new()));
    let err = empty_backend()
        .request_transact_probe(&request)
        .unwrap_err();
    assert_eq!(
        unsupported_message(err),
        "the Ed25519 keypair rail requires sender_owner_pubkey"
    );
}

#[test]
fn smart_account_rail_resolves_sender_first() {
    let request = smart_account_request(
        TransactionType::Transfer {
            recipient_viewing_key_account: RECIPIENT,
        },
        intent(vec![input(SOL_ASSET_ID, 0)], Vec::new()),
    );
    let err = empty_backend().request_transact(request).unwrap_err();
    assert!(
        matches!(err, SquadsBackendError::AccountNotFound(ref address) if *address == SENDER.to_string()),
        "{err:?}"
    );
}

#[test]
fn spend_requires_an_input() {
    let request = smart_account_request(withdraw(), intent(Vec::new(), Vec::new()));
    let err = backend_with_accounts()
        .request_transact(request)
        .unwrap_err();
    assert_eq!(unsupported_message(err), "a spend needs at least one input");
}

#[test]
fn spend_rejects_unknown_asset() {
    let request = smart_account_request(withdraw(), intent(vec![input(9, 0)], Vec::new()));
    let err = backend_with_accounts()
        .request_transact(request)
        .unwrap_err();
    assert_eq!(unsupported_message(err), "unknown asset_id 9");
}

#[test]
fn withdrawal_takes_at_most_one_input() {
    let request = smart_account_request(
        withdraw(),
        intent(
            vec![input(SOL_ASSET_ID, 0), input(SOL_ASSET_ID, 1)],
            Vec::new(),
        ),
    );
    let err = backend_with_accounts()
        .request_transact(request)
        .unwrap_err();
    assert_eq!(unsupported_message(err), "a spend takes at most 1 inputs");
}

#[test]
fn transfer_requires_a_recipient_output() {
    let request = smart_account_request(
        TransactionType::Transfer {
            recipient_viewing_key_account: RECIPIENT,
        },
        intent(
            vec![input(SOL_ASSET_ID, 0)],
            vec![OutputUtxo {
                owner: Address::new_from_array([5u8; 32]),
                asset_id: SOL_ASSET_ID,
                amount: 1_000,
            }],
        ),
    );
    let err = backend_with_accounts()
        .request_transact(request)
        .unwrap_err();
    assert_eq!(unsupported_message(err), "intent has no recipient output");
}
