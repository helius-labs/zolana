//! Rail-selection unit tests for `request_transact` / `request_transact_probe`.
//! The full P256 probe/finalize (which needs the indexer + prover server) is
//! exercised by the suite; here we assert the rail dispatch and error paths, which
//! are pure client logic reached before any RPC call.

use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use solana_keypair::Keypair;
use zolana_client::{ClientError, Rpc};
use zolana_keypair::P256Pubkey;
use zolana_squads_client::{
    PrivateTransactionIntent, RequestTransactRequest, SquadsBackend, SquadsBackendError,
    TransactionType,
};
use zolana_squads_interface::{instruction::instruction_data::EncryptedUtxos, types::Address};

struct MockRpc;
impl Rpc for MockRpc {
    fn get_account(
        &self,
        _address: Address,
    ) -> core::result::Result<Option<solana_account::Account>, ClientError> {
        Ok(None)
    }
}

fn backend() -> SquadsBackend<MockRpc, MockRpc> {
    SquadsBackend::new(
        SecretKey::random(&mut OsRng),
        Keypair::new(),
        Address::default(),
        Address::default(),
        "http://127.0.0.1:3001",
        MockRpc,
        MockRpc,
    )
}

fn empty_intent() -> PrivateTransactionIntent {
    PrivateTransactionIntent {
        sender_viewing_key_account: Address::default(),
        inputs: Vec::new(),
        outputs: Vec::new(),
        encrypted_utxos: EncryptedUtxos {
            tx_viewing_pk: [0u8; 33],
            sender_ciphertext: [0u8; 40],
            recipient_ciphertexts: Vec::new(),
        },
        expiry: 0,
    }
}

fn owner_pubkey() -> [u8; 33] {
    *P256Pubkey::from_p256(&SecretKey::random(&mut OsRng).public_key()).as_bytes()
}

#[test]
fn p256_rail_requires_owner_signature() {
    let request = RequestTransactRequest {
        transaction_type: TransactionType::Withdraw {
            public_amount: 1,
            recipient_account: Address::default(),
        },
        intent: empty_intent(),
        sender_owner_pubkey: Some(owner_pubkey()),
        sender_vault: None,
        owner_signature: None,
    };
    let err = backend().request_transact(request).unwrap_err();
    assert!(matches!(err, SquadsBackendError::Unsupported(_)));
}

#[test]
fn probe_requires_sender_owner_pubkey() {
    let request = RequestTransactRequest {
        transaction_type: TransactionType::Withdraw {
            public_amount: 1,
            recipient_account: Address::default(),
        },
        intent: empty_intent(),
        sender_owner_pubkey: None,
        sender_vault: None,
        owner_signature: None,
    };
    let err = backend().request_transact_probe(&request).unwrap_err();
    assert!(matches!(err, SquadsBackendError::Unsupported(_)));
}

#[test]
fn no_owner_pubkey_selects_smart_account_rail() {
    // With no owner pubkey the smart-account rail runs; it resolves the sender VKA
    // first, so the mock (no accounts) surfaces AccountNotFound -- proving the P256
    // owner-signature bail is no longer hit for the smart-account rail.
    let request = RequestTransactRequest {
        transaction_type: TransactionType::Transfer {
            recipient_viewing_key_account: Address::default(),
        },
        intent: empty_intent(),
        sender_owner_pubkey: None,
        sender_vault: None,
        owner_signature: None,
    };
    let err = backend().request_transact(request).unwrap_err();
    assert!(matches!(err, SquadsBackendError::AccountNotFound(_)));
}
