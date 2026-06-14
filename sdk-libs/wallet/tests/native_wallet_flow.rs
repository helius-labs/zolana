use std::sync::{Arc, Mutex};

use zolana_client::testing::MockHost;
use zolana_client::WalletError;
use zolana_client::{
    ApprovalRequest, CreatePrivateWalletInput, DecryptionMode, DeriveViewTagsRequest,
    GetPrivateTransactionsInput, HeliusPrivacyInterface, P256Signature, PrivateTransferRoute,
    SendPrivateTransferInput, ShieldedPublicKey, TransactionDirection, ViewTag,
};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::{P256Pubkey, ShieldedKeypair};
use zolana_transaction::{Address, SOL_MINT};
use zolana_wallet_demo::{DemoWallet, DemoWalletEnvironment};

fn owner(seed: u8) -> Address {
    Address::new_from_array([seed; 32])
}

struct RecordingHost {
    inner: MockHost,
    create_calls: Arc<Mutex<usize>>,
    ecdh_calls: Arc<Mutex<usize>>,
    read_calls: Arc<Mutex<usize>>,
    write_calls: Arc<Mutex<usize>>,
    derive_calls: Arc<Mutex<usize>>,
    sign_calls: Arc<Mutex<usize>>,
    approvals: Arc<Mutex<Vec<ApprovalRequest>>>,
}

impl HeliusPrivacyInterface for RecordingHost {
    fn create_p256_keypair(
        &mut self,
        wallet_id: zolana_client::PrivateWalletId,
    ) -> zolana_client::Result<ShieldedPublicKey> {
        *self.create_calls.lock().unwrap() += 1;
        self.inner.create_p256_keypair(wallet_id)
    }

    fn get_shielded_public_key(
        &self,
        wallet_id: zolana_client::PrivateWalletId,
    ) -> zolana_client::Result<ShieldedPublicKey> {
        self.inner.get_shielded_public_key(wallet_id)
    }

    fn sign_p256(
        &self,
        wallet_id: zolana_client::PrivateWalletId,
        message: &[u8],
    ) -> zolana_client::Result<P256Signature> {
        *self.sign_calls.lock().unwrap() += 1;
        self.inner.sign_p256(wallet_id, message)
    }

    fn ecdh_p256(
        &self,
        wallet_id: zolana_client::PrivateWalletId,
        public_key: &P256Pubkey,
    ) -> zolana_client::Result<[u8; 32]> {
        *self.ecdh_calls.lock().unwrap() += 1;
        self.inner.ecdh_p256(wallet_id, public_key)
    }

    fn derive_nullifier(
        &self,
        wallet_id: zolana_client::PrivateWalletId,
        utxo_hash: &[u8; 32],
        blinding: &[u8; BLINDING_LEN],
    ) -> zolana_client::Result<[u8; 32]> {
        self.inner.derive_nullifier(wallet_id, utxo_hash, blinding)
    }

    fn derive_view_tags(
        &self,
        wallet_id: zolana_client::PrivateWalletId,
        request: DeriveViewTagsRequest,
    ) -> zolana_client::Result<Vec<ViewTag>> {
        *self.derive_calls.lock().unwrap() += 1;
        self.inner.derive_view_tags(wallet_id, request)
    }

    fn read_state(
        &self,
        wallet_id: zolana_client::PrivateWalletId,
    ) -> zolana_client::Result<Option<Vec<u8>>> {
        *self.read_calls.lock().unwrap() += 1;
        self.inner.read_state(wallet_id)
    }

    fn write_state(
        &mut self,
        wallet_id: zolana_client::PrivateWalletId,
        encrypted_state: Vec<u8>,
    ) -> zolana_client::Result<()> {
        *self.write_calls.lock().unwrap() += 1;
        self.inner.write_state(wallet_id, encrypted_state)
    }

    fn request_user_approval(&self, request: &ApprovalRequest) -> zolana_client::Result<()> {
        self.approvals.lock().unwrap().push(request.clone());
        Ok(())
    }
}

#[tokio::test]
async fn create_private_wallet_and_read_empty_balances() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment).unwrap();

    let wallet = alice.create_private_wallet().await.unwrap();
    let balances = alice.get_private_token_balances().await.unwrap();

    assert_eq!(wallet.inbox, alice.owner());
    assert!(balances.balances.is_empty());
}

#[tokio::test]
async fn mock_airdrop_syncs_to_private_balance_once() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment).unwrap();
    alice.create_private_wallet().await.unwrap();

    alice.mock_airdrop(SOL_MINT, 100).await.unwrap();
    let first = alice.sync_private_wallet().await.unwrap();
    let second = alice.sync_private_wallet().await.unwrap();

    assert_eq!(first.stored_utxos, 1);
    assert_eq!(second.stored_utxos, 0);
    assert_eq!(alice.private_balance(SOL_MINT).await.unwrap(), 100);
}

#[tokio::test]
async fn private_transfer_to_registered_recipient_updates_both_wallets() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment.clone()).unwrap();
    let mut bob = DemoWallet::new("bob", environment).unwrap();
    alice.create_private_wallet().await.unwrap();
    bob.create_private_wallet().await.unwrap();

    alice.mock_airdrop(SOL_MINT, 100).await.unwrap();
    alice.sync_private_wallet().await.unwrap();

    let result = alice
        .send_private_transfer(bob.owner(), SOL_MINT, 25)
        .await
        .unwrap();
    alice.sync_private_wallet().await.unwrap();
    bob.sync_private_wallet().await.unwrap();

    assert_eq!(result.route, PrivateTransferRoute::PrivateTransfer);
    assert_eq!(alice.private_balance(SOL_MINT).await.unwrap(), 75);
    assert_eq!(bob.private_balance(SOL_MINT).await.unwrap(), 25);

    let alice_history = alice.get_private_transactions(10).await.unwrap();
    let bob_history = bob.get_private_transactions(10).await.unwrap();
    assert_eq!(alice_history[0].direction, TransactionDirection::Outbound);
    assert_eq!(bob_history[0].direction, TransactionDirection::Inbound);
}

#[tokio::test]
async fn prod_native_consumer_uses_client_without_exposed_keypairs() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment.clone()).unwrap();
    let mut bob = DemoWallet::new("bob", environment).unwrap();
    let alice_wallet = alice.create_private_wallet().await.unwrap();
    let bob_wallet = bob.create_private_wallet().await.unwrap();

    alice.mock_airdrop(SOL_MINT, 40).await.unwrap();
    alice.sync_private_wallet().await.unwrap();
    alice
        .send_private_transfer(bob.owner(), SOL_MINT, 15)
        .await
        .unwrap();
    alice.sync_private_wallet().await.unwrap();
    bob.sync_private_wallet().await.unwrap();

    assert_eq!(alice_wallet.inbox, alice.owner());
    assert_eq!(bob_wallet.inbox, bob.owner());
    assert_eq!(alice.private_balance(SOL_MINT).await.unwrap(), 25);
    assert_eq!(bob.private_balance(SOL_MINT).await.unwrap(), 15);
}

#[tokio::test]
async fn prod_native_host_create_and_approval_hooks_are_used() {
    let environment = DemoWalletEnvironment::new();
    let create_calls = Arc::new(Mutex::new(0usize));
    let ecdh_calls = Arc::new(Mutex::new(0usize));
    let read_calls = Arc::new(Mutex::new(0usize));
    let write_calls = Arc::new(Mutex::new(0usize));
    let derive_calls = Arc::new(Mutex::new(0usize));
    let sign_calls = Arc::new(Mutex::new(0usize));
    let approvals = Arc::new(Mutex::new(Vec::new()));
    let alice_owner = owner(3);
    let host = RecordingHost {
        inner: MockHost::new(ShieldedKeypair::new().unwrap()).unwrap(),
        create_calls: create_calls.clone(),
        ecdh_calls: ecdh_calls.clone(),
        read_calls: read_calls.clone(),
        write_calls: write_calls.clone(),
        derive_calls: derive_calls.clone(),
        sign_calls: sign_calls.clone(),
        approvals: approvals.clone(),
    };
    let client = environment.client_with_host(alice_owner, host);
    let mut alice = DemoWallet::from_client(alice_owner, client).unwrap();
    let mut bob = DemoWallet::new("bob", environment).unwrap();

    assert_eq!(*create_calls.lock().unwrap(), 0);
    let alice_wallet = alice.create_private_wallet().await.unwrap();
    bob.create_private_wallet().await.unwrap();
    assert_eq!(*create_calls.lock().unwrap(), 1);
    assert_eq!(*write_calls.lock().unwrap(), 1);

    alice.mock_airdrop(SOL_MINT, 40).await.unwrap();
    alice.sync_private_wallet().await.unwrap();
    alice
        .send_private_transfer(bob.owner(), SOL_MINT, 15)
        .await
        .unwrap();

    assert_eq!(*read_calls.lock().unwrap(), 1);
    assert!(*derive_calls.lock().unwrap() > 0);
    assert!(*ecdh_calls.lock().unwrap() > 0);
    assert_eq!(*write_calls.lock().unwrap(), 2);
    assert_eq!(*sign_calls.lock().unwrap(), 1);
    let approvals = approvals.lock().unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].private_wallet_id, alice_wallet.id);
    assert_eq!(approvals[0].recipient, bob.owner());
    assert_eq!(approvals[0].amount, 15);
}

#[tokio::test]
async fn test_consumer_can_pass_generated_keypairs_to_client() {
    let environment = DemoWalletEnvironment::new();
    let alice_owner = owner(1);
    let bob_owner = owner(2);
    let mut alice = environment
        .test_client(alice_owner, ShieldedKeypair::new().unwrap())
        .unwrap();
    let mut bob = environment
        .test_client(bob_owner, ShieldedKeypair::new().unwrap())
        .unwrap();
    let alice_wallet = alice
        .create_private_wallet(CreatePrivateWalletInput {
            inbox: alice_owner,
            label: None,
            decryption_mode: DecryptionMode::Local,
        })
        .await
        .unwrap();
    let bob_wallet = bob
        .create_private_wallet(CreatePrivateWalletInput {
            inbox: bob_owner,
            label: None,
            decryption_mode: DecryptionMode::Local,
        })
        .await
        .unwrap();

    alice
        .mock_airdrop(alice_wallet.id, SOL_MINT, 70)
        .await
        .unwrap();
    alice.sync_private_wallet(alice_wallet.id).await.unwrap();
    alice
        .send_private_transfer(SendPrivateTransferInput {
            private_wallet_id: alice_wallet.id,
            recipient: bob_owner,
            mint: SOL_MINT,
            amount: 30,
        })
        .await
        .unwrap();
    alice.sync_private_wallet(alice_wallet.id).await.unwrap();
    bob.sync_private_wallet(bob_wallet.id).await.unwrap();

    let alice_balance = alice
        .get_private_token_balances(alice_wallet.id)
        .await
        .unwrap();
    let bob_balance = bob.get_private_token_balances(bob_wallet.id).await.unwrap();
    assert_eq!(alice_balance.balances[0].amount, 40);
    assert_eq!(bob_balance.balances[0].amount, 30);
}

#[tokio::test]
async fn private_transfer_can_spend_multiple_notes() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment.clone()).unwrap();
    let mut bob = DemoWallet::new("bob", environment).unwrap();
    alice.create_private_wallet().await.unwrap();
    bob.create_private_wallet().await.unwrap();

    alice.mock_airdrop(SOL_MINT, 60).await.unwrap();
    alice.mock_airdrop(SOL_MINT, 50).await.unwrap();
    alice.sync_private_wallet().await.unwrap();

    alice
        .send_private_transfer(bob.owner(), SOL_MINT, 100)
        .await
        .unwrap();
    alice.sync_private_wallet().await.unwrap();
    bob.sync_private_wallet().await.unwrap();

    assert_eq!(alice.private_balance(SOL_MINT).await.unwrap(), 10);
    assert_eq!(bob.private_balance(SOL_MINT).await.unwrap(), 100);
}

#[tokio::test]
async fn private_transfer_rejects_reusing_pending_spend_before_sync() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment.clone()).unwrap();
    let mut bob = DemoWallet::new("bob", environment).unwrap();
    alice.create_private_wallet().await.unwrap();
    bob.create_private_wallet().await.unwrap();

    alice.mock_airdrop(SOL_MINT, 100).await.unwrap();
    alice.sync_private_wallet().await.unwrap();
    alice
        .send_private_transfer(bob.owner(), SOL_MINT, 25)
        .await
        .unwrap();

    let err = alice
        .send_private_transfer(bob.owner(), SOL_MINT, 25)
        .await
        .unwrap_err();

    assert!(matches!(err, WalletError::InsufficientPrivateBalance));
}

#[tokio::test]
async fn private_transfer_rejects_unregistered_recipient() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment).unwrap();
    let bob = DemoWallet::new("bob", DemoWalletEnvironment::new()).unwrap();
    alice.create_private_wallet().await.unwrap();
    alice.mock_airdrop(SOL_MINT, 100).await.unwrap();
    alice.sync_private_wallet().await.unwrap();

    let err = alice
        .send_private_transfer(bob.owner(), SOL_MINT, 25)
        .await
        .unwrap_err();

    assert!(matches!(err, WalletError::RecipientPrivateWalletNotFound));
}

#[tokio::test]
async fn private_transfer_rejects_insufficient_balance() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment.clone()).unwrap();
    let mut bob = DemoWallet::new("bob", environment).unwrap();
    alice.create_private_wallet().await.unwrap();
    bob.create_private_wallet().await.unwrap();

    let err = alice
        .send_private_transfer(bob.owner(), SOL_MINT, 1)
        .await
        .unwrap_err();

    assert!(matches!(err, WalletError::InsufficientPrivateBalance));
}

#[tokio::test]
async fn deposit_instruction_is_explicitly_unsupported() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment).unwrap();
    alice.create_private_wallet().await.unwrap();

    let err = alice
        .get_deposit_instruction(alice.owner(), SOL_MINT, 9, 100)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        WalletError::Unsupported("deposit instruction")
    ));
}

#[tokio::test]
async fn delegated_mode_round_trips_metadata() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment).unwrap();
    alice.create_private_wallet().await.unwrap();
    let provider = DemoWallet::new("provider", DemoWalletEnvironment::new())
        .unwrap()
        .owner();

    let wallet = alice
        .set_decryption_mode(DecryptionMode::Delegated {
            provider,
            expires_at: None,
        })
        .await
        .unwrap();

    assert_eq!(
        wallet.decryption_mode,
        DecryptionMode::Delegated {
            provider,
            expires_at: None
        }
    );
}

#[tokio::test]
async fn create_private_wallet_rejects_duplicate_registration() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment).unwrap();
    alice.create_private_wallet().await.unwrap();

    let err = alice.create_private_wallet().await.unwrap_err();

    assert!(matches!(err, WalletError::PrivateWalletAlreadyCreated));
}

#[tokio::test]
async fn create_private_wallet_rejects_duplicate_inbox_across_clients() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment.clone()).unwrap();
    alice.create_private_wallet().await.unwrap();
    let mut duplicate = DemoWallet::with_owner(alice.owner(), environment).unwrap();

    let err = duplicate.create_private_wallet().await.unwrap_err();

    assert!(matches!(err, WalletError::InboxAlreadyRegistered));
}

#[tokio::test]
async fn privacy_client_rejects_inbox_owner_mismatch() {
    let environment = DemoWalletEnvironment::new();
    let victim_inbox = DemoWallet::new("victim", DemoWalletEnvironment::new())
        .unwrap()
        .owner();
    let attacker_owner = DemoWallet::new("attacker", DemoWalletEnvironment::new())
        .unwrap()
        .owner();
    let mut client = environment.native_client(attacker_owner).unwrap();

    let err = client
        .create_private_wallet(CreatePrivateWalletInput {
            inbox: victim_inbox,
            label: None,
            decryption_mode: DecryptionMode::Local,
        })
        .await
        .unwrap_err();

    assert!(matches!(err, WalletError::InboxOwnerMismatch));
}

#[tokio::test]
async fn privacy_client_rejects_cross_wallet_history_reads() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment.clone()).unwrap();
    alice.create_private_wallet().await.unwrap();
    alice.mock_airdrop(SOL_MINT, 100).await.unwrap();
    let alice_id = alice.private_wallet_id().unwrap();
    let attacker_owner = DemoWallet::new("attacker", DemoWalletEnvironment::new())
        .unwrap()
        .owner();
    let client = environment.native_client(attacker_owner).unwrap();

    let err = client
        .get_private_transactions(alice_id, GetPrivateTransactionsInput { limit: 10 })
        .await
        .unwrap_err();

    assert!(matches!(err, WalletError::PrivateWalletNotFound));
}

#[tokio::test]
async fn mock_airdrop_rejects_zero_amount() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment).unwrap();
    alice.create_private_wallet().await.unwrap();

    let err = alice.mock_airdrop(SOL_MINT, 0).await.unwrap_err();

    assert!(matches!(err, WalletError::InvalidAmount));
}

#[tokio::test]
async fn private_transfer_rejects_zero_amount() {
    let environment = DemoWalletEnvironment::new();
    let mut alice = DemoWallet::new("alice", environment.clone()).unwrap();
    let mut bob = DemoWallet::new("bob", environment).unwrap();
    alice.create_private_wallet().await.unwrap();
    bob.create_private_wallet().await.unwrap();
    alice.mock_airdrop(SOL_MINT, 100).await.unwrap();
    alice.sync_private_wallet().await.unwrap();

    let err = alice
        .send_private_transfer(bob.owner(), SOL_MINT, 0)
        .await
        .unwrap_err();

    assert!(matches!(err, WalletError::InvalidAmount));
}
