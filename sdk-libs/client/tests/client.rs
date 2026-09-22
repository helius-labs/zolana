use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Arc, Mutex},
    thread,
};

use async_trait::async_trait;
use serde_json::{json, Value};
use solana_account::Account;
use solana_address::Address;
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_keypair::Signer;
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use zolana_client::{
    client::{SignedPrivateTransaction, ZolanaClient},
    indexer::{AsyncZolanaIndexer, ZolanaIndexer},
    prover::{
        transact::assemble, witness::WitnessReader, AsyncProverClient, ProofCompressed,
        ProverClient, TransferInput, TransferInputs,
    },
    rpc::{
        compile_message, sign_transaction, AsyncRpc, IndexerPollConfig, IndexerRpcConfig, Rpc,
        SettlementAccountValidation, MAX_LOADED_ACCOUNTS_DATA_SIZE, NULLIFIER_TREE_HEIGHT,
        STATE_TREE_HEIGHT,
    },
    ClientError, ProofAuthority,
};
use zolana_interface::{
    instruction::{
        InterfaceTransfer, Transact, TransactInterfaceTransferAccounts,
        TransactSolTransferAccounts, TransactSplDepositAccounts,
    },
    pda,
};
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{
    instructions::transact::ConfidentialTransaction, utxo::SppProofInputUtxo, Data, Mint, Utxo,
    WalletUtxo,
};

#[test]
fn from_urls_requires_https_off_loopback() {
    // The indexer response is the wallet's UTXO set and the prover request
    // is the witness. In plaintext to a remote host both are readable by
    // anyone on the path, which is the privacy property itself.
    for (indexer, prover) in [
        ("http://indexer.example.com", "https://prover.example.com"),
        ("https://indexer.example.com", "http://prover.example.com"),
    ] {
        assert!(
            matches!(
                ZolanaClient::from_urls((), indexer, prover),
                Err(ClientError::InsecureServiceUrl { .. })
            ),
            "expected {indexer} / {prover} to be rejected"
        );
    }

    assert!(ZolanaClient::from_urls(
        (),
        "https://indexer.example.com",
        "https://prover.example.com",
    )
    .is_ok());
}

#[test]
fn loopback_http_is_allowed_but_lookalikes_are_not() {
    // `127.` prefix matching has to mean the loopback block, not any host
    // whose name merely starts with it.
    for url in [
        "http://127.0.0.1:8784",
        "http://127.1.2.3:8784",
        "http://localhost:8784",
        "http://svc.localhost:8784",
    ] {
        assert!(
            ZolanaClient::from_urls((), url, url).is_ok(),
            "expected {url} to be allowed"
        );
    }
    for url in [
        "http://127.0.0.1.evil.com:8784",
        "http://localhost.evil.com:8784",
        "http://notlocalhost:8784",
    ] {
        assert!(
            ZolanaClient::from_urls((), url, url).is_err(),
            "expected {url} to be rejected"
        );
    }
}

/// The checked constructor refuses these URLs; the escape hatch takes them
/// and builds a client anyway, which is the whole of its contract.
#[test]
fn the_insecure_escape_hatch_is_explicit() {
    let indexer = "http://indexer.internal:8784";
    let prover = "http://prover.internal:3001";
    assert!(matches!(
        ZolanaClient::from_urls((), indexer, prover),
        Err(ClientError::InsecureServiceUrl { .. })
    ));

    let client = ZolanaClient::from_urls_allowing_insecure_http((), indexer, prover);
    assert_eq!(client.indexer().api().base_path(), indexer);
}

#[tokio::test]
async fn from_urls_is_safe_inside_an_async_runtime() {
    let client = ZolanaClient::from_urls((), "http://127.0.0.1:8784", "http://127.0.0.1:3001")
        .expect("loopback http is allowed");

    drop(client);
}

#[test]
fn settlement_accounts_accept_duplicate_sol_recipients_and_mixed_directions() {
    let spl = TransactSplDepositAccounts {
        mint: Pubkey::new_unique(),
        spl_interface: Pubkey::new_unique(),
        token_authority: Pubkey::new_unique(),
        user_token_account: Pubkey::new_unique(),
        token_program: Pubkey::new_unique(),
    };
    let interface_transfers = [
        InterfaceTransfer::SolWithdrawal { amount: 7 },
        InterfaceTransfer::SplDeposit {
            amount: 11,
            spl_interface_bump: 42,
        },
        InterfaceTransfer::SolWithdrawal { amount: 3 },
    ];
    let settlement_transfers = [
        TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
            recipient: Pubkey::new_unique(),
        }),
        TransactInterfaceTransferAccounts::SplDeposit(spl),
        TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
            recipient: Pubkey::new_unique(),
        }),
    ];

    SettlementAccountValidation {
        transfers: &interface_transfers,
        accounts: &settlement_transfers,
    }
    .validate()
    .expect("ordered duplicate-asset account groups are valid");
}

#[test]
fn settlement_accounts_reject_count_and_type_mismatches() {
    let sol_accounts = TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
        recipient: Pubkey::new_unique(),
    });
    assert!(matches!(
        SettlementAccountValidation {
            transfers: &[InterfaceTransfer::SolWithdrawal { amount: 1 }],
            accounts: &[],
        }
        .validate(),
        Err(ClientError::SettlementTransferCountMismatch {
            interface_transfers: 1,
            account_groups: 0,
        })
    ));
    assert!(matches!(
        SettlementAccountValidation {
            transfers: &[InterfaceTransfer::SplWithdrawal {
                amount: 1,
                spl_interface_bump: 42,
            }],
            accounts: &[sol_accounts],
        }
        .validate(),
        Err(ClientError::SettlementTransferTypeMismatch { index: 0 })
    ));
}

#[test]
fn confirm_private_transaction_sync_waits_for_indexer() {
    let payer = Keypair::new();
    let sender = ShieldedKeypair::from_keypair(&payer).expect("sender");
    let funded = funded_utxo(&sender, 10);
    // The proofs must name the account the input's own tree id derives,
    // which is what the reader asks for and what validation checks.
    let tree = pda::tree(funded.tree_id);
    let recipient = Pubkey::new_unique();
    let mut transfer = ConfidentialTransaction::new(vec![funded], payer.pubkey())
        .expect("confidential transaction");
    transfer.withdraw_sol(4, recipient).expect("withdraw");
    let proof_inputs = transfer.encrypt(&sender).expect("encrypt");
    let shielded = SignedPrivateTransaction {
        transaction: proof_inputs,
        settlement_transfers: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts { recipient },
        )],
    };
    let commitment = shielded.transaction.input_utxo_hashes().unwrap().remove(0);
    let signature = Signature::from([5u8; 64]);
    let server = MockIndexerServer::respond_by_path(vec![
        (
            "/getMerkleProofs",
            merkle_response(tree, commitment.utxo_hash),
        ),
        (
            "/getNonInclusionProofs",
            nullifier_response(tree, commitment.nullifier),
        ),
        (
            "/getShieldedTransactionsBySignature",
            indexed_transaction_by_signature_response(signature),
        ),
    ]);
    let rpc = MockSubmitRpc::new(signature);
    let sent = rpc.sent.clone();
    let client = ZolanaClient::new(
        rpc,
        ZolanaIndexer::new(server.url()),
        ProverClient::new("http://unused.invalid".to_string()),
        AsyncZolanaIndexer::new(server.url()),
        AsyncProverClient::new("http://unused.invalid".to_string()),
    )
    .with_compute_unit_price(25_000);

    let blockhash = Hash::default();
    let message = client
        .finish_submission_unsigned_sync_with(&shielded, payer.pubkey(), &sender, blockhash, |_| {
            Ok(ProofCompressed {
                a: [0u8; 32],
                b: [0u8; 128],
                c: [0u8; 32],
                commitment: None,
            })
        })
        .expect("finish");
    let signers: Vec<&dyn Signer> = vec![&payer];
    let transaction = sign_transaction(message, &signers).expect("sign the v1 transaction");
    let result = Rpc::process_transaction(client.rpc(), transaction).expect("send");
    client
        .confirm_private_transaction_sync(result)
        .expect("indexed");

    assert_eq!(result, signature);
    let sent = sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    let sent_message = &sent.first().expect("one transaction was sent").message;
    // v1 carries the compute ceiling and the priority fee in the header, so
    // the transact is the only instruction; under legacy this was three.
    assert!(matches!(sent_message, VersionedMessage::V1(_)));
    assert_eq!(sent_message.instructions().len(), 1);
    let requests = server.requests();
    // The two proof fetches race, so only their membership is defined; the
    // indexed-transaction lookup still happens after them.
    let (proofs, rest) = requests.split_at(2);
    let mut proofs = proofs.to_vec();
    proofs.sort();
    assert_eq!(proofs, ["/getMerkleProofs", "/getNonInclusionProofs"]);
    assert_eq!(rest, ["/getShieldedTransactionsBySignature"]);
}

#[test]
fn submit_validation_binds_fee_payer() {
    struct StopBeforeProving;
    impl ProofAuthority for StopBeforeProving {
        fn complete_inputs(&self, _inputs: &mut [TransferInput]) -> Result<(), ClientError> {
            Err(ClientError::Rpc("test authority reached".into()))
        }
    }

    let payer = Keypair::new();
    let sender = ShieldedKeypair::from_keypair(&payer).expect("sender");
    let funded = funded_utxo(&sender, 10);
    let tree = pda::tree(funded.tree_id);
    let server = MockIndexerServer::respond_by_path(vec![
        ("/getMerkleProofs", merkle_response(tree, funded.utxo_hash)),
        (
            "/getNonInclusionProofs",
            nullifier_response(tree, funded.nullifier),
        ),
    ]);
    let signed = SignedPrivateTransaction {
        transaction: ConfidentialTransaction::new(vec![funded], payer.pubkey())
            .expect("transaction")
            .encrypt(&sender)
            .expect("encrypt"),
        settlement_transfers: Vec::new(),
    };
    let client = ZolanaClient::new(
        MockSubmitRpc::new(Signature::default()),
        ZolanaIndexer::new(server.url()),
        ProverClient::new("http://unused.invalid".to_string()),
        AsyncZolanaIndexer::new(server.url()),
        AsyncProverClient::new("http://unused.invalid".to_string()),
    );

    assert!(matches!(
        client.finish_submission_unsigned_sync(
            &signed,
            Keypair::new().pubkey(),
            &StopBeforeProving
        ),
        Err(ClientError::FeePayerMismatch)
    ));
    assert!(matches!(
        client.finish_submission_unsigned_sync(&signed, payer.pubkey(), &StopBeforeProving),
        Err(ClientError::Rpc(message)) if message == "test authority reached"
    ));
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn spend_proofs_are_bound_to_requested_commitments_and_tree() {
    let payer = Keypair::new();
    let owner = ShieldedKeypair::from_keypair(&payer).expect("owner");
    let input = SppProofInputUtxo::from(funded_utxo(&owner, 10));
    let tree = pda::tree(input.tree_id);
    let load = |state: Value| {
        let server = MockIndexerServer::respond_by_path(vec![
            ("/getMerkleProofs", state),
            (
                "/getNonInclusionProofs",
                nullifier_response(tree, input.nullifier),
            ),
        ]);
        let client = ZolanaClient::new(
            MockSubmitRpc::new(Signature::default()),
            ZolanaIndexer::new(server.url()),
            ProverClient::new("http://unused.invalid".to_string()),
            AsyncZolanaIndexer::new(server.url()),
            AsyncProverClient::new("http://unused.invalid".to_string()),
        );
        let result =
            Rpc::get_input_merkle_proofs(&client, &[&input], Some(IndexerRpcConfig::at_slot(0)));
        assert_eq!(server.requests().len(), 2);
        result
    };
    let proofs = load(merkle_response(tree, input.utxo_hash)).expect("matching proofs");
    assert_eq!(proofs.len(), 1);
    assert!(matches!(
        load(merkle_response(tree, [9u8; 32])),
        Err(ClientError::StateProofLeafMismatch { index: 0 })
    ));
    assert!(matches!(
        load(rpc_result(json!({
            "context": { "blockTime": 10, "slot": 1 }, "proofs": [],
        }))),
        Err(ClientError::IncompleteInputProofs {
            expected: 1,
            state: 0,
            nullifier: 1
        })
    ));
}

/// The ceilings used to ride in front of the transact as compute-budget
/// instructions. In v1 they are header state, so what a client configures
/// has to show up there instead -- and an unset header field is zero, not a
/// default, so both ceilings must be present whether or not a price was set.
#[test]
fn a_client_writes_its_configured_ceilings_into_the_header() {
    let client = |price: Option<u64>| {
        let base = ZolanaClient::new(
            MockSubmitRpc::new(Signature::from([1u8; 64])),
            ZolanaIndexer::new("http://unused.invalid"),
            ProverClient::new("http://unused.invalid".to_string()),
            AsyncZolanaIndexer::new("http://unused.invalid"),
            AsyncProverClient::new("http://unused.invalid".to_string()),
        )
        .with_compute_unit_limit(1_000_000);
        match price {
            Some(price) => base.with_compute_unit_price(price),
            None => base,
        }
    };

    assert_eq!(
        client(None).compute_budget().transaction_config(),
        solana_message::v1::TransactionConfig::empty()
            .with_compute_unit_limit(1_000_000)
            .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE)
    );
    assert_eq!(
        client(Some(25_000)).compute_budget().transaction_config(),
        solana_message::v1::TransactionConfig::empty()
            .with_compute_unit_limit(1_000_000)
            .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE)
            .with_priority_fee(25_000)
    );
}

#[test]
fn confirm_private_transaction_sync_times_out_when_indexer_lags() {
    let signature = Signature::from([9u8; 64]);
    let server = MockIndexerServer::respond_with(vec![rpc_result(json!({
        "context": { "blockTime": 12, "slot": 1 },
        "transactions": [],
    }))]);
    let rpc = MockSubmitRpc::new(signature);
    let client = ZolanaClient::new(
        rpc,
        ZolanaIndexer::new(server.url()),
        ProverClient::new("http://unused.invalid".to_string()),
        AsyncZolanaIndexer::new(server.url()),
        AsyncProverClient::new("http://unused.invalid".to_string()),
    )
    .with_indexer_poll_config(IndexerPollConfig::new(0, 0, 0));
    let error = client
        .confirm_private_transaction_sync(signature)
        .expect_err("empty indexer response should time out");
    let _ = server.requests();

    assert!(matches!(error, ClientError::IndexerTimeout));
}

#[test]
fn confirm_private_transaction_async_polls_until_the_event_is_indexed() {
    let signature = Signature::from([10u8; 64]);
    let server = MockIndexerServer::respond_with(vec![
        rpc_result(json!({
            "context": { "blockTime": 12, "slot": 1 },
            "transactions": [],
        })),
        indexed_transaction_by_signature_response(signature),
    ]);
    let client = ZolanaClient::new(
        MockSubmitRpc::new(signature),
        ZolanaIndexer::new(server.url()),
        ProverClient::new("http://unused.invalid".to_string()),
        AsyncZolanaIndexer::new(server.url()),
        AsyncProverClient::new("http://unused.invalid".to_string()),
    )
    .with_indexer_poll_config(IndexerPollConfig::new(1, 0, 0));

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime
        .block_on(client.confirm_private_transaction(signature))
        .expect("async lookup should poll past an empty response");

    assert_eq!(
        server.requests(),
        [
            "/getShieldedTransactionsBySignature",
            "/getShieldedTransactionsBySignature",
        ]
    );
}

#[test]
fn confirm_private_transaction_sync_retries_transient_indexer_error() {
    let signature = Signature::from([15u8; 64]);
    let server = MockIndexerServer::respond_with(vec![
        rpc_error(-32603, "Internal error"),
        indexed_transaction_by_signature_response(signature),
    ]);
    let client = ZolanaClient::new(
        MockSubmitRpc::new(signature),
        ZolanaIndexer::new(server.url()),
        ProverClient::new("http://unused.invalid".to_string()),
        AsyncZolanaIndexer::new(server.url()),
        AsyncProverClient::new("http://unused.invalid".to_string()),
    )
    .with_indexer_poll_config(IndexerPollConfig::new(1, 0, 0));

    client
        .confirm_private_transaction_sync(signature)
        .expect("retryable indexer error should be retried");

    assert_eq!(
        server.requests(),
        [
            "/getShieldedTransactionsBySignature",
            "/getShieldedTransactionsBySignature",
        ]
    );
}

/// An indexer that fails every attempt has not reported a lag, so reporting
/// `IndexerTimeout` would send the caller looking for a transaction that
/// was never queried successfully.
#[test]
fn confirm_private_transaction_sync_surfaces_the_last_transient_error() {
    let signature = Signature::from([20u8; 64]);
    let server = MockIndexerServer::respond_with(vec![
        rpc_error(-32603, "Internal error"),
        rpc_error(-32603, "Internal error"),
    ]);
    let client = ZolanaClient::new(
        MockSubmitRpc::new(signature),
        ZolanaIndexer::new(server.url()),
        ProverClient::new("http://unused.invalid".to_string()),
        AsyncZolanaIndexer::new(server.url()),
        AsyncProverClient::new("http://unused.invalid".to_string()),
    )
    .with_indexer_poll_config(IndexerPollConfig::new(1, 0, 0));

    let error = client
        .confirm_private_transaction_sync(signature)
        .expect_err("an indexer that never answers must not look like a lag");

    assert_eq!(
        server.requests(),
        [
            "/getShieldedTransactionsBySignature",
            "/getShieldedTransactionsBySignature",
        ]
    );
    let ClientError::PollTimedOut {
        attempts,
        last_error,
    } = error
    else {
        panic!("expected PollTimedOut, got {error:?}");
    };
    assert_eq!(attempts, 2);
    assert!(last_error
        .expect("the last transient error is kept")
        .contains("Internal error"));
}

/// One signature can carry several Rings events, and nothing stops two of
/// them from sharing a view tag. Confirmation only proves the transaction
/// is indexed, so every event of that signature is an acceptable answer.
#[test]
fn confirm_private_transaction_sync_accepts_events_sharing_a_view_tag() {
    let signature = Signature::from([18u8; 64]);
    let server = MockIndexerServer::respond_with(vec![rpc_result(json!({
        "context": { "blockTime": 12, "slot": 1 },
        "transactions": [
            { "eventIndex": 0, "transaction": indexed_transaction_json(signature) },
            { "eventIndex": 1, "transaction": indexed_transaction_json(signature) },
        ],
    }))]);
    let client = ZolanaClient::new(
        MockSubmitRpc::new(signature),
        ZolanaIndexer::new(server.url()),
        ProverClient::new("http://unused.invalid".to_string()),
        AsyncZolanaIndexer::new(server.url()),
        AsyncProverClient::new("http://unused.invalid".to_string()),
    )
    .with_indexer_poll_config(IndexerPollConfig::new(0, 0, 0));

    client
        .confirm_private_transaction_sync(signature)
        .expect("events sharing a view tag are not an error");

    assert_eq!(server.requests(), ["/getShieldedTransactionsBySignature"]);
}

/// Confirmation no longer reads view tags, so the forwarders are the only
/// thing keeping the capability reachable through `ZolanaClient`.
#[test]
fn client_forwards_transact_output_view_tags_to_the_rpc() {
    let signature = Signature::from([21u8; 64]);
    let expected = vec![[7u8; 32], [9u8; 32]];
    let client = ZolanaClient::new(
        MockSubmitRpc::new(signature).with_view_tags(expected.clone()),
        ZolanaIndexer::new("http://unused.invalid"),
        ProverClient::new("http://unused.invalid".to_string()),
        AsyncZolanaIndexer::new("http://unused.invalid"),
        AsyncProverClient::new("http://unused.invalid".to_string()),
    );

    assert_eq!(
        Rpc::transact_output_view_tags_from_signature(&client, signature).expect("sync tags"),
        expected
    );

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    assert_eq!(
        runtime
            .block_on(AsyncRpc::transact_output_view_tags_from_signature(
                &client, signature
            ))
            .expect("async tags"),
        expected
    );
}

fn funded_utxo(keypair: &ShieldedKeypair, amount: u64) -> WalletUtxo {
    let mut blinding = [0u8; 32];
    blinding[1..].fill(7);
    let utxo = Utxo {
        owner: keypair.signing_pubkey(),
        asset: Mint::SOL,
        amount,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    let nullifier_key = &keypair.nullifier_key;
    let nullifier_pubkey = nullifier_key.pubkey().expect("nullifier pubkey");
    let tree_id = 0;
    let hash = utxo
        .hash(&nullifier_pubkey, &[0u8; 32], &[0u8; 32], tree_id)
        .expect("utxo hash");
    let nullifier = utxo.nullifier(&hash, nullifier_key).expect("nullifier");
    WalletUtxo {
        utxo,
        nullifier_pubkey,
        utxo_hash: hash,
        nullifier,
        data_hash: None,
        ring_data_hash: None,
        tree_id,
        leaf_index: 0,
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        slot_index: 0,
    }
}

struct MockSubmitRpc {
    signature: Signature,
    view_tags: Vec<[u8; 32]>,
    sent: Arc<Mutex<Vec<VersionedTransaction>>>,
}

impl MockSubmitRpc {
    fn new(signature: Signature) -> Self {
        Self {
            signature,
            view_tags: Vec::new(),
            sent: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn with_view_tags(mut self, view_tags: Vec<[u8; 32]>) -> Self {
        self.view_tags = view_tags;
        self
    }
}

impl Rpc for MockSubmitRpc {
    fn get_account(&self, _address: Address) -> Result<Option<Account>, ClientError> {
        Ok(None)
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Ok((Hash::new_from_array([4u8; 32]), 100))
    }

    fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        _config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        self.sent.lock().unwrap().push(transaction.clone());
        Ok(self.signature)
    }

    fn process_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        self.sent.lock().unwrap().push(transaction);
        Ok(self.signature)
    }

    fn confirm_transaction(&self, _signature: Signature) -> Result<bool, ClientError> {
        Ok(true)
    }

    fn transact_output_view_tags_from_signature(
        &self,
        _signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        Ok(self.view_tags.clone())
    }
}

#[async_trait]
impl AsyncRpc for MockSubmitRpc {
    async fn confirm_transaction(&self, _signature: Signature) -> Result<bool, ClientError> {
        Ok(true)
    }

    async fn transact_output_view_tags_from_signature(
        &self,
        _signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        Ok(self.view_tags.clone())
    }
}

fn merkle_response(tree: Address, leaf: [u8; 32]) -> Value {
    rpc_result(json!({
        "context": { "blockTime": 10, "slot": 1 },
        "proofs": [{
            "leaf": encode_hash(leaf),
            "merkleContext": {
                "treeType": 0,
                "tree": encode_address(tree),
            },
            "path": vec![encode_hash([0u8; 32]); STATE_TREE_HEIGHT],
            "leafIndex": 0,
            "root": encode_hash([3u8; 32]),
            "rootSeq": 1,
            "rootIndex": 0,
        }],
    }))
}

fn nullifier_response(tree: Address, leaf: [u8; 32]) -> Value {
    rpc_result(json!({
        "context": { "blockTime": 10, "slot": 1 },
        "proofs": [{
            "leaf": encode_hash(leaf),
            "merkleContext": {
                "treeType": 1,
                "tree": encode_address(tree),
            },
            "path": vec![encode_hash([0u8; 32]); NULLIFIER_TREE_HEIGHT],
            "lowElement": encode_hash([0u8; 32]),
            "lowElementIndex": 0,
            "highElement": encode_hash([u8::MAX; 32]),
            "highElementIndex": 1,
            "root": encode_hash([4u8; 32]),
            "rootSeq": 1,
            "rootIndex": 0,
        }],
    }))
}

fn indexed_transaction_json(signature: Signature) -> Value {
    json!({
        "slot": 11,
        "txSignature": signature.to_string(),
        "txViewingPk": null,
        "outputSlots": [{
            "viewTag": encode_hash([0u8; 32]),
            "outputContext": {
                "hash": encode_hash([1u8; 32]),
                "tree": encode_address(pda::tree(0)),
                "treeId": 0,
                "leafIndex": 0,
            },
            "payload": "",
        }],
        "messages": [],
        "nullifiers": [],
        "proofless": false,
    })
}

fn indexed_transaction_by_signature_response(signature: Signature) -> Value {
    rpc_result(json!({
        "context": { "blockTime": 11, "slot": 1 },
        "transactions": [{
            "eventIndex": 0,
            "transaction": indexed_transaction_json(signature),
        }],
    }))
}

fn rpc_result(result: Value) -> Value {
    json!({
        "id": "test-account",
        "jsonrpc": "2.0",
        "result": result,
    })
}

fn rpc_error(code: i64, message: &str) -> Value {
    json!({
        "id": "test-account",
        "jsonrpc": "2.0",
        "error": {
            "code": code,
            "message": message,
        },
    })
}

fn encode_hash(hash: [u8; 32]) -> String {
    bs58::encode(hash).into_string()
}

fn encode_address(address: Address) -> String {
    bs58::encode(address.to_bytes()).into_string()
}

struct MockIndexerServer {
    url: String,
    requests: mpsc::Receiver<MockRequest>,
    handle: thread::JoinHandle<()>,
}

struct MockRequest {
    path: String,
}

impl MockIndexerServer {
    /// Serve each response to the request whose path asks for it.
    ///
    /// `respond_with` hands responses out in order, which stops being a
    /// description of the server once the client fetches concurrently: the
    /// proof fetches race, and whichever connects first would take the
    /// other's body.
    fn respond_by_path(responses: Vec<(&'static str, Value)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock indexer");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (request_tx, requests) = mpsc::channel();
        let count = responses.len();
        let handle = thread::spawn(move || {
            let mut remaining: Vec<(&'static str, Value)> = responses;
            for _ in 0..count {
                let (mut stream, _) = listener.accept().expect("accept request");
                let request = read_request(&mut stream);
                let index = remaining
                    .iter()
                    .position(|(path, _)| *path == request.path)
                    .unwrap_or_else(|| panic!("no mock response for {}", request.path));
                let (_, response) = remaining.remove(index);
                request_tx.send(request).expect("record request");
                write_json_response(&mut stream, &response);
            }
        });
        Self {
            url,
            requests,
            handle,
        }
    }

    fn respond_with(responses: Vec<Value>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock indexer");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (request_tx, requests) = mpsc::channel();
        let handle = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept request");
                request_tx
                    .send(read_request(&mut stream))
                    .expect("record request");
                write_json_response(&mut stream, &response);
            }
        });
        Self {
            url,
            requests,
            handle,
        }
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn requests(self) -> Vec<String> {
        self.handle.join().expect("mock indexer thread");
        self.requests
            .try_iter()
            .map(|request| request.path)
            .collect()
    }
}

fn read_request(stream: &mut TcpStream) -> MockRequest {
    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];
    let mut body_start = None;
    let mut content_length = 0usize;
    loop {
        let read = stream.read(&mut buffer).expect("read request");
        assert_ne!(read, 0, "client closed before sending request");
        data.extend_from_slice(&buffer[..read]);
        if body_start.is_none() {
            if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                body_start = Some(index + 4);
                let headers = String::from_utf8_lossy(&data[..index]);
                content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse().ok())
                    })
                    .unwrap_or(0);
            }
        }
        if let Some(start) = body_start {
            if data.len() >= start + content_length {
                break;
            }
        }
    }
    let start = body_start.expect("request body");
    let headers = String::from_utf8_lossy(&data[..start]);
    let path = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("request path")
        .to_string();
    MockRequest { path }
}

fn write_json_response(stream: &mut TcpStream, response: &Value) {
    let body = response.to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body,
    )
    .expect("write response");
}
trait TestSubmission {
    fn finish_submission_unsigned_sync_with(
        &self,
        signed: &SignedPrivateTransaction,
        fee_payer: Pubkey,
        authority: &dyn ProofAuthority,
        recent_blockhash: Hash,
        prove: impl FnOnce(&TransferInputs) -> Result<ProofCompressed, ClientError>,
    ) -> Result<VersionedMessage, ClientError>;
}

impl<R: Rpc> TestSubmission for ZolanaClient<R> {
    fn finish_submission_unsigned_sync_with(
        &self,
        signed: &SignedPrivateTransaction,
        fee_payer: Pubkey,
        authority: &dyn ProofAuthority,
        recent_blockhash: Hash,
        prove: impl FnOnce(&TransferInputs) -> Result<ProofCompressed, ClientError>,
    ) -> Result<VersionedMessage, ClientError> {
        if signed.transaction.payer != fee_payer {
            return Err(ClientError::FeePayerMismatch);
        }
        let owner_signers = signed.transaction.owner_signer_pubkeys()?;
        let commitments = signed.transaction.input_utxo_hashes()?;
        let witnesses = self.indexer().input_witnesses(
            &commitments,
            &signed.transaction.dummy_nullifiers(),
            None,
        )?;
        let mut assembled = assemble(
            signed.transaction.clone(),
            &witnesses.spend_proofs,
            &witnesses.dummy_nullifier_proofs,
        )?;
        let inputs = &mut assembled.prover_inputs;
        authority.complete_inputs(&mut inputs.inputs)?;
        let proof = prove(&assembled.prover_inputs)?.to_transact_proof();
        let input_trees = assembled
            .input_tree_ids
            .iter()
            .copied()
            .map(pda::tree)
            .collect();
        let data = assembled.with_proof(proof);
        SettlementAccountValidation {
            transfers: &data.interface_transfers,
            accounts: &signed.settlement_transfers,
        }
        .validate()?;
        let instruction = Transact {
            payer: fee_payer,
            input_trees,
            output_tree: pda::tree(signed.transaction.output_tree_id),
            owner_signers,
            interface_transfer_accounts: signed.settlement_transfers.clone(),
            data,
        }
        .instruction();
        compile_message(
            &fee_payer,
            &[instruction],
            recent_blockhash,
            self.compute_budget(),
        )
    }
}
