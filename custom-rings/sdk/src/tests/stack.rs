//! Debug builds keep every value and future a poll builds in its stack frame,
//! and a Poseidon hash needs about 1 MiB of stack on top of the deepest poll.

use std::{
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use custom_ring_interface::{
    MemberRegistryRoot, RingProgramConfig, MEMBER_REGISTRY_EMPTY_ROOT, MEMBER_REGISTRY_ROOT,
    MEMBER_REGISTRY_ROOT_HISTORY, RING_PROGRAM_CONFIG,
};
use solana_account::Account;
use solana_address::Address;
use solana_signature::Signature;
use zolana_api::{HttpClient, HttpFuture, HttpRequest, HttpResponse};
use zolana_client::{
    AsyncProverClient, AsyncRpc, AsyncWitnessReader, AsyncZolanaClient, ClientError,
    GetRingMemberRecordRequest, GetRingMemberRecordResponse, IndexerRpcConfig, InputWitnesses,
    Shape,
};
use zolana_keypair::{ShieldedKeypair, X25519Secret};
use zolana_ring_client::{
    AuditError, RingOrigin, RingRecovery, RingScan, SourceMember, TransactionOrigin,
};
use zolana_ring_member_registry::MemberRegistryTree;
use zolana_ring_policy::Member;
use zolana_ring_policy::{ListId, RuleTable};
use zolana_transaction::{
    instructions::transact::ConfidentialTransaction, utxo::SppProofInputUtxo, AssetRegistry,
    SOL_MINT,
};

use super::support::{account, member, note, pinned, ring, tree_account, Accounts};
use crate::{
    CustomRingMerge, CustomRingTransfer, CustomRingTransferInput, DelegateOutput, DelegateTransfer,
    DelegateTransferInput, DepositAsset, MemberWrite, MergeProofInput, PoolTree, RegisterKey,
    RingDeposit, RingOperation, RingSubmission, UpdateMembers,
};

/// A blocking caller and each Tokio frame under it hold the future by value.
const MAX_FUTURE: usize = 8 * 1024;
/// Below the caller of `block_on`, the deepest poll that reaches a stub.
const MAX_POLL_DEPTH: usize = 384 * 1024;

fn assert_small(name: &str, future: impl Future) {
    let size = size_of_val(&future);
    assert!(size <= MAX_FUTURE, "{name} is a {size} byte future");
}

#[inline(never)]
fn stack_address() -> usize {
    let marker = 0u8;
    std::hint::black_box(&marker) as *const u8 as usize
}

#[derive(Debug)]
struct Depth {
    deepest: AtomicUsize,
    prover_calls: AtomicUsize,
}

impl Depth {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            deepest: AtomicUsize::new(usize::MAX),
            prover_calls: AtomicUsize::new(0),
        })
    }

    fn record(&self) {
        self.deepest.fetch_min(stack_address(), Ordering::Relaxed);
    }
}

/// Serves `accounts`, refuses the blockhash and the input witnesses.
struct Probe {
    accounts: Accounts,
    depth: Arc<Depth>,
}

#[async_trait]
impl AsyncRpc for Probe {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.depth.record();
        self.accounts.get_account(address).await
    }

    async fn get_latest_blockhash(&self) -> Result<(solana_message::Hash, u64), ClientError> {
        self.depth.record();
        Err(ClientError::NoInputs)
    }

    /// Every member is absent from the empty registry.
    async fn get_ring_member_record(
        &self,
        request: GetRingMemberRecordRequest,
    ) -> Result<GetRingMemberRecordResponse, ClientError> {
        self.depth.record();
        let member = Member::from_bytes(request.member.0).map_err(|_| ClientError::NoInputs)?;
        let tree = MemberRegistryTree::new().map_err(|_| ClientError::NoInputs)?;
        Ok(crate::member_registry::tests::response(
            &tree, &member, 0, None,
        ))
    }
}

impl AsyncWitnessReader for Probe {
    async fn input_witnesses(
        &self,
        _inputs: &[&SppProofInputUtxo],
        _dummy_nullifiers: &[[u8; 32]],
        _config: Option<IndexerRpcConfig>,
    ) -> Result<InputWitnesses, ClientError> {
        self.depth.record();
        Err(ClientError::NoInputs)
    }
}

/// The prover answers every request with a failed status, which the client does not retry.
#[derive(Debug)]
struct ProbeHttp(Arc<Depth>);

impl HttpClient for ProbeHttp {
    fn send<'a>(&'a self, _request: HttpRequest) -> HttpFuture<'a> {
        Box::pin(async move {
            self.0.record();
            self.0.prover_calls.fetch_add(1, Ordering::Relaxed);
            Ok(HttpResponse {
                status: http::StatusCode::INTERNAL_SERVER_ERROR,
                headers: http::HeaderMap::new(),
                body: Vec::new(),
            })
        })
    }
}

struct NoOrigin;

impl TransactionOrigin for NoOrigin {
    async fn origin(
        &self,
        _signature: Signature,
        _event_index: u16,
        _ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        Err(AuditError::MissingEventIndex)
    }
}

fn client(accounts: Accounts, depth: &Arc<Depth>) -> AsyncZolanaClient<Probe, Probe> {
    let probe = |accounts| Probe {
        accounts,
        depth: Arc::clone(depth),
    };
    let prover = AsyncProverClient::with_client(
        "http://127.0.0.1:3001".to_string(),
        ProbeHttp(Arc::clone(depth)),
    );
    AsyncZolanaClient::new(probe(accounts), probe(Accounts::default()), prover)
}

/// A policy ring with an empty pinned table over tree 0.
fn policy_ring() -> Accounts {
    let tree = PoolTree::from_id(0);
    let program = ring().program_id();
    let config = RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: Address::new_from_array([3; 32]),
        auditor_pubkey: *X25519Secret::new().pubkey().as_bytes(),
        bump: Address::find_program_address(&[RingProgramConfig::SEED], &program).1,
        has_policy: 1,
        mode: 0,
    };
    let table = RuleTable::builder().build();
    let mut history = [[0; 32]; MEMBER_REGISTRY_ROOT_HISTORY];
    history[0] = MEMBER_REGISTRY_EMPTY_ROOT;
    let registry = MemberRegistryRoot {
        discriminator: MEMBER_REGISTRY_ROOT,
        next_index: 1u64.to_le_bytes(),
        bump: Address::find_program_address(&[MemberRegistryRoot::SEED], &program).1,
        history_cursor: 0,
        history,
    };
    Accounts::default()
        .with(ring().config_pda(), account(program, &config))
        .with(
            ring().member_registry_root_pda(),
            account(program, &registry),
        )
        .with(
            ring().policy_config_pda(),
            account(program, &pinned(ring(), &table, tree)),
        )
        .with(tree.address, tree_account(tree))
}

fn transfer(sender: &ShieldedKeypair) -> CustomRingTransfer<'_> {
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let mut transaction = ConfidentialTransaction::new(
        vec![note(sender, 10, 0, Some(ring().program_id()))],
        solana_signer::Signer::pubkey(sender),
    )
    .unwrap();
    transaction
        .transfer_sol(&recipient.shielded_address().unwrap(), 4)
        .unwrap();
    transaction
        .pad_utxos(Shape::IN2_OUT4, &sender.shielded_address().unwrap())
        .unwrap();
    CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction,
    })
}

fn deposit(payer: &ShieldedKeypair) -> RingDeposit<'_> {
    RingDeposit {
        ring: ring(),
        payer,
        recipient: payer,
        tree: PoolTree::from_id(0).address,
        asset: DepositAsset::Sol,
        amount: 1,
        cosigner: None,
    }
}

/// How far below this frame the deepest stub call was polled, and the output.
fn poll_depth<T>(depth: &Arc<Depth>, operation: impl Future<Output = T>) -> (usize, T) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let top = stack_address();
    let output = runtime.block_on(operation);
    let deepest = depth.deepest.load(Ordering::Relaxed);
    assert_ne!(deepest, usize::MAX, "no stub call was polled");
    (top - deepest, output)
}

#[test]
fn every_operation_future_stays_small() {
    let depth = Depth::new();
    let client = client(Accounts::default(), &depth);
    let keys = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let payer = Address::new_from_array([6; 32]);
    let tree = PoolTree::from_id(0);
    assert_small("CustomRingTransfer::prove", transfer(&keys).prove(&client));
    let delegate = DelegateTransfer::new(DelegateTransferInput {
        ring: ring(),
        delegate: Address::new_from_array([5; 32]),
        payer,
        source_nullifier_key: &keys.nullifier_key,
        inputs: vec![note(&keys, 5, 0, Some(ring().program_id())).into()],
        outputs: vec![DelegateOutput {
            recipient: recipient.shielded_address().unwrap(),
            asset: SOL_MINT,
            amount: 5,
        }],
    });
    assert_small("DelegateTransfer::prove", delegate.prove(&client));
    assert_small("RingDeposit::prepare", deposit(&keys).prepare(&client));
    assert_small("RingDeposit::send", deposit(&keys).send(&client));
    let register = RegisterKey {
        ring: ring(),
        member: &keys,
    };
    assert_small("RegisterKey::prove", register.prove(&client));
    let update = UpdateMembers {
        ring: ring(),
        writes: vec![MemberWrite::add(member(3), ListId::Allow)],
        signers: vec![payer],
    };
    assert_small("UpdateMembers::prove", update.prove(&client));
    let notes = [3, 5].map(|amount| note(&keys, amount, 0, Some(ring().program_id())));
    let merge = CustomRingMerge::new(ring(), notes.into(), None)
        .unwrap()
        .encrypt(&keys)
        .unwrap();
    let input = MergeProofInput {
        nullifier_key: keys.nullifier_key.clone(),
        input_tree: tree.address,
        output_tree: tree.address,
    };
    assert_small(
        "PreparedCustomRingMerge::prove",
        merge.prove(input, &client),
    );
    let mut submission = RingSubmission::new(RingOperation::from(transfer(&keys)));
    assert_small("RingSubmission::send", submission.send(&client, &keys, &[]));
    assert_small(
        "RingSubmission::send_until_settled",
        submission.send_until_settled(&client, &keys, &[]),
    );
    let auditor = X25519Secret::new();
    let indexer = client.indexer();
    let assets = AssetRegistry::default();
    let scan = RingScan::new(ring().program_id(), auditor.pubkey());
    assert_small(
        "RingScan::audit",
        scan.audit(&auditor, indexer, &NoOrigin, &assets),
    );
    let address = keys.shielded_address().unwrap();
    let recovery = RingRecovery::new(ring().program_id(), &auditor).for_member(SourceMember {
        address: &address,
        nullifier_key: &keys.nullifier_key,
    });
    assert_small(
        "MemberRecovery::run",
        recovery.run(indexer, &NoOrigin, &assets),
    );
}

/// Staging, the policy witness and both proof requests poll under the transfer.
#[test]
fn a_policy_transfer_polls_within_a_bounded_stack() {
    let depth = Depth::new();
    let client = client(policy_ring(), &depth);
    let sender = ShieldedKeypair::new_ed25519().unwrap();
    let transfer = transfer(&sender);
    let (polled, result) = poll_depth(&depth, transfer.prove(&client));
    assert!(result.is_err());
    assert!(depth.prover_calls.load(Ordering::Relaxed) > 0);
    assert!(
        polled <= MAX_POLL_DEPTH,
        "a policy transfer polls {polled} bytes deep"
    );
}

/// The submission proves the deposit, then asks for a blockhash.
#[test]
fn a_deposit_submission_polls_within_a_bounded_stack() {
    let depth = Depth::new();
    let client = client(policy_ring(), &depth);
    let payer = ShieldedKeypair::new_ed25519().unwrap();
    let (polled, result) = poll_depth(&depth, deposit(&payer).send(&client));
    assert!(result.is_err());
    assert!(depth.prover_calls.load(Ordering::Relaxed) > 0);
    assert!(
        polled <= MAX_POLL_DEPTH,
        "a deposit submission polls {polled} bytes deep"
    );
}
