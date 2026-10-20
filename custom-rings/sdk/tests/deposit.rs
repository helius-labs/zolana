use custom_ring_interface::{
    DepositAudit, MemberRegistryRoot, RingProgramConfig, DEPOSIT_AUDIT, MEMBER_REGISTRY_ROOT,
    MEMBER_REGISTRY_ROOT_HISTORY, RING_PROGRAM_CONFIG,
};
use custom_ring_sdk::{CustomRing, DepositAsset, RingDeposit, RingError};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
};

use solana_account::Account;
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::{
    ClientError, ComputeBudgetConfig, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig,
    ProofDataSource, ProverClient, Rpc, WitnessReader, ZolanaClient,
};
use zolana_indexer_api::{
    Context, GetRingMemberRecordRequest, GetRingMemberRecordResponse, Hash, RingLowRecordView,
};
use zolana_keypair::{ShieldedKeypair, X25519Keypair};
use zolana_ring_member_registry::{MemberRegistryTree, Opening};

/// One mock serves both the RPC and the indexer of the client.
fn client<R: Rpc + WitnessReader + Clone + Send + Sync + 'static>(
    rpc: R,
    prover: ProverClient,
) -> ZolanaClient<R, R> {
    ZolanaClient::new(rpc.clone(), rpc, prover)
}

#[derive(Clone)]
struct DepositRpc {
    ring: CustomRing,
    config: Account,
    setting: Option<Account>,
}

impl WitnessReader for DepositRpc {}

impl Rpc for DepositRpc {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        if address == self.ring.config_pda() {
            return Ok(Some(self.config.clone()));
        }
        assert_eq!(address, self.ring.deposit_audit_pda());
        Ok(self.setting.clone())
    }

    /// The recipient's sender stream is free.
    fn get_shielded_transactions_by_tags(
        &self,
        _tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Ok(GetShieldedTransactionsByTagsResponse {
            context: zolana_client::Context {
                block_time: 0,
                slot: 0,
            },
            output_tree_id: None,
            transactions: Vec::new(),
            next_cursor: None,
            scanned_through: None,
        })
    }
}

#[test]
fn deposit_audit_setting_of_zero_does_not_waive_the_proof() {
    let ring = CustomRing::new(Address::new_from_array([42; 32]));
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let config = RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: recipient.pubkey(),
        auditor_pubkey: *X25519Keypair::new().pubkey().as_bytes(),
        bump: Address::find_program_address(&[RingProgramConfig::SEED], &ring.program_id()).1,
        has_policy: 0,
        mode: 0,
    };
    let setting = DepositAudit {
        discriminator: DEPOSIT_AUDIT,
        required: 0,
        bump: Address::find_program_address(&[DepositAudit::SEED], &ring.program_id()).1,
    };
    let inactive = Account {
        data: bytemuck::bytes_of(&setting).to_vec(),
        owner: ring.program_id(),
        ..Account::default()
    };
    for setting in [None, Some(inactive)] {
        let rpc = DepositRpc {
            ring,
            config: Account {
                data: bytemuck::bytes_of(&config).to_vec(),
                owner: ring.program_id(),
                ..Account::default()
            },
            setting,
        };
        let unreachable = ProverClient::new("http://127.0.0.1:1".to_owned());
        let client = client(rpc, unreachable);
        let deposit = RingDeposit {
            ring,
            payer: &recipient,
            recipient: &recipient,
            tree: Address::new_from_array([8; 32]),
            asset: DepositAsset::Sol,
            amount: 11,
            cosigner: None,
        };
        let prepared = client.block_on(deposit.prepare(client.as_async())).unwrap();
        assert_eq!(
            prepared.budget(),
            ComputeBudgetConfig::new(custom_ring_interface::compute_unit_limit(
                custom_ring_interface::InstructionTag::AuditedDeposit
            ))
        );
        assert!(matches!(
            client.block_on(prepared.prove(client.as_async())),
            Err(RingError::Client(_))
        ));
    }
}

#[test]
fn anonymous_deposit_refuses_a_public_recipient_before_building_the_note() {
    let ring = CustomRing::new(Address::new_from_array([42; 32]));
    let payer = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let config = RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: payer.pubkey(),
        auditor_pubkey: *X25519Keypair::new().pubkey().as_bytes(),
        bump: Address::find_program_address(&[RingProgramConfig::SEED], &ring.program_id()).1,
        has_policy: 0,
        mode: custom_ring_interface::RingMode::Anonymous as u8,
    };
    let rpc = DepositRpc {
        ring,
        config: Account {
            data: bytemuck::bytes_of(&config).to_vec(),
            owner: ring.program_id(),
            ..Account::default()
        },
        setting: None,
    };
    let client = client(rpc, ProverClient::new("http://127.0.0.1:1".to_owned()));
    let deposit = RingDeposit {
        ring,
        payer: &recipient,
        recipient: &recipient,
        tree: Address::new_from_array([8; 32]),
        asset: DepositAsset::Sol,
        amount: 11,
        cosigner: None,
    };
    assert!(matches!(
        client.block_on(deposit.prepare(client.as_async())),
        Err(RingError::AnonymousPublicSignerLinksOwner)
    ));
    let deposit = RingDeposit {
        payer: &payer,
        ..deposit
    };
    let prepared = client.block_on(deposit.prepare(client.as_async())).unwrap();
    let mut submission = custom_ring_sdk::RingSubmission::new(prepared);
    assert!(matches!(
        client.block_on(submission.send(client.as_async(), &recipient, &[&payer])),
        Err(RingError::AnonymousPublicSignerLinksOwner)
    ));
    assert_eq!(submission.attempts(), 0);
}

/// Answers config and registry reads, every member is unregistered.
/// An empty registry, every member reads as absent under the sentinel.
#[derive(Clone)]
struct EscrowRpc {
    ring: CustomRing,
    config: Account,
    registry: Option<Account>,
    tree: MemberRegistryTree,
}

impl WitnessReader for EscrowRpc {}

impl Rpc for EscrowRpc {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        if address == self.ring.config_pda() {
            return Ok(Some(self.config.clone()));
        }
        assert_eq!(address, self.ring.member_registry_root_pda());
        Ok(self.registry.clone())
    }

    fn get_ring_member_record(
        &self,
        request: GetRingMemberRecordRequest,
    ) -> Result<GetRingMemberRecordResponse, ClientError> {
        let Opening::Absent {
            low,
            low_index,
            path,
        } = self.tree.opening(&request.member.0).unwrap()
        else {
            panic!("an empty registry");
        };
        Ok(GetRingMemberRecordResponse {
            context: Context::default(),
            root: Hash(self.tree.root()),
            root_index: 0,
            next_index: self.tree.next_index(),
            present: false,
            record: None,
            index: 0,
            path: Vec::new(),
            low: Some(RingLowRecordView {
                member: Hash(low.member),
                next: Hash(low.next),
                lists: low.lists,
                escrow_key: Hash(low.escrow_key),
                index: low_index,
                path: path.into_iter().map(Hash).collect(),
            }),
        })
    }
}

#[test]
fn an_escrowed_ring_refuses_an_unregistered_recipient_from_either_proof_data_source() {
    let ring = CustomRing::new(Address::new_from_array([42; 32]));
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let account = |data: Vec<u8>| Account {
        data,
        owner: ring.program_id(),
        ..Account::default()
    };
    let config = RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: recipient.pubkey(),
        auditor_pubkey: *X25519Keypair::new().pubkey().as_bytes(),
        bump: Address::find_program_address(&[RingProgramConfig::SEED], &ring.program_id()).1,
        has_policy: 1,
        mode: 1,
    };
    let tree = MemberRegistryTree::new().unwrap();
    let mut history = [[0; 32]; MEMBER_REGISTRY_ROOT_HISTORY];
    history[0] = tree.root();
    let registry = MemberRegistryRoot {
        discriminator: MEMBER_REGISTRY_ROOT,
        next_index: 1u64.to_le_bytes(),
        bump: Address::find_program_address(&[MemberRegistryRoot::SEED], &ring.program_id()).1,
        history_cursor: 0,
        history,
    };
    let send = |registry: Option<Account>, prover: ProverClient| {
        let rpc = EscrowRpc {
            ring,
            config: account(bytemuck::bytes_of(&config).to_vec()),
            registry,
            tree: tree.clone(),
        };
        let client = client(rpc, prover);
        let deposit = RingDeposit {
            ring,
            payer: &recipient,
            recipient: &recipient,
            tree: Address::new_from_array([8; 32]),
            asset: DepositAsset::Sol,
            amount: 11,
            cosigner: None,
        };
        client.block_on(async {
            let prepared = deposit.prepare(client.as_async()).await?;
            prepared.prove(client.as_async()).await
        })
    };
    let owner = zolana_ring_policy::Member::owner_tag(recipient.pubkey().as_array()).unwrap();
    let refused = |result: Result<_, RingError>| {
        matches!(
            result,
            Err(RingError::UnregisteredOutputKey { owner: refused }) if refused == owner
        )
    };
    let registry_account = || Some(account(bytemuck::bytes_of(&registry).to_vec()));
    let unreachable = || {
        ProverClient::new("http://127.0.0.1:1".to_owned())
            .with_proof_data_source(ProofDataSource::Client)
    };
    assert!(matches!(
        send(None, unreachable()),
        Err(RingError::MissingMemberRegistry)
    ));
    assert!(refused(send(registry_account(), unreachable())));

    let prover = refusing_prover(owner.as_bytes());
    assert!(refused(send(
        registry_account(),
        ProverClient::new(prover.url.clone())
    )));
    prover.handle.join().unwrap();
}

struct RefusingProver {
    url: String,
    handle: std::thread::JoinHandle<()>,
}

fn refusing_prover(member: &[u8; 32]) -> RefusingProver {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let body = serde_json::json!({
        "code": "registry_member_missing",
        "message": "registry member missing",
        "member": Address::new_from_array(*member).to_string(),
    })
    .to_string();
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
        }
        reader.read_exact(&mut vec![0; length]).unwrap();
        write!(
            reader.get_mut(),
            "HTTP/1.1 422 Unprocessable Entity\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    RefusingProver { url, handle }
}
