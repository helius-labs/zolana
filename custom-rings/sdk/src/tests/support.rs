//! The chain and indexer every unit test reads, accounts from one map and the queries recorded.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use bytemuck::{Pod, Zeroable};
use custom_ring_interface::{
    stream::EPOCH_SLOTS, AppliedAt, CoSignScope, EscrowKey, MemberRegistry, QueueEntry,
    RecordQueue, RingMode, RingProgramConfig, SourceSlot, CONFIG_PDA_SEED, DEFAULT_INSERT_FEE,
    MEMBER_REGISTRY_PDA_SEED, N_SOURCE_SLOTS, RECORD_QUEUE_PDA_SEED, RING_PROGRAM_CONFIG,
};
use solana_account::Account;
use solana_address::Address;
use zolana_client::{
    AsyncProverClient, AsyncRpc, AsyncWitnessReader, AsyncZolanaClient, ClientError, Context,
    GetMerkleProofsResponse, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig,
    InputWitnesses, MerkleContext, MerkleProof, ProofDataSource,
};
use zolana_indexer_api::{
    Base64String, GetRingMemberOpeningsRequest, GetRingMemberOpeningsResponse, Hash,
    RingMemberOpening, RingMemberRecordView, RingRecordPathView, RingRegistryRootView,
    SerializablePubkey,
};
use zolana_interface::{
    state::{
        default_tree_fees,
        discriminator::{RING_CONFIG, TREE_ACCOUNT_DISCRIMINATOR},
        nullifier_tree_params, RingConfig,
    },
    RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{random_blinding, NullifierKey, ShieldedKeypair, SigningKey, X25519Keypair};
use zolana_ring_member_registry::{MemberRecord, MemberRegistryTree, RecordOpening, RecordTree};
use zolana_ring_policy::{Member, RuleTable};
use zolana_transaction::{
    instructions::transact::ShieldedTransaction, utxo::SppProofInputUtxo, Data, Mint, Utxo,
    WalletUtxo,
};
use zolana_tree::TreeAccount;

use crate::{trees::PoolTree, CustomRing};

pub(crate) const SLOT: u64 = 9 * EPOCH_SLOTS + 5;
pub(crate) const TREE_ID: u16 = 0;

pub(crate) fn program() -> Address {
    Address::new_from_array([42; 32])
}

pub(crate) fn ring() -> CustomRing {
    CustomRing::new(program())
}

pub(crate) fn payer() -> Address {
    Address::new_from_array([7; 32])
}

pub(crate) fn authority() -> Address {
    Address::new_from_array([8; 32])
}

pub(crate) fn auditor() -> X25519Keypair {
    X25519Keypair::from_bytes(&[5; 32])
}

pub(crate) fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

pub(crate) fn owner_identity(owner: &ShieldedKeypair) -> Member {
    let identity = owner
        .shielded_address()
        .unwrap()
        .signing_pubkey
        .owner_proof_input_hash()
        .unwrap();
    Member::from_bytes(identity).unwrap()
}

pub(crate) fn wallet(utxo: Utxo, key: &NullifierKey, tree_id: u16, leaf_index: u64) -> WalletUtxo {
    let nullifier_pubkey = key.pubkey().unwrap();
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id)
        .unwrap();
    WalletUtxo {
        nullifier: key.nullifier(&utxo_hash, &utxo.blinding).unwrap(),
        utxo,
        nullifier_pubkey,
        utxo_hash,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id,
        leaf_index,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Default::default(),
        slot_index: 0,
    }
}

pub(crate) fn ring_utxo(
    owner: &ShieldedKeypair,
    asset: Mint,
    amount: u64,
    leaf: u64,
) -> WalletUtxo {
    wallet(
        Utxo {
            owner: owner.signing_pubkey(),
            asset,
            amount,
            blinding: random_blinding(),
            ring_program_id: Some(program()),
            data: Data::default(),
        },
        &owner.nullifier_key,
        TREE_ID,
        leaf,
    )
}

pub(crate) fn account<T: Pod>(owner: Address, value: &T) -> Account {
    Account {
        lamports: 1,
        data: bytemuck::bytes_of(value).to_vec(),
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

pub(crate) fn empty(owner: Address) -> Account {
    Account {
        lamports: 1,
        data: Vec::new(),
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

fn tree_account(tree: PoolTree) -> Account {
    let mut data = vec![0u8; TreeAccount::account_size()];
    let params = nullifier_tree_params();
    TreeAccount::init(
        &mut data,
        TREE_ACCOUNT_DISCRIMINATOR,
        32,
        tree.address.to_bytes(),
        tree.id,
        params,
        default_tree_fees(params.input_queue_zkp_batch_size).unwrap(),
    )
    .unwrap();
    Account {
        lamports: 1,
        data,
        owner: Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        executable: false,
        rent_epoch: 0,
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RingSettings {
    pub mode: RingMode,
    pub has_policy: bool,
    pub co_signer: Option<(Address, CoSignScope)>,
    pub delegate: Option<Address>,
    pub created_slot: u64,
}

impl RingSettings {
    pub(crate) const fn new(mode: RingMode) -> Self {
        Self {
            mode,
            has_policy: false,
            co_signer: None,
            delegate: None,
            created_slot: 0,
        }
    }

    pub(crate) fn config(&self) -> RingProgramConfig {
        let mut config = RingProgramConfig::zeroed();
        config.discriminator = RING_PROGRAM_CONFIG;
        config.authority = authority();
        config.auditor_pubkey = *auditor().pubkey().as_bytes();
        config.bump = Address::find_program_address(&[CONFIG_PDA_SEED], &program()).1;
        config.has_policy = u8::from(self.has_policy);
        config.mode = self.mode as u8;
        config.insert_fee = DEFAULT_INSERT_FEE.to_le_bytes();
        config.created_slot = self.created_slot.to_le_bytes();
        if let Some((signer, scope)) = self.co_signer {
            config.co_signer = signer;
            config.co_sign_scope = scope.bits();
        }
        if let Some(delegate) = self.delegate {
            config.delegate = delegate;
        }
        config
    }
}

/// Clones share the query log.
#[derive(Clone, Default)]
pub(crate) struct Chain {
    accounts: HashMap<Address, Account>,
    /// Outputs occupying stream tags.
    transactions: Vec<ShieldedTransaction>,
    /// Leaf indexes a Merkle proof request may name.
    leaves: HashMap<[u8; 32], u64>,
    registry: Option<Arc<Registry>>,
    /// A root the indexer serves in place of the tree's newest.
    served_root: Option<[u8; 32]>,
    /// The leaves of every Merkle proof request.
    pub proof_requests: Arc<Mutex<Vec<Vec<[u8; 32]>>>>,
}

impl Chain {
    pub(crate) fn ring(settings: RingSettings) -> Self {
        let registration = RingConfig {
            discriminator: RING_CONFIG,
            authority: authority(),
            program_id: program(),
            ring_authority_transact_is_enabled: 1,
            paused: 0,
            activated: 1,
            bump: Address::find_program_address(&[RING_AUTH_PDA_SEED], &program()).1,
        };
        Self::default()
            .with(ring().config_pda(), account(program(), &settings.config()))
            .with(
                ring().ring_auth_pda(),
                account(
                    Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
                    &registration,
                ),
            )
            .with_tree(TREE_ID)
    }

    pub(crate) fn with(mut self, address: Address, account: Account) -> Self {
        self.accounts.insert(address, account);
        self
    }

    pub(crate) fn with_tree(self, id: u16) -> Self {
        let tree = PoolTree {
            address: zolana_interface::pda::tree(id),
            id,
        };
        self.with(tree.address, tree_account(tree))
    }

    pub(crate) fn with_leaf(mut self, hash: [u8; 32], leaf_index: u64) -> Self {
        self.leaves.insert(hash, leaf_index);
        self
    }

    pub(crate) fn with_served_root(mut self, root: [u8; 32]) -> Self {
        self.served_root = Some(root);
        self
    }

    pub(crate) fn with_transaction(mut self, transaction: ShieldedTransaction) -> Self {
        self.transactions.push(transaction);
        self
    }

    /// The ring's own registry pinning `rules`, every list read from it.
    pub(crate) fn with_registry(self, registry: Registry, rules: &RuleTable) -> Self {
        let account = registry.account(rules);
        Self {
            registry: Some(Arc::new(registry)),
            ..self
        }
        .with(ring().registry_pda(), account)
    }

    pub(crate) fn with_queue(
        self,
        entries: &[QueueEntry],
        queued_at: u64,
        next_apply_slot: u64,
    ) -> Self {
        let bump = Address::find_program_address(&[RECORD_QUEUE_PDA_SEED], &program()).1;
        let mut queue = RecordQueue::new(bump);
        for entry in entries {
            queue.push(entry, queued_at).unwrap();
        }
        queue.next_apply_slot = next_apply_slot.to_le_bytes();
        self.with(ring().queue_pda(), account(program(), &queue))
    }

    /// The indexed route, the prover fetches the input proofs and no witness is read here.
    pub(crate) fn client(self) -> AsyncZolanaClient<Chain, Chain> {
        AsyncZolanaClient::new(
            self.clone(),
            self,
            AsyncProverClient::local().with_proof_data_source(ProofDataSource::Prover),
        )
    }
}

const CONTEXT: Context = Context {
    block_time: 0,
    slot: SLOT,
};

#[async_trait]
impl AsyncRpc for Chain {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        Ok(self.accounts.get(&address).cloned())
    }

    async fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        Ok(addresses
            .iter()
            .map(|address| self.accounts.get(address).cloned())
            .collect())
    }

    async fn get_slot(&self) -> Result<u64, ClientError> {
        Ok(SLOT)
    }

    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Ok(GetShieldedTransactionsByTagsResponse {
            context: CONTEXT,
            output_tree_id: Some(TREE_ID),
            transactions: self
                .transactions
                .iter()
                .filter(|tx| {
                    tx.output_slots
                        .iter()
                        .any(|slot| tags.contains(&slot.view_tag))
                })
                .cloned()
                .collect(),
            next_cursor: None,
            scanned_through: None,
        })
    }

    async fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        self.proof_requests.lock().unwrap().push(leaves.clone());
        let mut data = self.accounts[&tree_account].data.clone();
        let mut tree = TreeAccount::from_bytes(&mut data, tree_account.to_bytes()).unwrap();
        let newest = tree.utxo_tree();
        let (root, root_index) = (newest.root(), newest.current_root_index());
        let proofs = leaves
            .iter()
            .map(|leaf| MerkleProof {
                leaf: *leaf,
                merkle_context: MerkleContext {
                    tree_type: 0,
                    tree: tree_account,
                },
                path: vec![[3; 32]; 32],
                leaf_index: self.leaves.get(leaf).copied().unwrap_or_default(),
                root: self.served_root.unwrap_or(root),
                root_seq: SLOT,
                root_index,
            })
            .collect();
        Ok(GetMerkleProofsResponse {
            context: CONTEXT,
            proofs,
        })
    }

    async fn get_ring_member_openings(
        &self,
        request: GetRingMemberOpeningsRequest,
    ) -> Result<GetRingMemberOpeningsResponse, ClientError> {
        let registry = self
            .registry
            .as_ref()
            .ok_or(ClientError::UnsupportedRpcMethod(
                "get_ring_member_openings",
            ))?;
        Ok(GetRingMemberOpeningsResponse {
            context: zolana_indexer_api::Context {
                block_time: 0,
                slot: SLOT,
            },
            root: RingRegistryRootView {
                root: Hash(registry.root()),
                root_index: 1,
                applied: 0,
                next_index: registry.tree.records().len() as u64,
            },
            openings: request
                .members
                .iter()
                .map(|member| registry.opening(&member.0))
                .collect(),
        })
    }
}

impl AsyncWitnessReader for Chain {
    fn input_witnesses(
        &self,
        _inputs: &[&SppProofInputUtxo],
        _dummy_nullifiers: &[[u8; 32]],
        _config: Option<IndexerRpcConfig>,
    ) -> impl std::future::Future<Output = Result<InputWitnesses, ClientError>> + Send {
        std::future::ready(Err(ClientError::NoInputs))
    }
}

/// The ring's own record tree, every member escrowing its nullifier key.
pub(crate) struct Registry {
    tree: MemberRegistryTree,
    views: HashMap<[u8; 32], RingMemberRecordView>,
}

impl Registry {
    /// Each owner with `lists` set, ordered as the linked records require.
    pub(crate) fn new(owners: &[(&ShieldedKeypair, u64)]) -> Self {
        let sealed = [0x5a; 32];
        let mut members: Vec<_> = owners
            .iter()
            .map(|(owner, lists)| {
                let address = owner.shielded_address().unwrap();
                let member = address.signing_pubkey.owner_proof_input_hash().unwrap();
                let escrow_key = EscrowKey {
                    nullifier_pk: &address.nullifier_pubkey,
                    ciphertext: &sealed,
                }
                .hash()
                .unwrap();
                let view = RingMemberRecordView {
                    member: Hash(member),
                    next: Hash([0; 32]),
                    lists: *lists,
                    escrow_key: Hash(escrow_key),
                    owner_pubkey: Some(SerializablePubkey(Address::new_from_array(
                        address.signing_pubkey.as_ed25519().unwrap(),
                    ))),
                    nullifier_pk: Some(Hash(address.nullifier_pubkey)),
                    eph_pk: Some(Base64String(auditor().pubkey().as_bytes().to_vec())),
                    ciphertext: Some(Base64String(sealed.to_vec())),
                };
                (member, view)
            })
            .collect();
        members.sort_by_key(|(member, _)| *member);
        let mut records = vec![MemberRecord {
            next: members
                .first()
                .map_or(MemberRecord::SENTINEL.next, |(member, _)| *member),
            ..MemberRecord::SENTINEL
        }];
        let mut views = HashMap::new();
        for (position, (member, mut view)) in members.iter().cloned().enumerate() {
            let next = members
                .get(position + 1)
                .map_or(MemberRecord::SENTINEL.next, |(next, _)| *next);
            view.next = Hash(next);
            records.push(MemberRecord {
                member,
                next,
                lists: view.lists,
                escrow_key: view.escrow_key.0,
            });
            views.insert(member, view);
        }
        Self {
            tree: MemberRegistryTree::from_records(records).unwrap(),
            views,
        }
    }

    pub(crate) fn root(&self) -> [u8; 32] {
        self.tree.root().unwrap()
    }

    fn account(&self, rules: &RuleTable) -> Account {
        let bump = Address::find_program_address(&[MEMBER_REGISTRY_PDA_SEED], &program()).1;
        let mut registry = MemberRegistry::new(bump, SLOT);
        registry.push_root(
            self.root(),
            AppliedAt {
                applied: 0,
                slot: SLOT,
            },
        );
        let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
        for list in rules.referenced().iter() {
            sources[list.slot()].list_id = list as u8;
        }
        registry.set_policy(sources, rules.encode(), SLOT).unwrap();
        account(program(), &registry)
    }

    fn opening(&self, member: &[u8; 32]) -> RingMemberOpening {
        let opening = self.tree.opening(member).unwrap();
        let (present, record, path) = match opening {
            RecordOpening::Present { record, path } => (true, record, path),
            RecordOpening::Absent { low, path } => (false, low, path),
        };
        let view = match present {
            true => self.views[member].clone(),
            false => RingMemberRecordView {
                member: Hash(record.member),
                next: Hash(record.next),
                lists: record.lists,
                escrow_key: Hash(record.escrow_key),
                owner_pubkey: None,
                nullifier_pk: None,
                eph_pk: None,
                ciphertext: None,
            },
        };
        RingMemberOpening {
            present,
            record: view,
            path: RingRecordPathView {
                index: path.index,
                siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
            },
        }
    }
}
