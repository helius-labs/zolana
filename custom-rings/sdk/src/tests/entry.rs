//! A child of `entry`, the input slots and the walk bounds are private to it.

use std::sync::Mutex;

use async_trait::async_trait;
use solana_account::Account;
use zolana_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, AsyncProverClient, ClientError, Context,
    GetMerkleProofsResponse, GetNonInclusionProofsResponse, MerkleContext, NonInclusionProof,
    NULLIFIER_TREE_HEIGHT,
};
use zolana_interface::instruction::instruction_data::transact::TransactProof;
use zolana_ring_policy::{EntryState, ListId};

use super::*;
use crate::tests::support::{
    lookup, member, namespace, no_witnesses, ring, slot, transaction, tree, Lineage, NullifierRpc,
};

async fn read(lookup: EntryLookup, rpc: &NullifierRpc) -> Result<Option<LiveEntry>, RingError> {
    ReadEntry::new(
        lookup.address_tree_id,
        namespace(),
        lookup.list_id,
        lookup.member,
    )
    .read(rpc)
    .await
}

#[tokio::test]
async fn an_unclaimed_address_reads_none_after_one_nullifier_request() {
    let lookup = lookup(ListId::Allow, member(1));
    let rpc = NullifierRpc::new(Vec::new());
    assert_eq!(read(lookup, &rpc).await.unwrap(), None);
    assert_eq!(rpc.requests(), vec![vec![lookup.address().unwrap()]]);
}

#[tokio::test]
async fn a_lineage_is_walked_one_version_per_request_across_trees() {
    let lineage = Lineage::across(
        lookup(ListId::Allow, member(1)),
        &[EntryState::Active, EntryState::Cleared, EntryState::Active],
        &[0, 9, 7],
    );
    let mut spenders = lineage.spenders();
    // A slot naming another tree than its leaf hashes under decodes to nothing.
    let mut misplaced = slot(&lineage.versions[1]);
    misplaced.output_context.tree_id = 7;
    spenders[1].output_slots.insert(0, misplaced);
    let rpc = NullifierRpc::new(spenders);
    let live = read(lineage.lookup, &rpc).await.unwrap().unwrap();
    assert_eq!(live, lineage.versions[2]);
    assert_eq!(live.entry.version, 2);
    assert_eq!(live.tree_id, 7);
    assert_eq!(
        rpc.requests(),
        vec![
            vec![lineage.address()],
            vec![lineage.versions[0].nullifier],
            vec![lineage.versions[1].nullifier],
            vec![lineage.versions[2].nullifier],
        ]
    );
}

#[tokio::test]
async fn a_round_follows_the_cursor_across_pages() {
    let first = Lineage::new(lookup(ListId::Allow, member(1)), &[EntryState::Active]);
    let second = Lineage::new(lookup(ListId::Allow, member(2)), &[EntryState::Active]);
    let mut spenders = first.spenders();
    spenders.extend(second.spenders());
    let mut rpc = NullifierRpc::new(spenders);
    rpc.page_size = Some(1);
    let lineages = walk(&rpc, &[first.lookup, second.lookup], None)
        .await
        .unwrap();
    assert_eq!(lineages, vec![first.live(), second.live()]);
    // Two full claim pages end on an empty third, the next round is one empty page.
    assert_eq!(rpc.requests().len(), 4);
}

#[tokio::test]
async fn a_spender_without_a_successor_breaks_the_lineage() {
    let lineage = Lineage::new(
        lookup(ListId::Frozen, member(3)),
        &[EntryState::Active, EntryState::Cleared],
    );
    let mut spenders = lineage.spenders();
    spenders[1].output_slots.clear();
    let rpc = NullifierRpc::new(spenders);
    assert!(matches!(
        read(lineage.lookup, &rpc).await,
        Err(RingError::BrokenLineage {
            list_id: ListId::Frozen,
            version: 1,
            ..
        })
    ));
}

#[test]
fn a_tampered_payload_is_not_decoded() {
    let lineage = Lineage::new(lookup(ListId::Allow, member(4)), &[EntryState::Active]);
    let live = lineage.versions[0];
    let address = lineage.address();
    let genuine = slot(&live);
    let spender = transaction(address, Vec::new());
    let decode = |slot: &OutputSlot| {
        lineage.lookup.decode(
            &address,
            SpentSlot {
                transaction: &spender,
                slot,
            },
        )
    };
    assert_eq!(decode(&genuine), Some(live));
    let mut tampered = genuine.clone();
    // Flipping the state byte breaks the commitment.
    tampered.payload[38] = EntryState::Cleared as u8;
    assert_eq!(decode(&tampered), None);
    let mut wrong_pair = genuine;
    wrong_pair.payload[5] = ListId::Block as u8;
    assert_eq!(decode(&wrong_pair), None);
}

/// A lineage whose slots carry `version || nullifier` in the clear.
struct Synthetic {
    address: [u8; 32],
}

impl LineageLookup for Synthetic {
    type Live = (u64, [u8; 32]);

    fn address(&self) -> Result<[u8; 32], RingError> {
        Ok(self.address)
    }

    fn decode(&self, _address: &[u8; 32], slot: SpentSlot<'_>) -> Option<(u64, [u8; 32])> {
        let payload = &slot.slot.payload;
        Some((
            u64::from_le_bytes(payload.get(..8)?.try_into().ok()?),
            payload.get(8..40)?.try_into().ok()?,
        ))
    }

    fn nullifier(live: &(u64, [u8; 32])) -> [u8; 32] {
        live.1
    }

    fn version(live: &(u64, [u8; 32])) -> u64 {
        live.0
    }

    fn broken(&self, version: u64) -> RingError {
        RingError::BrokenLineage {
            list_id: ListId::Allow,
            member: [0; 32],
            version,
        }
    }
}

const HEAD: [u8; 32] = [0xff; 32];

fn synthetic_nullifier(version: u64) -> [u8; 32] {
    let mut nullifier = [1; 32];
    nullifier[..8].copy_from_slice(&version.to_le_bytes());
    nullifier
}

/// Spends `spent` into a slot carrying `version` and its successor nullifier.
fn synthetic_spender(spent: [u8; 32], version: u64, next: [u8; 32]) -> ShieldedTransaction {
    let mut payload = version.to_le_bytes().to_vec();
    payload.extend_from_slice(&next);
    transaction(
        spent,
        vec![OutputSlot {
            view_tag: [0; 32],
            output_context: zolana_client::OutputContext {
                hash: [0; 32],
                tree_id: 0,
                leaf_index: version,
            },
            payload,
        }],
    )
}

async fn synthetic(
    spenders: Vec<ShieldedTransaction>,
) -> Result<Vec<Option<(u64, [u8; 32])>>, RingError> {
    walk(
        &NullifierRpc::new(spenders),
        &[Synthetic { address: HEAD }],
        None,
    )
    .await
}

#[tokio::test]
async fn a_lineage_that_revisits_a_spent_version_is_a_cycle() {
    let first = synthetic_nullifier(0);
    let to_head = vec![
        synthetic_spender(HEAD, 0, first),
        synthetic_spender(first, 1, HEAD),
    ];
    let to_itself = vec![
        synthetic_spender(HEAD, 0, first),
        synthetic_spender(first, 1, first),
    ];
    for spenders in [to_head, to_itself] {
        assert!(matches!(
            synthetic(spenders).await,
            Err(RingError::LineageCycle)
        ));
    }
    let straight = vec![
        synthetic_spender(HEAD, 0, first),
        synthetic_spender(first, 1, synthetic_nullifier(1)),
    ];
    assert_eq!(
        synthetic(straight).await.unwrap(),
        vec![Some((1, synthetic_nullifier(1)))]
    );
}

#[tokio::test]
async fn a_version_out_of_order_stalls_the_lineage() {
    let first = synthetic_nullifier(0);
    assert!(matches!(
        synthetic(vec![synthetic_spender(HEAD, 1, first)]).await,
        Err(RingError::LineageStalled { version: 0 })
    ));
    assert!(matches!(
        synthetic(vec![
            synthetic_spender(HEAD, 0, first),
            synthetic_spender(first, 0, synthetic_nullifier(1)),
        ])
        .await,
        Err(RingError::LineageStalled { version: 1 })
    ));
}

/// Pages forever, `cursor` names each next page.
struct Pages {
    cursor: fn(usize) -> Vec<u8>,
    requests: Mutex<usize>,
}

#[async_trait]
impl AsyncRpc for Pages {
    async fn get_shielded_transactions_by_nullifiers(
        &self,
        _nullifiers: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        let mut requests = self.requests.lock().unwrap();
        *requests += 1;
        Ok(GetShieldedTransactionsByNullifiersResponse {
            context: Context {
                block_time: 0,
                slot: 0,
            },
            transactions: Vec::new(),
            next_cursor: Some((self.cursor)(*requests)),
            scanned_through: None,
            output_tree_id: None,
        })
    }
}

#[tokio::test]
async fn a_cursor_that_does_not_move_fails_the_round() {
    let rpc = Pages {
        cursor: |_| vec![1],
        requests: Mutex::new(0),
    };
    assert!(matches!(
        walk(&rpc, &[Synthetic { address: HEAD }], None).await,
        Err(RingError::Client(ClientError::IndexerCursorNotAdvanced))
    ));
    assert_eq!(*rpc.requests.lock().unwrap(), 2);
}

#[tokio::test]
async fn a_round_past_its_page_bound_fails() {
    let rpc = Pages {
        cursor: |request| (request as u64).to_le_bytes().to_vec(),
        requests: Mutex::new(0),
    };
    assert!(matches!(
        walk(&rpc, &[Synthetic { address: HEAD }], None).await,
        Err(RingError::LineageBound)
    ));
    assert_eq!(*rpc.requests.lock().unwrap(), MAX_PAGES_PER_ROUND);
}

/// Every nullifier has a spender publishing the next version.
struct Endless {
    rounds: Mutex<usize>,
}

#[async_trait]
impl AsyncRpc for Endless {
    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        _cursor: Option<Vec<u8>>,
        _limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        *self.rounds.lock().unwrap() += 1;
        let spent = nullifiers[0];
        let version = match spent {
            HEAD => 0,
            _ => u64::from_le_bytes(spent[..8].try_into().unwrap()) + 1,
        };
        Ok(GetShieldedTransactionsByNullifiersResponse {
            context: Context {
                block_time: 0,
                slot: 0,
            },
            transactions: vec![synthetic_spender(
                spent,
                version,
                synthetic_nullifier(version),
            )],
            next_cursor: None,
            scanned_through: Some(Vec::new()),
            output_tree_id: None,
        })
    }
}

#[tokio::test]
async fn a_lineage_past_its_version_bound_fails() {
    let rpc = Endless {
        rounds: Mutex::new(0),
    };
    assert!(matches!(
        walk(&rpc, &[Synthetic { address: HEAD }], None).await,
        Err(RingError::LineageBound)
    ));
    assert_eq!(*rpc.rounds.lock().unwrap(), MAX_LINEAGE_VERSIONS);
}

/// Every call fails as unsupported, a test reaching one sees that error.
struct NoRpc;

#[async_trait]
impl AsyncRpc for NoRpc {}

no_witnesses!(NoRpc);

fn client<R, I>(rpc: R, indexer: I) -> AsyncZolanaClient<R, I> {
    AsyncZolanaClient::new(rpc, indexer, AsyncProverClient::local())
}

#[tokio::test]
async fn a_commitment_no_list_content_recovers_is_refused_before_any_call() {
    let refused = CreateEntry {
        ring: ring(),
        payer: Address::new_from_array([1; 32]),
        address_tree: PoolTree::from_id(0),
        output_tree: PoolTree::from_id(0),
        list_id: ListId::Allow,
        member: member(3),
        state: EntryState::Active,
        content_hash: [1; 32],
    }
    .prove(&client(NoRpc, NoRpc))
    .await;
    assert!(matches!(
        refused,
        Err(RingError::InvalidContent(ListId::Allow))
    ));
}

#[tokio::test]
async fn an_update_past_the_last_version_is_refused_before_any_call() {
    let mut spent = Lineage::new(lookup(ListId::Allow, member(1)), &[EntryState::Active])
        .live()
        .unwrap();
    spent.entry.version = u64::MAX;
    let refused = UpdateEntry {
        ring: ring(),
        payer: Address::new_from_array([1; 32]),
        address_tree: PoolTree::from_id(0),
        output_tree: PoolTree::from_id(0),
        spent,
        state: EntryState::Cleared,
        content_hash: [0; 32],
    }
    .prove(&client(NoRpc, NoRpc))
    .await;
    assert!(matches!(refused, Err(RingError::VersionOverflow)));
}

#[test]
fn a_mutation_spends_from_its_input_tree_and_writes_to_its_output_tree() {
    let input_tree = Address::new_from_array([2; 32]);
    let output_tree = Address::new_from_array([4; 32]);
    let nullifier = [9; 32];
    let metas = namespace_write_metas(
        ring(),
        Address::new_from_array([1; 32]),
        input_tree,
        output_tree,
        nullifier,
    );
    assert_eq!(metas[0].pubkey, ring().config_pda());
    assert_eq!(metas[1].pubkey, ring().policy_config_pda());
    assert!(metas[2].is_signer && metas[2].is_writable);
    assert_eq!(metas[3].pubkey, output_tree);
    assert!(metas[3].is_writable);
    assert_eq!(metas[6].pubkey, input_tree);
    assert!(metas[6].is_writable);
    assert_eq!(
        metas[7].pubkey,
        pda::nullifier_pda(&input_tree, &nullifier).0
    );
    assert!(metas[7].is_writable);
    assert_eq!(metas[8].pubkey, ring().namespace_pda());
    assert!(!metas[8].is_signer);
}

#[test]
fn a_proven_write_names_create_or_update_by_its_spent_version() {
    let lineage = Lineage::new(
        lookup(ListId::Allow, member(1)),
        &[EntryState::Active, EntryState::Cleared],
    );
    let proven = |spent: Option<ListEntry>| ProvenEntry {
        ring: ring(),
        payer: Address::new_from_array([1; 32]),
        output_tree: pda::tree(4),
        input_tree: pda::tree(0),
        entry: lineage.versions[1].entry,
        spent,
        proof: EntryProof {
            proof: TransactProof::zeroed(),
            nullifier_tree_root_index: 3,
            utxo_tree_root_index: 4,
            nullifier: [9; 32],
            private_tx_blinding: [5; 32],
        },
    };
    let created = proven(None).instruction().unwrap();
    assert_eq!(created.data[0], tag::CREATE_ENTRY);
    let updated = proven(Some(lineage.versions[0].entry))
        .instruction()
        .unwrap();
    assert_eq!(updated.data[0], tag::UPDATE_ENTRY);
    assert!(updated.data.len() > created.data.len());
    for instruction in [created, updated] {
        assert_eq!(instruction.program_id, ring().program_id());
        assert_eq!(
            instruction.accounts,
            namespace_write_metas(
                ring(),
                Address::new_from_array([1; 32]),
                pda::tree(0),
                pda::tree(4),
                [9; 32],
            )
        );
    }
}

/// Serves one state proof and one non-inclusion proof, both shaped by the test.
struct ProofIndexer {
    state: Option<MerkleProof>,
    absence: NonInclusionProof,
}

#[async_trait]
impl AsyncRpc for ProofIndexer {
    async fn get_merkle_proofs(
        &self,
        _tree_account: Address,
        _leaves: Vec<[u8; 32]>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        Ok(GetMerkleProofsResponse {
            context: Context {
                block_time: 0,
                slot: 0,
            },
            proofs: self.state.iter().cloned().collect(),
        })
    }

    async fn get_non_inclusion_proofs(
        &self,
        _tree_account: Address,
        _leaves: Vec<[u8; 32]>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        Ok(GetNonInclusionProofsResponse {
            context: Context {
                block_time: 0,
                slot: 0,
            },
            proofs: vec![self.absence.clone()],
        })
    }
}

no_witnesses!(ProofIndexer);

fn state_proof(leaf: [u8; 32], tree: Address, height: usize) -> MerkleProof {
    MerkleProof {
        leaf,
        merkle_context: MerkleContext { tree_type: 0, tree },
        path: vec![[0; 32]; height],
        leaf_index: 0,
        root: [3; 32],
        root_seq: 1,
        root_index: 0,
    }
}

fn absence_proof(leaf: [u8; 32], tree: Address, height: usize) -> NonInclusionProof {
    NonInclusionProof {
        leaf,
        merkle_context: MerkleContext { tree_type: 1, tree },
        path: vec![[0; 32]; height],
        low_element: [5; 32],
        low_element_index: 0,
        high_element: [6; 32],
        high_element_index: 1,
        root: [9; 32],
        root_seq: 1,
        root_index: 0,
    }
}

#[tokio::test]
async fn an_update_refuses_a_state_proof_for_another_leaf_tree_or_height() {
    let owner = crate::tests::support::owner();
    let input_tree = PoolTree::from_id(7);
    let data_hash = [2; 32];
    let blinding = [3; 32];
    let leaf = owner
        .leaf_hash(&data_hash, &blinding, input_tree.id)
        .unwrap();
    let spend = |state: Option<MerkleProof>| async move {
        let indexer = ProofIndexer {
            state,
            absence: absence_proof([0; 32], tree(), NULLIFIER_TREE_HEIGHT),
        };
        InputSlot::spend(&indexer, &owner, input_tree, data_hash, blinding)
            .await
            .map(|slot| slot.input_hash)
    };
    assert_eq!(
        spend(Some(state_proof(leaf, tree(), STATE_TREE_HEIGHT)))
            .await
            .unwrap(),
        leaf
    );
    assert!(matches!(
        spend(Some(state_proof([1; 32], tree(), STATE_TREE_HEIGHT))).await,
        Err(RingError::Client(ClientError::StateProofLeafMismatch {
            index: 0
        }))
    ));
    assert!(matches!(
        spend(Some(state_proof(leaf, pda::tree(8), STATE_TREE_HEIGHT))).await,
        Err(RingError::Client(ClientError::StateProofTreeMismatch {
            index: 0
        }))
    ));
    assert!(matches!(
        spend(Some(state_proof(leaf, tree(), STATE_TREE_HEIGHT - 1))).await,
        Err(RingError::Client(ClientError::ProofPathLength { got, expected }))
            if got == STATE_TREE_HEIGHT - 1 && expected == STATE_TREE_HEIGHT
    ));
    assert!(matches!(spend(None).await, Err(RingError::MissingProof)));
}

/// Serves no tree account, a write past the absence checks stops at the tree read.
struct NoTrees;

#[async_trait]
impl AsyncRpc for NoTrees {
    async fn get_account(&self, _address: Address) -> Result<Option<Account>, ClientError> {
        Ok(None)
    }
}

#[tokio::test]
async fn a_claim_refuses_a_non_inclusion_proof_for_another_leaf_tree_or_height() {
    let owner = crate::tests::support::owner();
    let address_tree = PoolTree::from_id(7);
    let address = [4; 32];
    let prove = |absence: NonInclusionProof| async move {
        let client = client(
            NoTrees,
            ProofIndexer {
                state: None,
                absence,
            },
        );
        NamespaceWrite {
            owner: &owner,
            namespace: namespace(),
            input_tree: address_tree,
            output_tree: address_tree,
            payer: Address::new_from_array([1; 32]),
            slot: InputSlot::claim(&owner, [6; 32], address, address_tree.id),
            output_data_hash: [0; 32],
        }
        .prove(&client, |_| Vec::new())
        .await
        .map(|_| ())
    };
    assert!(matches!(
        prove(absence_proof(address, tree(), NULLIFIER_TREE_HEIGHT)).await,
        Err(RingError::MissingTree { address: missing }) if missing == tree()
    ));
    assert!(matches!(
        prove(absence_proof([1; 32], tree(), NULLIFIER_TREE_HEIGHT)).await,
        Err(RingError::Client(ClientError::NullifierProofLeafMismatch {
            index: 0
        }))
    ));
    assert!(matches!(
        prove(absence_proof(address, pda::tree(8), NULLIFIER_TREE_HEIGHT)).await,
        Err(RingError::Client(ClientError::NullifierProofTreeMismatch {
            index: 0
        }))
    ));
    assert!(matches!(
        prove(absence_proof(address, tree(), NULLIFIER_TREE_HEIGHT - 1)).await,
        Err(RingError::Client(ClientError::ProofPathLength { got, expected }))
            if got == NULLIFIER_TREE_HEIGHT - 1 && expected == NULLIFIER_TREE_HEIGHT
    ));
}
