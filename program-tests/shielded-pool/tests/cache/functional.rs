use shielded_pool_tests::support::{
    fixtures::Pool,
    merge::{ring_cache_identity, RealMergeProof, RealRingMergeProof},
    transact::{proof_env, tree_progress},
};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    prover::{MergeCacheTarget, MergeRingCacheTarget},
    ComputeBudgetConfig,
};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::{merge_transact::MERGE_DEFAULT_INPUT_COUNT, CreateCacheData},
        CreateCache,
    },
    pda,
    state::{
        cache::{CacheAccount, CACHE_CAPACITY},
        discriminator::CACHE,
    },
};
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::{test_blinding, Rejection, ZolanaProgramTest};

const MERGE_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

struct CacheFixture {
    address: Pubkey,
    bump: u8,
    owner_identity: [u8; 32],
    tree_id: u16,
    expires_at: i64,
    rent_sponsor: Pubkey,
}

impl CacheFixture {
    fn account(&self, commitments: [[u8; 32]; CACHE_CAPACITY]) -> CacheAccount {
        CacheAccount {
            discriminator: CACHE,
            bump: self.bump,
            frozen: 0,
            tree_id: self.tree_id.to_le_bytes(),
            expires_at: self.expires_at.to_le_bytes(),
            owner_identity: self.owner_identity,
            rent_sponsor: self.rent_sponsor.to_bytes(),
            commitments,
        }
    }

    fn empty(&self) -> CacheAccount {
        self.account([[0u8; 32]; CACHE_CAPACITY])
    }

    fn holding(&self, slot: u8, commitment: [u8; 32]) -> CacheAccount {
        let mut commitments = [[0u8; 32]; CACHE_CAPACITY];
        *commitments
            .get_mut(usize::from(slot))
            .expect("cache slot within capacity") = commitment;
        self.account(commitments)
    }
}

fn now(rpc: &ZolanaProgramTest) -> i64 {
    rpc.svm.get_sysvar::<solana_clock::Clock>().unix_timestamp
}

fn cache_state(rpc: &ZolanaProgramTest, cache: &Pubkey) -> CacheAccount {
    *bytemuck::from_bytes(&rpc.account_data(cache).expect("cache data"))
}

fn rebind_cache_owner(pool: &mut Pool, cache: &Pubkey, owner_identity: [u8; 32]) {
    let mut state = cache_state(&pool.rpc, cache);
    state.owner_identity = owner_identity;
    let mut account = pool.rpc.svm.get_account(cache).expect("cache account");
    account.data = bytemuck::bytes_of(&state).to_vec();
    pool.rpc
        .svm
        .set_account(*cache, account)
        .expect("rebind the cache owner identity");
}

fn create_cache(
    pool: &mut Pool,
    owner_identity: [u8; 32],
    nonce: u64,
    tree_id: u16,
) -> CacheFixture {
    let rent_sponsor = pool.rpc.payer.pubkey();
    let expires_at = now(&pool.rpc) + 1_000;
    let builder = CreateCache {
        payer: rent_sponsor,
        data: CreateCacheData {
            owner_identity,
            nonce,
            tree_id,
            expires_at,
        },
    };
    let (address, bump) = pda::cache(&rent_sponsor, nonce);
    pool.rpc
        .create_and_send_default_payer_transaction(&[builder.instruction()], &[])
        .expect("create the cache");
    CacheFixture {
        address,
        bump,
        owner_identity,
        tree_id,
        expires_at,
        rent_sponsor,
    }
}

fn owner_identity_of(pool: &Pool) -> [u8; 32] {
    solana_owner_identity(&pool.rpc.payer.pubkey().to_bytes()).expect("owner identity")
}

fn shielded_keypair(pool: &Pool) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(&pool.rpc.payer.insecure_clone()).expect("shielded keypair")
}

fn send_merge(pool: &mut Pool, ix: Instruction, expectation: &str) {
    pool.rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &[],
            ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
        )
        .unwrap_or_else(|error| panic!("{expectation}: {error:?}"));
}

fn expect_rejection(pool: &mut Pool, ix: Instruction, error: ShieldedPoolError) {
    let failure = pool
        .rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &[],
            ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
        )
        .expect_err("the merge must be rejected");
    Rejection::pool(error).assert_litesvm(failure);
}

#[test]
fn merge_writes_the_bound_slot() {
    const SLOT: u8 = 5;
    let mut pool = proof_env();
    let tree = pool.tree;
    let tree_id = pool.tree_id;
    let owner_identity = owner_identity_of(&pool);
    let cache = create_cache(&mut pool, owner_identity, 1, tree_id);

    let merge = RealMergeProof {
        input_count: MERGE_DEFAULT_INPUT_COUNT,
        real_input_count: 1,
    }
    .build_cached(
        &mut pool,
        MergeCacheTarget {
            address: cache.address,
            slot: SLOT,
        },
    );
    let ix = merge.instruction(&pool);

    let (utxo_next_before, nullifier_next_before) = tree_progress(&pool.rpc, &tree);
    send_merge(&mut pool, ix, "cached merge with a valid proof");

    assert_eq!(
        cache_state(&pool.rpc, &cache.address),
        cache.holding(SLOT, merge.data.output_utxo_hash)
    );
    assert_eq!(
        tree_progress(&pool.rpc, &tree),
        (
            utxo_next_before + 1,
            nullifier_next_before + MERGE_DEFAULT_INPUT_COUNT as u64
        ),
        "a cached merge still appends its output and queues one nullifier per input"
    );
}

#[test]
fn confidential_merge_cannot_write_a_cache_bound_to_another_identity() {
    const SLOT: u8 = 0;
    let mut pool = proof_env();
    let tree_id = pool.tree_id;
    let stranger = Keypair::new();
    let owner_identity =
        solana_owner_identity(&stranger.pubkey().to_bytes()).expect("stranger identity");
    let cache = create_cache(&mut pool, owner_identity, 1, tree_id);

    let merge = RealMergeProof {
        input_count: MERGE_DEFAULT_INPUT_COUNT,
        real_input_count: 1,
    }
    .build_cached(
        &mut pool,
        MergeCacheTarget {
            address: cache.address,
            slot: SLOT,
        },
    );
    let ix = merge.instruction(&pool);

    expect_rejection(&mut pool, ix, ShieldedPoolError::CacheOwnerMismatch);
    assert_eq!(cache_state(&pool.rpc, &cache.address), cache.empty());
}

#[test]
fn merge_rejects_a_cache_for_another_tree() {
    const SLOT: u8 = 2;
    let mut pool = proof_env();
    let other_tree_id = pool.tree_id.checked_add(1).expect("a second tree id");
    let owner_identity = owner_identity_of(&pool);
    let cache = create_cache(&mut pool, owner_identity, 1, other_tree_id);

    let merge = RealMergeProof {
        input_count: MERGE_DEFAULT_INPUT_COUNT,
        real_input_count: 1,
    }
    .build_cached(
        &mut pool,
        MergeCacheTarget {
            address: cache.address,
            slot: SLOT,
        },
    );
    let ix = merge.instruction(&pool);

    expect_rejection(&mut pool, ix, ShieldedPoolError::CacheTreeMismatch);
    assert_eq!(cache_state(&pool.rpc, &cache.address), cache.empty());
}

#[test]
fn ring_merge_writes_the_bound_slot() {
    const SLOT: u8 = 3;
    let mut pool = proof_env();
    let tree = pool.tree;
    let tree_id = pool.tree_id;
    let operation_id = test_blinding(21);
    let owner_identity = ring_cache_identity(&shielded_keypair(&pool), &operation_id);
    let cache = create_cache(&mut pool, owner_identity, 1, tree_id);

    let merge = RealRingMergeProof {
        input_count: MERGE_DEFAULT_INPUT_COUNT,
        real_input_count: 1,
    }
    .build_cached(
        &mut pool,
        MergeRingCacheTarget {
            address: cache.address,
            slot: SLOT,
            operation_id,
        },
    );
    let ix = merge.instruction(&pool);

    let (utxo_next_before, nullifier_next_before) = tree_progress(&pool.rpc, &tree);
    send_merge(&mut pool, ix, "cached ring merge with a valid proof");

    assert_eq!(
        cache_state(&pool.rpc, &cache.address),
        cache.holding(SLOT, merge.data.merge.output_utxo_hash)
    );
    assert_eq!(
        tree_progress(&pool.rpc, &tree),
        (
            utxo_next_before + 1,
            nullifier_next_before + MERGE_DEFAULT_INPUT_COUNT as u64
        ),
        "a cached ring merge still appends its output and queues one nullifier per input"
    );
}

#[test]
fn ring_merge_cannot_write_another_users_cache_on_the_same_ring() {
    const SLOT: u8 = 1;
    let mut pool = proof_env();
    let tree_id = pool.tree_id;
    let operation_id = test_blinding(22);
    let stranger =
        ShieldedKeypair::from_keypair(&Keypair::new()).expect("a second user of the same ring");
    let owner_identity = ring_cache_identity(&stranger, &operation_id);
    let mut cache = create_cache(&mut pool, owner_identity, 1, tree_id);

    let merge = RealRingMergeProof {
        input_count: MERGE_DEFAULT_INPUT_COUNT,
        real_input_count: 1,
    }
    .build_cached(
        &mut pool,
        MergeRingCacheTarget {
            address: cache.address,
            slot: SLOT,
            operation_id,
        },
    );
    let ix = merge.instruction(&pool);

    expect_rejection(
        &mut pool,
        ix.clone(),
        ShieldedPoolError::TransactProofVerificationFailed,
    );
    assert_eq!(cache_state(&pool.rpc, &cache.address), cache.empty());

    let merger_identity = ring_cache_identity(&shielded_keypair(&pool), &operation_id);
    rebind_cache_owner(&mut pool, &cache.address, merger_identity);
    cache.owner_identity = merger_identity;
    send_merge(
        &mut pool,
        ix,
        "the same ring merge against a cache bound to the merging user",
    );
    assert_eq!(
        cache_state(&pool.rpc, &cache.address),
        cache.holding(SLOT, merge.data.merge.output_utxo_hash),
        "only the cache's bound identity separates the rejection from acceptance"
    );
}

#[test]
fn plain_ring_merge_without_a_cache_still_verifies() {
    let mut pool = proof_env();
    let tree = pool.tree;

    let merge = RealRingMergeProof {
        input_count: MERGE_DEFAULT_INPUT_COUNT,
        real_input_count: 1,
    }
    .build(&mut pool);
    assert_eq!(
        merge.data.merge.cache_slot, None,
        "a plain ring merge carries no cache slot"
    );
    let ix = merge.instruction(&pool);

    let (utxo_next_before, nullifier_next_before) = tree_progress(&pool.rpc, &tree);
    send_merge(&mut pool, ix, "plain ring merge with a valid proof");

    assert_eq!(
        tree_progress(&pool.rpc, &tree),
        (
            utxo_next_before + 1,
            nullifier_next_before + MERGE_DEFAULT_INPUT_COUNT as u64
        ),
        "a ring merge without a cache appends its output and queues one nullifier per input"
    );
}

#[test]
fn cross_rail_caches_are_mutually_unwritable() {
    const SLOT: u8 = 4;
    let operation_id = test_blinding(23);

    let mut confidential = proof_env();
    let tree_id = confidential.tree_id;
    let ring_identity = ring_cache_identity(&shielded_keypair(&confidential), &operation_id);
    let ring_cache = create_cache(&mut confidential, ring_identity, 1, tree_id);
    let merge = RealMergeProof {
        input_count: MERGE_DEFAULT_INPUT_COUNT,
        real_input_count: 1,
    }
    .build_cached(
        &mut confidential,
        MergeCacheTarget {
            address: ring_cache.address,
            slot: SLOT,
        },
    );
    let ix = merge.instruction(&confidential);
    expect_rejection(&mut confidential, ix, ShieldedPoolError::CacheOwnerMismatch);
    assert_eq!(
        cache_state(&confidential.rpc, &ring_cache.address),
        ring_cache.empty()
    );

    let mut ring = proof_env();
    let ring_tree_id = ring.tree_id;
    let confidential_identity = owner_identity_of(&ring);
    let mut confidential_cache = create_cache(&mut ring, confidential_identity, 1, ring_tree_id);
    let ring_merge = RealRingMergeProof {
        input_count: MERGE_DEFAULT_INPUT_COUNT,
        real_input_count: 1,
    }
    .build_cached(
        &mut ring,
        MergeRingCacheTarget {
            address: confidential_cache.address,
            slot: SLOT,
            operation_id,
        },
    );
    let ring_ix = ring_merge.instruction(&ring);
    expect_rejection(
        &mut ring,
        ring_ix.clone(),
        ShieldedPoolError::TransactProofVerificationFailed,
    );
    assert_eq!(
        cache_state(&ring.rpc, &confidential_cache.address),
        confidential_cache.empty()
    );

    let ring_merger_identity = ring_cache_identity(&shielded_keypair(&ring), &operation_id);
    rebind_cache_owner(&mut ring, &confidential_cache.address, ring_merger_identity);
    confidential_cache.owner_identity = ring_merger_identity;
    send_merge(
        &mut ring,
        ring_ix,
        "the same ring merge against a ring-bound cache",
    );
    assert_eq!(
        cache_state(&ring.rpc, &confidential_cache.address),
        confidential_cache.holding(SLOT, ring_merge.data.merge.output_utxo_hash),
        "only the cache's bound identity separates the rejection from acceptance"
    );
}
