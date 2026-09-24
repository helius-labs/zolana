use borsh::{BorshDeserialize, BorshSerialize};
use shielded_pool_tests::support::{
    cache::CachedSpendFixture,
    fixtures::Pool,
    merge::{RealMergeProof, RealRingMergeProof},
    transact::{proof_env, tree_progress},
};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{prover::MergeCacheTarget, ComputeBudgetConfig};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::{
        merge_transact::MERGE_DEFAULT_INPUT_COUNT,
        transact::{TransactIxData, NO_UTXO_ROOT},
        CreateCacheData,
    },
    pda,
    state::{
        cache::{CacheAccount, CACHE_CAPACITY},
        discriminator::CACHE,
    },
};
use zolana_program::instruction::CreateCache;
use zolana_program_test::{test_blinding, Rejection, ZolanaProgramTest};
use zolana_tree::TreeAccount;
use zolana_user_registry_interface::state::UserRecord;

const MERGE_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

struct CacheFixture {
    address: Pubkey,
    bump: u8,
    tree_id: u16,
    expires_at: i64,
    rent_sponsor: Keypair,
    write_authority: Pubkey,
}

impl CacheFixture {
    fn account(&self, utxo_hashes: [[u8; 32]; CACHE_CAPACITY]) -> CacheAccount {
        CacheAccount {
            discriminator: CACHE,
            bump: self.bump,
            tree_id: self.tree_id.to_le_bytes(),
            expires_at: self.expires_at.to_le_bytes(),
            rent_sponsor: self.rent_sponsor.pubkey(),
            write_authority: self.write_authority,
            utxo_hashes,
        }
    }

    fn empty(&self) -> CacheAccount {
        self.account([[0u8; 32]; CACHE_CAPACITY])
    }

    fn holding(&self, slot: u8, utxo_hash: [u8; 32]) -> CacheAccount {
        let mut utxo_hashes = [[0u8; 32]; CACHE_CAPACITY];
        *utxo_hashes
            .get_mut(usize::from(slot))
            .expect("cache slot within capacity") = utxo_hash;
        self.account(utxo_hashes)
    }
}

fn now(rpc: &ZolanaProgramTest) -> i64 {
    rpc.svm.get_sysvar::<solana_clock::Clock>().unix_timestamp
}

fn cache_state(rpc: &ZolanaProgramTest, cache: &Pubkey) -> CacheAccount {
    *bytemuck::from_bytes(&rpc.account_data(cache).expect("cache data"))
}

fn create_cache(pool: &mut Pool, nonce: u64, tree_id: u16) -> CacheFixture {
    let rent_sponsor = Keypair::new();
    pool.rpc
        .airdrop(&rent_sponsor.pubkey(), 1_000_000_000)
        .expect("fund rent sponsor");
    let write_authority = pool.rpc.payer.pubkey();
    let expires_at = now(&pool.rpc) + 1_000;
    let builder = CreateCache {
        payer: rent_sponsor.pubkey(),
        data: CreateCacheData {
            write_authority,
            nonce,
            tree_id,
            expires_at,
        },
    };
    let (address, bump) = pda::cache(&rent_sponsor.pubkey(), nonce);
    pool.rpc
        .create_and_send_default_payer_transaction(&[builder.instruction()], &[&rent_sponsor])
        .expect("create the cache");
    CacheFixture {
        address,
        bump,
        tree_id,
        expires_at,
        rent_sponsor,
        write_authority,
    }
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
    let cache = create_cache(&mut pool, 1, tree_id);

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

    reject_cache_sponsor_write(&mut pool, &cache, ix.clone());

    let record_account = pool
        .rpc
        .svm
        .get_account(&merge.user_record)
        .expect("user record");
    let mut mismatched_record = record_account.clone();
    let mut record =
        UserRecord::deserialize(&mut record_account.data.get(1..).expect("record payload"))
            .expect("decode user record");
    record.nullifier_pubkey = test_blinding(99);
    mismatched_record.data = vec![UserRecord::DISCRIMINATOR];
    record
        .serialize(&mut mismatched_record.data)
        .expect("encode user record");
    mismatched_record.data.resize(UserRecord::SIZE, 0);
    pool.rpc
        .svm
        .set_account(merge.user_record, mismatched_record)
        .expect("replace registry key");
    let tree_before = pool.rpc.svm.get_account(&tree).expect("tree account");
    expect_rejection(
        &mut pool,
        ix.clone(),
        ShieldedPoolError::TransactProofVerificationFailed,
    );
    assert_eq!(cache_state(&pool.rpc, &cache.address), cache.empty());
    assert_eq!(
        pool.rpc.svm.get_account(&tree).expect("tree account"),
        tree_before
    );
    for nullifier in &merge.nullifiers {
        assert!(pool
            .rpc
            .svm
            .get_account(&pda::nullifier_pda(&tree, nullifier).0)
            .is_none());
    }
    pool.rpc
        .svm
        .set_account(merge.user_record, record_account)
        .expect("restore registry key");

    let (utxo_next_before, nullifier_next_before) = tree_progress(&pool.rpc, &tree);
    store_cache(
        &mut pool.rpc,
        cache.address,
        cache.holding(SLOT, zolana_test_utils::transact::fe(99)),
    );
    send_merge_with_independent_payer(&mut pool, &cache, ix, 2);

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
fn merge_rejects_a_cache_for_another_tree() {
    const SLOT: u8 = 2;
    let mut pool = proof_env();
    let other_tree_id = pool.tree_id.checked_add(1).expect("a second tree id");
    let cache = create_cache(&mut pool, 1, other_tree_id);

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
    let cache = create_cache(&mut pool, 1, tree_id);

    let merge = RealRingMergeProof {
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

    reject_cache_sponsor_write(&mut pool, &cache, ix.clone());

    let (utxo_next_before, nullifier_next_before) = tree_progress(&pool.rpc, &tree);
    store_cache(
        &mut pool.rpc,
        cache.address,
        cache.holding(SLOT, zolana_test_utils::transact::fe(99)),
    );
    send_merge_with_independent_payer(&mut pool, &cache, ix, 3);

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

fn send_merge_with_independent_payer(
    pool: &mut Pool,
    cache: &CacheFixture,
    mut ix: Instruction,
    payer_index: usize,
) {
    ix.accounts.get_mut(payer_index).expect("payer").pubkey = cache.rent_sponsor.pubkey();
    assert_eq!(
        ix.accounts.last().expect("writer").pubkey,
        cache.write_authority
    );
    pool.rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &[&cache.rent_sponsor],
            ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
        )
        .expect("distinct payer and writer authorize overwriting an occupied slot");
}

// The rent sponsor cannot write. Both rails subsequently accept the same
// proof with the independent write authority in its trailing signer account.
fn reject_cache_sponsor_write(pool: &mut Pool, cache: &CacheFixture, mut ix: Instruction) {
    let sponsor = &cache.rent_sponsor;
    // Replace both the fee payer and the explicit writer with the sponsor.
    // The normal writer is deliberately absent from the signers.
    for account in ix
        .accounts
        .iter_mut()
        .filter(|meta| meta.is_signer && meta.pubkey == cache.write_authority)
    {
        account.pubkey = sponsor.pubkey();
    }
    let accounts_before: Vec<_> = ix
        .accounts
        .iter()
        .filter(|meta| meta.is_writable && meta.pubkey != sponsor.pubkey())
        .map(|meta| (meta.pubkey, pool.rpc.svm.get_account(&meta.pubkey)))
        .collect();
    let failure = pool
        .rpc
        .create_and_send_transaction_with_budget(
            &[ix],
            &sponsor.pubkey(),
            &[sponsor],
            ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
        )
        .expect_err("rent sponsor cannot authorize cache writes");
    Rejection::pool(ShieldedPoolError::CacheWriteAuthorityMismatch).assert_litesvm(failure);
    for (address, before) in accounts_before {
        assert_eq!(
            pool.rpc.svm.get_account(&address),
            before,
            "unchanged account {address}"
        );
    }
}

#[test]
fn ring_merge_without_a_cache_verifies() {
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

/// The cache stands in for state inclusion, and nothing else: the spend proves
/// ownership and nullifier non-inclusion as usual, publishes no UTXO root, and
/// leaves the cache unchanged for subsequent reads and writes.
#[test]
fn transact_spends_cached_commitments_without_mutating_the_cache() {
    let mut pool = proof_env();
    let tree = pool.tree;
    let tree_id = pool.tree_id;

    let spend = CachedSpendFixture::all_cached(2, 2, 9).build(&mut pool.rpc, tree, tree_id);

    assert!(
        !spend
            .instruction
            .accounts
            .last()
            .expect("read-only cache")
            .is_writable
    );
    let data = TransactIxData::deserialize(spend.instruction.data.get(1..).expect("body"))
        .expect("decode the cached transact");
    assert_eq!(
        data.tree_contexts
            .iter()
            .map(|context| context.utxo_tree_root_index)
            .collect::<Vec<_>>(),
        vec![NO_UTXO_ROOT]
    );
    let mut tree_data = pool.rpc.account_data(&tree).expect("tree account");
    assert!(
        TreeAccount::from_bytes(&mut tree_data, tree.to_bytes())
            .expect("load tree")
            .get_utxo_tree_root(NO_UTXO_ROOT)
            .is_err(),
        "no root history slot answers to the sentinel"
    );
    let mut expired = cache_state(&pool.rpc, &spend.cache);
    expired.expires_at = 0i64.to_le_bytes();
    store_cache(&mut pool.rpc, spend.cache, expired);
    let before = cache_state(&pool.rpc, &spend.cache);
    let (utxo_next_before, nullifier_next_before) = tree_progress(&pool.rpc, &tree);

    pool.rpc
        .create_and_send_default_payer_transaction_with_budget(
            std::slice::from_ref(&spend.instruction),
            &[],
            ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
        )
        .expect("spend the cached commitments");

    let state = cache_state(&pool.rpc, &spend.cache);
    assert_eq!(
        state, before,
        "read-only spending preserves the entire cache"
    );
    assert_eq!(
        state.utxo_hashes.get(..spend.commitments.len()),
        Some(spend.commitments.as_slice()),
        "spending leaves the seated commitments in place"
    );
    assert_eq!(
        tree_progress(&pool.rpc, &tree),
        (
            utxo_next_before + 2,
            nullifier_next_before + spend.nullifiers.len() as u64
        ),
        "a cached spend appends its outputs and queues one nullifier per input"
    );

    // The nullifiers are spent, so the same instruction cannot run twice even
    // though the cache still holds the commitments.
    pool.rpc
        .create_and_send_default_payer_transaction_with_budget(
            std::slice::from_ref(&spend.instruction),
            &[],
            ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
        )
        .expect_err("a cached spend cannot be replayed");
}

/// Each way a cached spend can be malformed, checked against one proven
/// instruction. A refused spend leaves the cache unchanged.
#[test]
fn a_cached_spend_rejects_every_broken_cache_binding() {
    let mut pool = proof_env();
    let tree = pool.tree;
    let tree_id = pool.tree_id;
    let spend = CachedSpendFixture::all_cached(2, 2, 11).build(&mut pool.rpc, tree, tree_id);
    let seated = cache_state(&pool.rpc, &spend.cache);

    // A cached selector expects the cache as its final account.
    let mut without_cache = spend.instruction.clone();
    without_cache.accounts.pop();
    expect_transact_rejection(
        &mut pool,
        without_cache,
        ShieldedPoolError::InvalidSettlementAccounts,
    );
    assert_eq!(cache_state(&pool.rpc, &spend.cache), seated);

    // An empty slot carries nothing to spend, and zero must never be spendable.
    let mut emptied = seated;
    if let Some(slot) = emptied.utxo_hashes.first_mut() {
        *slot = [0u8; 32];
    }
    store_cache(&mut pool.rpc, spend.cache, emptied);
    expect_transact_rejection(
        &mut pool,
        spend.instruction.clone(),
        ShieldedPoolError::CacheSlotEmpty,
    );
    assert_eq!(cache_state(&pool.rpc, &spend.cache), emptied);

    // One cache belongs to one tree, and a commitment is hashed under its tree.
    let mut other_tree = seated;
    other_tree.tree_id = tree_id.wrapping_add(1).to_le_bytes();
    store_cache(&mut pool.rpc, spend.cache, other_tree);
    expect_transact_rejection(
        &mut pool,
        spend.instruction.clone(),
        ShieldedPoolError::TransactProofVerificationFailed,
    );
    assert_eq!(cache_state(&pool.rpc, &spend.cache), other_tree);
}

fn store_cache(rpc: &mut ZolanaProgramTest, cache: Pubkey, state: CacheAccount) {
    let mut account = rpc.svm.get_account(&cache).expect("cache account");
    account.data = bytemuck::bytes_of(&state).to_vec();
    rpc.svm.set_account(cache, account).expect("store cache");
}

fn expect_transact_rejection(pool: &mut Pool, ix: Instruction, error: ShieldedPoolError) {
    let failure = pool
        .rpc
        .create_and_send_default_payer_transaction_with_budget(
            std::slice::from_ref(&ix),
            &[],
            ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
        )
        .expect_err("the cached spend must be rejected");
    Rejection::pool(error).assert_litesvm(failure);
}
