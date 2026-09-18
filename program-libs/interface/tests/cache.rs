#![cfg(feature = "solana")]

use solana_instruction::AccountMeta;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{
        instruction_data::merge_transact::MergeProof, tag, CloseCache, CreateCache,
        CreateCacheData, MergeRing, MergeTransact, MergeTransactIxData,
    },
    pda,
    state::cache::{cached_input_fields, empty_cached_input_fields, CACHE_SEED},
    MAX_TRANSACT_INPUTS, PROGRAM_ID_PUBKEY,
};

fn create_data(nonce: u64) -> CreateCacheData {
    CreateCacheData {
        owner_identity: [9u8; 32],
        nonce,
        tree_id: 3,
        expires_at: 1_800_000_000,
    }
}

fn merge_data(cache_slot: Option<u8>) -> MergeTransactIxData {
    MergeTransactIxData {
        cache_slot,
        expiry_unix_ts: u64::MAX,
        proof: MergeProof::zeroed(),
        output_utxo_hash: [1u8; 32],
        nullifiers: (1u8..=8).map(|i| [i; 32]).collect(),
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
        private_tx_hash: [0u8; 32],
        eddsa_owner: true,
    }
}

/// A spend that uses no cache publishes a selection that depends on nothing but
/// its input count, so the program reads it from a table instead of folding
/// zeros on chain. Every entry must hold what the general construction
/// produces, for every count a transact can declare.
#[test]
fn the_empty_selection_matches_the_general_one_for_every_input_count() {
    let empty = [[0u8; 32]; MAX_TRANSACT_INPUTS];
    for input_count in 0..=MAX_TRANSACT_INPUTS {
        assert_eq!(
            empty_cached_input_fields(input_count).unwrap(),
            cached_input_fields(0, 0, empty.iter().take(input_count)).unwrap(),
            "input count {input_count}"
        );
    }
}

#[test]
fn cache_pda_derives_from_the_rent_sponsor_and_nonce() {
    let sponsor = Pubkey::new_unique();
    let (address, bump) = pda::cache(&sponsor, 7);
    let recreated = Pubkey::create_program_address(
        &[CACHE_SEED, sponsor.as_ref(), &7u64.to_le_bytes(), &[bump]],
        &pda::shielded_pool_program_id(),
    )
    .expect("canonical bump is on the curve complement");
    assert_eq!(recreated, address);
    assert_ne!(pda::cache(&sponsor, 8).0, address);
    assert_ne!(pda::cache(&Pubkey::new_unique(), 7).0, address);
    assert_ne!(pda::cache(&sponsor, 7 << 8).0, address);
}

#[test]
fn create_cache_lays_out_payer_cache_and_system() {
    let payer = Pubkey::new_unique();
    let data = create_data(42);
    let builder = CreateCache { payer, data };

    let ix = builder.instruction();
    assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
    assert_eq!(builder.cache(), pda::cache(&payer, 42).0);
    assert_eq!(
        ix.accounts,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(pda::cache(&payer, 42).0, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ]
    );
    assert_eq!(ix.data.first(), Some(&tag::CREATE_CACHE));
    assert_eq!(
        ix.data.get(1..),
        Some(wincode::serialize(&data).expect("serialize").as_slice())
    );
}

#[test]
fn close_cache_takes_no_signer_and_writes_both_accounts() {
    let cache = Pubkey::new_unique();
    let rent_recipient = Pubkey::new_unique();

    let ix = CloseCache {
        cache,
        rent_recipient,
        owner: None,
    }
    .instruction();
    assert_eq!(ix.program_id, PROGRAM_ID_PUBKEY);
    assert_eq!(
        ix.accounts,
        vec![
            AccountMeta::new(cache, false),
            AccountMeta::new(rent_recipient, false),
        ]
    );
    assert_eq!(ix.data, vec![tag::CLOSE_CACHE]);
}

#[test]
fn close_cache_appends_the_owner_signer_for_early_close() {
    let cache = Pubkey::new_unique();
    let rent_recipient = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let ix = CloseCache {
        cache,
        rent_recipient,
        owner: Some(owner),
    }
    .instruction();
    assert_eq!(
        ix.accounts,
        vec![
            AccountMeta::new(cache, false),
            AccountMeta::new(rent_recipient, false),
            AccountMeta::new_readonly(owner, true),
        ]
    );
    assert_eq!(ix.data, vec![tag::CLOSE_CACHE]);
}

#[test]
fn merge_transact_appends_the_cache_account_only_when_set() {
    let input_tree = Pubkey::new_unique();
    let cache = Pubkey::new_unique();
    let builder = MergeTransact {
        input_tree,
        output_tree: Pubkey::new_unique(),
        payer: Pubkey::new_unique(),
        user_record: Pubkey::new_unique(),
        data: merge_data(None),
        cache: None,
    };
    let without_cache = builder.instruction();
    assert_eq!(without_cache.accounts.len(), 6 + 8);
    assert_eq!(
        without_cache.accounts.last().map(|meta| meta.pubkey),
        Some(pda::nullifier_pda(&input_tree, &[8u8; 32]).0)
    );

    let with_cache = MergeTransact {
        data: merge_data(Some(4)),
        cache: Some(cache),
        ..builder
    }
    .instruction();
    assert_eq!(
        with_cache.accounts.get(..6 + 8),
        without_cache.accounts.get(..)
    );
    assert_eq!(
        with_cache.accounts.get(6 + 8),
        Some(&AccountMeta::new(cache, false))
    );
    assert_eq!(with_cache.accounts.len(), 6 + 8 + 1);
}

#[test]
fn merge_ring_appends_the_cache_account_only_when_set() {
    let input_tree = Pubkey::new_unique();
    let cache = Pubkey::new_unique();
    let builder = MergeRing {
        input_tree,
        output_tree: Pubkey::new_unique(),
        ring_program_id: Pubkey::new_unique(),
        payer: Pubkey::new_unique(),
        data: merge_data(None),
        output_ring_data_hash: [5u8; 32],
        cache: None,
    };
    let without_cache = builder.instruction();
    assert_eq!(without_cache.accounts.len(), 6 + 8);
    assert_eq!(
        without_cache.accounts.last().map(|meta| meta.pubkey),
        Some(pda::nullifier_pda(&input_tree, &[8u8; 32]).0)
    );

    let cached = MergeRing {
        data: merge_data(Some(0)),
        cache: Some(cache),
        ..builder
    };
    let with_cache = cached.instruction();
    assert_eq!(
        with_cache.accounts.get(..6 + 8),
        without_cache.accounts.get(..)
    );
    assert_eq!(
        with_cache.accounts.get(6 + 8),
        Some(&AccountMeta::new(cache, false))
    );
    assert_eq!(with_cache.accounts.len(), 6 + 8 + 1);
    assert_eq!(
        cached.cpi_instruction().accounts.get(6 + 8),
        Some(&AccountMeta::new(cache, false))
    );
}
