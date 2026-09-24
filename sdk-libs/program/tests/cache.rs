use solana_instruction::AccountMeta;
use solana_pubkey::Pubkey;
use zolana_hasher::hash_chain::create_right_hash_chain_4_from_slice;
use zolana_interface::{
    instruction::{
        instruction_data::merge_transact::MergeProof, tag, CreateCacheData, MergeTransactIxData,
    },
    pda,
    state::cache::{
        cached_input_fields, empty_cached_input_fields, CACHE_CAPACITY, CACHE_SEED,
        ZERO_SUFFIX_CHAINS,
    },
    MAX_TRANSACT_INPUTS, PROGRAM_ID_PUBKEY,
};
use zolana_program::instruction::{
    CacheWriteAccounts, CloseCache, CreateCache, MergeRing, MergeTransact,
};

fn create_data(nonce: u64) -> CreateCacheData {
    CreateCacheData {
        write_authority: Pubkey::new_from_array([8u8; 32]),
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

fn writes(pairs: &[(u8, u8)]) -> [zolana_interface::verifying_keys::CacheWrite; 8] {
    use zolana_interface::verifying_keys::{CacheAccess, CacheWrite};
    let mut out = CacheAccess::NO_WRITES;
    for (entry, (output, slot)) in out.iter_mut().zip(pairs) {
        *entry = CacheWrite {
            output: *output,
            slot: *slot,
        };
    }
    out
}

#[test]
fn cache_access_validates_read_and_write_masks_independently() {
    use zolana_interface::verifying_keys::CacheAccess;
    for (reads, pairs, inputs, outputs, valid) in [
        (0, &[][..], 2, 2, false),
        (1, &[], 2, 2, true),
        (0, &[(0, 0), (1, 2)], 2, 2, true),
        (3, &[(0, 0), (1, 2)], 2, 2, true),
        (4, &[(0, 0), (1, 2)], 2, 2, true),
        (0b111, &[], 2, 2, false),
        (1 << 35, &[], 1, 1, true),
        (1 << 36, &[], 1, 1, false),
        (0, &[(0, 35)], 1, 1, true),
        (0, &[(0, 36)], 1, 1, false),
        (0, &[(1, 4)], 2, 2, true),
        (0, &[(1, 30), (0, 2)], 2, 2, true),
        (0, &[(0, 3), (1, 3)], 2, 2, false),
        (0, &[(0, 3), (0, 4)], 2, 2, false),
        (0, &[(2, 3)], 2, 2, false),
        (0, &[(0, 255)], 2, 2, false),
        (0, &[(255, 3)], 2, 2, false),
        (1, &[], 64, 1, true),
        (
            0,
            &[
                (0, 0),
                (1, 1),
                (2, 2),
                (3, 3),
                (4, 4),
                (5, 5),
                (6, 6),
                (7, 7),
            ],
            1,
            8,
            true,
        ),
    ] {
        assert_eq!(
            CacheAccess {
                read_bitmap: reads,
                write_slots: writes(pairs),
            }
            .valid(inputs, outputs),
            valid,
            "reads {reads:#x}, writes {pairs:?}, {inputs}x{outputs}"
        );
    }
}

#[test]
fn a_write_after_the_first_unused_entry_is_refused() {
    use zolana_interface::verifying_keys::{CacheAccess, CacheWrite};
    let mut write_slots = writes(&[(0, 1)]);
    if let Some(entry) = write_slots.get_mut(2) {
        *entry = CacheWrite { output: 1, slot: 2 };
    }
    let access = CacheAccess {
        read_bitmap: 0,
        write_slots,
    };
    assert!(!access.valid(2, 2));
    assert_eq!(access.writes().count(), 1);
}

#[test]
fn only_the_packed_prefix_counts_as_writes() {
    use zolana_interface::verifying_keys::{CacheAccess, CacheWrite};
    let access = CacheAccess {
        read_bitmap: 0,
        write_slots: writes(&[(1, 30), (0, 2)]),
    };
    assert!(access.writes_cache());
    assert_eq!(
        access.writes().collect::<Vec<_>>(),
        vec![
            CacheWrite {
                output: 1,
                slot: 30
            },
            CacheWrite { output: 0, slot: 2 }
        ]
    );
    assert!(!CacheAccess {
        read_bitmap: 1,
        write_slots: CacheAccess::NO_WRITES,
    }
    .writes_cache());
}

#[test]
fn cache_write_binding_commits_to_destination_writes_and_external_data() {
    use zolana_interface::state::cache::bind_cache_write;
    let original = [1; 32];
    assert_eq!(bind_cache_write(original, None).unwrap(), original);
    let pairs = writes(&[(0, 0), (1, 1)]);
    let binding = bind_cache_write(original, Some((&[2; 32], &pairs))).unwrap();
    for other in [
        bind_cache_write([9; 32], Some((&[2; 32], &pairs))).unwrap(),
        bind_cache_write(original, Some((&[9; 32], &pairs))).unwrap(),
        bind_cache_write(original, Some((&[2; 32], &writes(&[(0, 0), (1, 2)])))).unwrap(),
        bind_cache_write(original, Some((&[2; 32], &writes(&[(1, 0), (0, 1)])))).unwrap(),
        bind_cache_write(original, Some((&[2; 32], &writes(&[(0, 0)])))).unwrap(),
        original,
    ] {
        assert_ne!(binding, other);
    }
}

/// Regenerates `ZERO_SUFFIX_CHAINS` in `state/cache.rs`. Only needed if
/// `MAX_TRANSACT_INPUTS` grows; run with `--ignored --nocapture` and paste.
#[test]
#[ignore = "prints the zero-suffix table for state/cache.rs"]
fn print_zero_suffix_chains() {
    let zero = [0u8; 32];
    for groups in 0..=(MAX_TRANSACT_INPUTS - 1).div_ceil(3) {
        let suffix = vec![zero; 1 + 3 * groups];
        let value = create_right_hash_chain_4_from_slice(&suffix).unwrap();
        let bytes: Vec<String> = value.iter().map(|byte| format!("0x{byte:02x}")).collect();
        println!("    [{}],", bytes.join(", "));
    }
}

#[test]
fn the_empty_selection_matches_the_general_one_for_every_input_count() {
    let empty = [[0u8; 32]; MAX_TRANSACT_INPUTS];
    let slots = [[0u8; 32]; CACHE_CAPACITY];
    for input_count in 0..=MAX_TRANSACT_INPUTS {
        let zeros = empty
            .get(..input_count)
            .expect("count fits the widest shape");
        let [tree_id, chain] = empty_cached_input_fields(input_count).unwrap();
        assert_eq!(tree_id, [0u8; 32], "input count {input_count}");
        assert_eq!(
            chain,
            create_right_hash_chain_4_from_slice(zeros).unwrap(),
            "input count {input_count}"
        );
        for cache_tree_id in [0, 7, u16::MAX] {
            assert_eq!(
                cached_input_fields(0, cache_tree_id, &slots, input_count).unwrap(),
                [tree_id, chain],
                "input count {input_count}, cache tree {cache_tree_id}"
            );
        }
    }
}

/// The table is the fold over zeros, recomputed here from the primitive rather
/// than from the table itself, so a transcription slip cannot pass.
#[test]
fn the_zero_suffix_table_is_the_fold_over_zeros() {
    let zero = [0u8; 32];
    for (groups, entry) in ZERO_SUFFIX_CHAINS.iter().enumerate() {
        let suffix = vec![zero; 1 + 3 * groups];
        assert_eq!(
            *entry,
            create_right_hash_chain_4_from_slice(&suffix).unwrap(),
            "Z({groups})"
        );
    }
    assert_eq!(
        ZERO_SUFFIX_CHAINS.len(),
        (MAX_TRANSACT_INPUTS - 1).div_ceil(3) + 1,
        "the table must reach the widest shape's group count"
    );
}

fn slot_hash(slot: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(low) = out.last_mut() {
        *low = u8::try_from(slot % 251 + 1).expect("fits a byte");
    }
    if let Some(high) = out.get_mut(30) {
        *high = 1;
    }
    out
}

fn filled_slots() -> [[u8; 32]; CACHE_CAPACITY] {
    let mut slots = [[0u8; 32]; CACHE_CAPACITY];
    for (slot, hash) in slots.iter_mut().enumerate() {
        *hash = slot_hash(slot);
    }
    slots
}

fn read_list(read_bitmap: u64, input_count: usize) -> Vec<[u8; 32]> {
    let mut list: Vec<[u8; 32]> = (0..CACHE_CAPACITY)
        .filter(|slot| read_bitmap >> slot & 1 == 1)
        .map(slot_hash)
        .collect();
    list.resize(input_count, [0u8; 32]);
    list
}

#[test]
fn the_skip_path_matches_the_plain_fold_for_every_selection() {
    let slots = filled_slots();
    for input_count in 1..=MAX_TRANSACT_INPUTS {
        let reads = input_count.min(CACHE_CAPACITY) as u32;
        let low = if reads == 64 {
            u64::MAX
        } else {
            (1u64 << reads) - 1
        };
        let mut selections = vec![0u64, low, 1, 1 << (CACHE_CAPACITY - 1)];
        selections.push(low << (CACHE_CAPACITY as u32 - reads));
        selections.push(
            (0..CACHE_CAPACITY)
                .step_by(7)
                .take(input_count)
                .fold(0, |b, s| b | 1 << s),
        );
        for read_bitmap in selections {
            if read_bitmap.count_ones() as usize > input_count {
                continue;
            }
            let [tree_id, chain] =
                cached_input_fields(read_bitmap, 9, &slots, input_count).unwrap();
            let expected = if read_bitmap == 0 {
                empty_cached_input_fields(input_count).unwrap()
            } else {
                [
                    zolana_interface::tree_slot::tree_id_field(9),
                    create_right_hash_chain_4_from_slice(&read_list(read_bitmap, input_count))
                        .unwrap(),
                ]
            };
            assert_eq!(
                [tree_id, chain],
                expected,
                "input count {input_count}, reads {read_bitmap:#x}"
            );
        }
    }
}

#[test]
fn reads_are_listed_in_slot_order_whatever_the_input_count() {
    let slots = filled_slots();
    let [_, chain] = cached_input_fields(1 << 30 | 1 << 3, 0, &slots, 2).unwrap();
    assert_eq!(
        chain,
        create_right_hash_chain_4_from_slice(&[slot_hash(3), slot_hash(30)]).unwrap()
    );
}

#[test]
fn a_selection_wider_than_the_inputs_or_the_cache_is_refused() {
    let slots = filled_slots();
    assert!(cached_input_fields(0b111, 0, &slots, 2).is_err());
    assert!(cached_input_fields(1 << CACHE_CAPACITY, 0, &slots, 2).is_err());
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
        writer: None,
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
fn close_cache_appends_the_writer_signer_for_early_close() {
    let cache = Pubkey::new_unique();
    let rent_recipient = Pubkey::new_unique();
    let writer = Pubkey::new_unique();
    let ix = CloseCache {
        cache,
        rent_recipient,
        writer: Some(writer),
    }
    .instruction();
    assert_eq!(
        ix.accounts,
        vec![
            AccountMeta::new(cache, false),
            AccountMeta::new(rent_recipient, false),
            AccountMeta::new_readonly(writer, true),
        ]
    );
    assert_eq!(ix.data, vec![tag::CLOSE_CACHE]);
}

#[test]
fn merge_transact_appends_the_cache_and_writer_only_when_set() {
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
        cache: Some(CacheWriteAccounts {
            cache,
            writer: builder.payer,
        }),
        ..builder
    }
    .instruction();
    assert_eq!(
        with_cache.accounts.get(..6 + 8),
        without_cache.accounts.get(..)
    );
    assert_eq!(
        with_cache.accounts.get(6 + 8..),
        Some(
            &[
                AccountMeta::new(cache, false),
                AccountMeta::new_readonly(builder.payer, true),
            ][..]
        )
    );
}

#[test]
fn merge_ring_appends_the_cache_and_writer_only_when_set() {
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
        cache: Some(CacheWriteAccounts {
            cache,
            writer: builder.payer,
        }),
        ..builder
    };
    let cache_accounts = [
        AccountMeta::new(cache, false),
        AccountMeta::new_readonly(builder.payer, true),
    ];
    let with_cache = cached.instruction();
    assert_eq!(
        with_cache.accounts.get(..6 + 8),
        without_cache.accounts.get(..)
    );
    assert_eq!(with_cache.accounts.get(6 + 8..), Some(&cache_accounts[..]));
    assert_eq!(
        cached.cpi_instruction().accounts.get(6 + 8..),
        Some(&cache_accounts[..])
    );
}
