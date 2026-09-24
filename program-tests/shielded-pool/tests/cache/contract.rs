use shielded_pool_tests::support::{fixtures::Pool, merge::write_user_record};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::{
        merge_transact::{MergeProof, MergeTransactIxData},
        CreateCacheData,
    },
    pda,
    state::{cache::CacheAccount, discriminator::CACHE},
};
use zolana_program::instruction::{CacheWriteAccounts, CloseCache, CreateCache, MergeTransact};
use zolana_program_test::{Rejection, ZolanaProgramTest};
use zolana_test_utils::transact::fe;

fn create(payer: Address, nonce: u64, tree_id: u16, expires_at: i64) -> (Address, u8, Instruction) {
    let builder = CreateCache {
        payer,
        data: CreateCacheData {
            write_authority: payer,
            nonce,
            tree_id,
            expires_at,
        },
    };
    let (cache, bump) = pda::cache(&payer, nonce);
    (cache, bump, builder.instruction())
}

fn close(cache: Address, rent_recipient: Address) -> Instruction {
    CloseCache {
        cache,
        rent_recipient,
        writer: None,
    }
    .instruction()
}

fn state(rpc: &ZolanaProgramTest, cache: &Address) -> CacheAccount {
    *bytemuck::from_bytes(&rpc.account_data(cache).expect("cache data"))
}

fn store(rpc: &mut ZolanaProgramTest, cache: Address, state: CacheAccount) {
    let mut account = rpc.svm.get_account(&cache).expect("cache account");
    account.data = bytemuck::bytes_of(&state).to_vec();
    rpc.svm.set_account(cache, account).expect("store cache");
}

fn now(rpc: &ZolanaProgramTest) -> i64 {
    rpc.svm.get_sysvar::<solana_clock::Clock>().unix_timestamp
}

fn warp(rpc: &mut ZolanaProgramTest, unix_timestamp: i64) {
    let mut clock = rpc.svm.get_sysvar::<solana_clock::Clock>();
    clock.unix_timestamp = unix_timestamp;
    rpc.svm.set_sysvar(&clock);
}

fn reject(
    rpc: &mut ZolanaProgramTest,
    ix: Instruction,
    error: impl Into<pinocchio::error::ProgramError>,
) {
    let pinocchio::error::ProgramError::Custom(code) = error.into() else {
        panic!("expected a custom error");
    };
    rpc.svm.expire_blockhash();
    let error_actual = rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("must reject");
    Rejection::custom(code).assert_litesvm(error_actual);
}

#[test]
fn create_is_idempotent_and_close_refunds_sponsor() {
    let Pool {
        mut rpc, tree_id, ..
    } = Pool::initialized();
    let payer = rpc.payer.pubkey();
    let expires_at = now(&rpc) + 1_000;
    let (cache, bump, ix) = create(payer, 1, tree_id, expires_at);
    rpc.airdrop(&cache, 1_000_000).expect("pre-fund the cache");
    rpc.create_and_send_default_payer_transaction(std::slice::from_ref(&ix), &[])
        .expect("create a pre-funded cache");
    assert_eq!(
        state(&rpc, &cache),
        CacheAccount {
            discriminator: CACHE,
            bump,
            tree_id: tree_id.to_le_bytes(),
            expires_at: expires_at.to_le_bytes(),
            rent_sponsor: payer,
            write_authority: payer,
            utxo_hashes: [[0; 32]; 36],
        }
    );

    let mut used = state(&rpc, &cache);
    *used.utxo_hashes.get_mut(0).expect("cache slot 0") = fe(7);
    store(&mut rpc, cache, used);
    rpc.svm.expire_blockhash();
    rpc.create_and_send_default_payer_transaction(&[ix], &[])
        .expect("re-send an identical create");
    assert_eq!(
        state(&rpc, &cache),
        used,
        "an idempotent create must not reset the cache"
    );

    let before = rpc.svm.get_account(&payer).expect("payer account").lamports;
    let rent = rpc.svm.get_account(&cache).expect("cache account").lamports;
    warp(&mut rpc, expires_at);
    rpc.create_and_send_default_payer_transaction(&[close(cache, payer)], &[])
        .expect("close an expired cache without any signer");
    assert!(rpc
        .svm
        .get_account(&cache)
        .is_none_or(|account| account.lamports == 0));
    let after = rpc.svm.get_account(&payer).expect("payer account").lamports;
    assert_eq!(
        after,
        before + rent - 5_000,
        "refund the sponsor less the single payer signature fee"
    );
}

#[test]
fn create_and_close_reject_unauthorized_configuration() {
    let Pool {
        mut rpc, tree_id, ..
    } = Pool::initialized();
    let payer = rpc.payer.pubkey();
    let expires_at = now(&rpc) + 1_000;
    let (cache, _, ix) = create(payer, 2, tree_id, expires_at);
    rpc.create_and_send_default_payer_transaction(&[ix], &[])
        .expect("create the cache");
    let before = state(&rpc, &cache);

    let changed_authority = CreateCache {
        payer,
        data: CreateCacheData {
            write_authority: Keypair::new().pubkey(),
            nonce: 2,
            tree_id,
            expires_at,
        },
    }
    .instruction();
    reject(
        &mut rpc,
        changed_authority,
        ShieldedPoolError::CacheConfigMismatch,
    );
    assert_eq!(state(&rpc, &cache), before);

    let (_, _, wrong_tree) = create(payer, 2, tree_id + 1, expires_at);
    reject(&mut rpc, wrong_tree, ShieldedPoolError::CacheConfigMismatch);
    assert_eq!(state(&rpc, &cache), before);

    let (_, _, extended) = create(payer, 2, tree_id, expires_at + 1);
    reject(&mut rpc, extended, ShieldedPoolError::CacheConfigMismatch);
    assert_eq!(state(&rpc, &cache), before);

    reject(
        &mut rpc,
        close(cache, payer),
        ShieldedPoolError::CacheNotExpired,
    );
    assert_eq!(state(&rpc, &cache), before);

    let other = Keypair::new();
    rpc.airdrop(&other.pubkey(), 1_000_000)
        .expect("fund the outsider");
    warp(&mut rpc, expires_at);
    reject(
        &mut rpc,
        close(cache, other.pubkey()),
        ShieldedPoolError::CacheRentRecipientMismatch,
    );
    assert_eq!(state(&rpc, &cache), before);
}

#[test]
fn writer_can_close_before_expiry_and_only_refund_sponsor() {
    let Pool {
        mut rpc, tree_id, ..
    } = Pool::initialized();
    let sponsor = rpc.payer.pubkey();
    let writer = Keypair::new();
    rpc.airdrop(&writer.pubkey(), 1_000_000)
        .expect("fund writer");
    let builder = CreateCache {
        payer: sponsor,
        data: CreateCacheData {
            write_authority: writer.pubkey(),
            nonce: 6,
            tree_id,
            expires_at: now(&rpc) + 1000,
        },
    };
    let cache = builder.cache();
    rpc.create_and_send_default_payer_transaction(&[builder.instruction()], &[])
        .expect("create");
    let before = state(&rpc, &cache);
    reject(
        &mut rpc,
        close(cache, sponsor),
        ShieldedPoolError::CacheNotExpired,
    );
    reject(
        &mut rpc,
        CloseCache {
            cache,
            rent_recipient: sponsor,
            writer: Some(sponsor),
        }
        .instruction(),
        ShieldedPoolError::CacheWriteAuthorityMismatch,
    );
    let instruction = CloseCache {
        cache,
        rent_recipient: sponsor,
        writer: Some(writer.pubkey()),
    }
    .instruction();
    let mut unsigned = instruction.clone();
    unsigned.accounts.last_mut().expect("writer").is_signer = false;
    reject(
        &mut rpc,
        unsigned,
        zolana_account_checks::AccountError::InvalidSigner,
    );
    let wrong_recipient = CloseCache {
        cache,
        rent_recipient: writer.pubkey(),
        writer: Some(writer.pubkey()),
    }
    .instruction();
    let failure = rpc
        .create_and_send_default_payer_transaction(&[wrong_recipient], &[&writer])
        .expect_err("cannot redirect rent");
    Rejection::pool(ShieldedPoolError::CacheRentRecipientMismatch).assert_litesvm(failure);
    assert_eq!(state(&rpc, &cache), before);
    let sponsor_before = rpc.svm.get_account(&sponsor).expect("sponsor").lamports;
    let rent = rpc.svm.get_account(&cache).expect("cache").lamports;
    rpc.create_and_send_default_payer_transaction(&[instruction], &[&writer])
        .expect("writer closes unused cache");
    assert!(rpc
        .svm
        .get_account(&cache)
        .is_none_or(|account| account.lamports == 0));
    assert_eq!(
        rpc.svm.get_account(&sponsor).expect("sponsor").lamports,
        sponsor_before + rent - 10_000
    );
}

#[test]
fn create_is_permissionless_and_scoped_to_the_signing_sponsor() {
    let Pool {
        mut rpc, tree_id, ..
    } = Pool::initialized();
    let payer = rpc.payer.pubkey();
    let expires_at = now(&rpc) + 1_000;
    let (cache, bump, ix) = create(payer, 3, tree_id, expires_at);
    assert_eq!(
        ix.accounts
            .iter()
            .filter(|meta| meta.is_signer)
            .map(|meta| meta.pubkey)
            .collect::<Vec<_>>(),
        vec![payer],
        "only the rent sponsor signs a create"
    );
    rpc.create_and_send_default_payer_transaction(&[ix], &[])
        .expect("create signed by the sponsor alone");
    let expected = CacheAccount {
        discriminator: CACHE,
        bump,
        tree_id: tree_id.to_le_bytes(),
        expires_at: expires_at.to_le_bytes(),
        rent_sponsor: payer,
        write_authority: payer,
        utxo_hashes: [[0; 32]; 36],
    };
    assert_eq!(state(&rpc, &cache), expected);

    let sponsor = Keypair::new();
    rpc.airdrop(&sponsor.pubkey(), 1_000_000_000)
        .expect("fund the second sponsor");
    let (second, second_bump, second_ix) = create(sponsor.pubkey(), 3, tree_id, expires_at);
    assert_ne!(second, cache, "a second sponsor gets its own address");
    rpc.create_and_send_default_payer_transaction(&[second_ix], &[&sponsor])
        .expect("a second sponsor may reuse the nonce");
    assert_eq!(
        state(&rpc, &second),
        CacheAccount {
            bump: second_bump,
            rent_sponsor: sponsor.pubkey(),
            write_authority: sponsor.pubkey(),
            ..expected
        }
    );
    assert_eq!(
        state(&rpc, &cache),
        expected,
        "a second sponsor must not disturb the first cache"
    );

    // Only an empty system-owned account can become a cache.
    for (nonce, owner, data) in [
        (6, Address::new_unique(), Vec::new()),
        (7, Address::default(), vec![1u8]),
    ] {
        let (occupied, _, occupied_ix) = create(payer, nonce, tree_id, expires_at);
        rpc.svm
            .set_account(
                occupied,
                Account {
                    lamports: 1_000_000,
                    data,
                    owner,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .expect("occupy the cache address");
        let before = rpc.svm.get_account(&occupied);
        reject(&mut rpc, occupied_ix, ShieldedPoolError::InvalidCache);
        assert_eq!(rpc.svm.get_account(&occupied), before);
    }

    let (stale, _, stale_ix) = create(payer, 5, tree_id, now(&rpc) - 1);
    reject(
        &mut rpc,
        stale_ix,
        ShieldedPoolError::CacheExpiryNotInFuture,
    );
    assert!(rpc
        .svm
        .get_account(&stale)
        .is_none_or(|account| account.data.is_empty()));
}

#[test]
fn merge_rejects_invalid_writes_and_rolls_back_overwrites() {
    for case in ["occupied", "slot", "expired", "p256", "zero proof"] {
        let Pool {
            mut rpc,
            tree,
            tree_id,
            ..
        } = Pool::initialized();
        let owner = rpc.payer.pubkey();
        let p256 = case == "p256";
        let record = write_user_record(&mut rpc, owner, p256.then_some([2; 33]), true);
        let expires_at = now(&rpc) + 1_000;
        let (cache, _, create_ix) = create(owner, 4, tree_id, expires_at);
        rpc.create_and_send_default_payer_transaction(&[create_ix], &[])
            .expect("create the cache");
        let mut cache_state = state(&rpc, &cache);
        let error = match case {
            "occupied" => {
                *cache_state.utxo_hashes.get_mut(0).expect("cache slot 0") = fe(9);
                ShieldedPoolError::TransactProofVerificationFailed
            }
            "slot" => ShieldedPoolError::InvalidCacheSlot,
            "expired" => {
                warp(&mut rpc, expires_at);
                ShieldedPoolError::CacheExpired
            }
            // A P256 registry owner caches like any other: only the proof stops it.
            _ => ShieldedPoolError::TransactProofVerificationFailed,
        };
        store(&mut rpc, cache, cache_state);
        let data = MergeTransactIxData {
            cache_slot: Some(if case == "slot" { 36 } else { 0 }),
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: fe(9),
            eddsa_owner: !p256,
            private_tx_hash: [0; 32],
            nullifiers: (1..=8).map(fe).collect(),
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        };
        let ix = MergeTransact {
            input_tree: tree,
            output_tree: tree,
            payer: owner,
            user_record: record,
            data,
            cache: Some(CacheWriteAccounts {
                cache,
                writer: owner,
            }),
        }
        .instruction();
        let before = rpc.account_data(&tree).expect("tree data");
        reject(&mut rpc, ix, error);
        assert_eq!(state(&rpc, &cache), cache_state, "{case}");
        assert_eq!(
            rpc.account_data(&tree).expect("tree data"),
            before,
            "{case}"
        );
    }
}
