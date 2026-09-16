use shielded_pool_tests::support::{fixtures::Pool, merge::write_user_record};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::{
            merge_transact::{MergeProof, MergeTransactIxData},
            CreateCacheData,
        },
        tag, MergeTransact,
    },
    state::{
        cache::{CacheAccount, CACHE_SEED},
        discriminator::CACHE,
    },
};
use zolana_program_test::{Rejection, ZolanaProgramTest};

fn create(
    rpc: &ZolanaProgramTest,
    owner: Address,
    operation: u8,
    tree_id: u16,
) -> (Address, Instruction) {
    let operation_id = [operation; 32];
    let (cache, _) = Address::find_program_address(
        &[CACHE_SEED, owner.as_ref(), &operation_id],
        &rpc.program_id,
    );
    let ix = CreateCacheData {
        owner_kind: 0,
        operation_id,
        tree_id,
        close_authority: owner.to_bytes(),
    };
    let mut data = vec![tag::CREATE_CACHE];
    data.extend(wincode::serialize(&ix).unwrap());
    (
        cache,
        Instruction {
            program_id: rpc.program_id,
            accounts: vec![
                AccountMeta::new(rpc.payer.pubkey(), true),
                AccountMeta::new_readonly(owner, true),
                AccountMeta::new(cache, false),
                AccountMeta::new_readonly(Address::default(), false),
            ],
            data,
        },
    )
}
fn state(rpc: &ZolanaProgramTest, cache: &Address) -> CacheAccount {
    *bytemuck::from_bytes(&rpc.account_data(cache).unwrap())
}
fn store(rpc: &mut ZolanaProgramTest, cache: Address, state: CacheAccount) {
    let mut account = rpc.svm.get_account(&cache).unwrap();
    account.data = bytemuck::bytes_of(&state).to_vec();
    rpc.svm.set_account(cache, account).unwrap();
}
fn close(
    rpc: &ZolanaProgramTest,
    cache: Address,
    authority: Address,
    recipient: Address,
) -> Instruction {
    Instruction {
        program_id: rpc.program_id,
        accounts: vec![
            AccountMeta::new(cache, false),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(recipient, false),
        ],
        data: vec![tag::CLOSE_CACHE],
    }
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
    let owner = Keypair::new();
    let (cache, ix) = create(&rpc, owner.pubkey(), 1, tree_id);
    rpc.airdrop(&cache, 1_000_000).unwrap(); // pre-funded PDA must still initialize
    rpc.create_and_send_default_payer_transaction(&[ix.clone()], &[&owner])
        .unwrap();
    let mut expected = state(&rpc, &cache);
    assert_eq!(
        expected,
        CacheAccount {
            discriminator: CACHE,
            bump: expected.bump,
            frozen: 0,
            owner_kind: 0,
            tree_id: tree_id.to_le_bytes(),
            owner: owner.pubkey().to_bytes(),
            operation_id: [1; 32],
            rent_sponsor: rpc.payer.pubkey().to_bytes(),
            close_authority: owner.pubkey().to_bytes(),
            commitments: [[0; 32]; 36]
        }
    );
    expected.commitments[0][31] = 7;
    expected.frozen = 1;
    store(&mut rpc, cache, expected);
    rpc.svm.expire_blockhash();
    rpc.create_and_send_default_payer_transaction(&[ix], &[&owner])
        .unwrap();
    assert_eq!(
        state(&rpc, &cache),
        expected,
        "idempotent create must not reset cache"
    );
    let before = rpc.svm.get_account(&rpc.payer.pubkey()).unwrap().lamports;
    let rent = rpc.svm.get_account(&cache).unwrap().lamports;
    let close = close(&rpc, cache, owner.pubkey(), rpc.payer.pubkey());
    rpc.create_and_send_default_payer_transaction(&[close], &[&owner])
        .unwrap();
    assert!(rpc
        .svm
        .get_account(&cache)
        .is_none_or(|account| account.lamports == 0));
    let after = rpc.svm.get_account(&rpc.payer.pubkey()).unwrap().lamports;
    assert_eq!(
        after,
        before + rent - 10_000,
        "refund sponsor less two signature fees"
    );
}

#[test]
fn create_and_close_reject_unauthorized_configuration() {
    let Pool {
        mut rpc, tree_id, ..
    } = Pool::initialized();
    let owner = rpc.payer.pubkey();
    let (cache, ix) = create(&rpc, owner, 2, tree_id);
    rpc.create_and_send_default_payer_transaction(&[ix], &[])
        .unwrap();
    let before = state(&rpc, &cache);
    let (_, wrong_tree) = create(&rpc, owner, 2, tree_id + 1);
    reject(&mut rpc, wrong_tree, ShieldedPoolError::CacheConfigMismatch);
    assert_eq!(state(&rpc, &cache), before);
    let other = Keypair::new();
    rpc.airdrop(&other.pubkey(), 1_000_000).unwrap();
    let wrong_recipient = close(&rpc, cache, owner, other.pubkey());
    reject(
        &mut rpc,
        wrong_recipient,
        ShieldedPoolError::InvalidReimbursementRecipient,
    );
    let wrong_authority = close(&rpc, cache, other.pubkey(), owner);
    let err = rpc
        .create_and_send_default_payer_transaction(&[wrong_authority], &[&other])
        .unwrap_err();
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller).assert_litesvm(err);
    assert_eq!(state(&rpc, &cache), before);
}

#[test]
fn merge_rejects_overwrites_frozen_caches_and_foreign_owners() {
    for case in [
        "occupied",
        "frozen",
        "owner",
        "slot",
        "p256",
        "p256 plain",
        "zero proof",
    ] {
        let Pool {
            mut rpc,
            tree,
            tree_id,
            ..
        } = Pool::initialized();
        let owner = rpc.payer.pubkey();
        let p256 = matches!(case, "p256" | "p256 plain");
        let record = write_user_record(&mut rpc, owner, p256.then_some([2; 33]), true);
        let (cache, create) = create(&rpc, owner, 4, tree_id);
        rpc.create_and_send_default_payer_transaction(&[create], &[])
            .unwrap();
        let mut cache_state = state(&rpc, &cache);
        let error = match case {
            "occupied" => {
                cache_state.commitments[0][31] = 9;
                ShieldedPoolError::CacheSlotOccupied
            }
            "frozen" => {
                cache_state.frozen = 1;
                ShieldedPoolError::CacheFrozen
            }
            "owner" => {
                cache_state.owner = [7; 32];
                ShieldedPoolError::CacheOwnerMismatch
            }
            "slot" => ShieldedPoolError::InvalidCacheSlot,
            "p256" => ShieldedPoolError::CacheUnsupportedOwner,
            _ => ShieldedPoolError::TransactProofVerificationFailed,
        };
        store(&mut rpc, cache, cache_state);
        let data = MergeTransactIxData {
            cache_slot: (case != "p256 plain").then_some(if case == "slot" { 36 } else { 0 }),
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: zolana_test_utils::transact::fe(9),
            eddsa_owner: !p256,
            private_tx_hash: [0; 32],
            nullifiers: (1..=8).map(zolana_test_utils::transact::fe).collect(),
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        };
        let mut ix = MergeTransact {
            input_tree: tree,
            output_tree: tree,
            payer: owner,
            user_record: record,
            data,
        }
        .instruction();
        if case != "p256 plain" {
            ix.accounts.push(AccountMeta::new(cache, false));
        }
        let before = rpc.account_data(&tree).unwrap();
        reject(&mut rpc, ix, error);
        assert_eq!(state(&rpc, &cache), cache_state);
        assert_eq!(rpc.account_data(&tree).unwrap(), before);
    }
}

#[test]
fn ring_cache_creation_requires_the_ring_signature_and_preserves_existing_slots() {
    for signed in [false, true] {
        let Pool {
            mut rpc,
            tree_id,
            authority,
            ..
        } = Pool::initialized();
        rpc.load_ring_test_program().unwrap();
        let ring_program = Address::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID);
        let ring_config = rpc
            .create_activated_ring_config(&authority, &authority.pubkey(), &authority, true)
            .unwrap();
        let (cache, mut ix) = create(&rpc, ring_program, 9, tree_id);
        ix.data = vec![tag::CREATE_CACHE];
        ix.data.extend(
            wincode::serialize(&CreateCacheData {
                owner_kind: 1,
                operation_id: [9; 32],
                tree_id,
                close_authority: rpc.payer.pubkey().to_bytes(),
            })
            .unwrap(),
        );
        *ix.accounts.get_mut(1).unwrap() = AccountMeta::new_readonly(ring_config, false);
        if signed {
            ix.program_id = ring_program;
            ix.accounts
                .push(AccountMeta::new_readonly(rpc.program_id, false));
        }
        let result = rpc.create_and_send_default_payer_transaction(&[ix.clone()], &[]);
        if !signed {
            assert!(result.is_err());
            assert!(rpc.svm.get_account(&cache).is_none());
            continue;
        }
        result.unwrap();
        let mut expected = state(&rpc, &cache);
        assert_eq!(
            expected,
            CacheAccount {
                discriminator: CACHE,
                bump: expected.bump,
                frozen: 0,
                owner_kind: 1,
                tree_id: tree_id.to_le_bytes(),
                owner: ring_program.to_bytes(),
                operation_id: [9; 32],
                rent_sponsor: rpc.payer.pubkey().to_bytes(),
                close_authority: rpc.payer.pubkey().to_bytes(),
                commitments: [[0; 32]; 36],
            }
        );
        expected.commitments[0] = zolana_test_utils::transact::fe(42);
        expected.frozen = 1;
        store(&mut rpc, cache, expected);
        rpc.svm.expire_blockhash();
        rpc.create_and_send_default_payer_transaction(&[ix], &[])
            .unwrap();
        assert_eq!(state(&rpc, &cache), expected);
    }
}
