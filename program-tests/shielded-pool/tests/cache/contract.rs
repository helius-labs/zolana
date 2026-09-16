use shielded_pool_tests::support::{fixtures::Pool, merge::write_user_record};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::{ComputeBudgetConfig, Proof, ProofCompressed};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::{
            merge_transact::{MergeProof, MergeTransactIxData},
            CreateCacheData,
        },
        tag, CachedInputs, CircuitId, InputUtxo, MergeRing, MergeTransact, OwnerTag, Transact,
        TransactIxData, TransactOutput, TreeContext,
    },
    state::{
        cache::{CacheAccount, CACHE_SEED},
        discriminator::CACHE,
        tree_id_offset,
    },
};
use zolana_program_test::{Rejection, ZolanaProgramTest};
use zolana_tree::TreeAccount;

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

fn bytes<const N: usize>(v: &serde_json::Value) -> [u8; N] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn vector(name: &str) -> serde_json::Value {
    serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/fixtures/cache/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap()
}
fn fields(v: &serde_json::Value, name: &str) -> Vec<[u8; 32]> {
    v[name].as_array().unwrap().iter().map(bytes).collect()
}

struct SpendFixture {
    rpc: ZolanaProgramTest,
    cache: Address,
    instruction: Instruction,
    ix: TransactIxData,
    tree: Address,
}
fn spend_fixture(name: &str, frozen: bool) -> SpendFixture {
    let Pool {
        mut rpc,
        tree,
        authority,
        ..
    } = Pool::initialized();
    rpc.payer = Keypair::new_from_array([0x42; 32]);
    rpc.airdrop(&rpc.payer.pubkey(), 1_000_000_000_000).unwrap();
    let output_tree = rpc.create_tree(&authority).unwrap();
    let v = vector(name);
    for (address, tree_id) in [(tree, 7u16), (output_tree, 11u16)] {
        let mut account = rpc.svm.get_account(&address).unwrap();
        let offset = tree_id_offset();
        account
            .data
            .get_mut(offset..offset + 2)
            .unwrap()
            .copy_from_slice(&tree_id.to_le_bytes());
        if address == tree {
            let mut state = TreeAccount::from_bytes(&mut account.data, address.to_bytes()).unwrap();
            state.utxo_tree().root_history[0] = bytes(&v["state_root"]);
            state.nullifier_tree().root_history.roots[0] = bytes(&v["nullifier_root"]);
        }
        rpc.svm.set_account(address, account).unwrap();
    }
    let (cache, create) = create(&rpc, rpc.payer.pubkey(), 3, 7);
    rpc.create_and_send_default_payer_transaction(&[create], &[])
        .unwrap();
    let mut record = state(&rpc, &cache);
    record.frozen = u8::from(frozen);
    for (slot, commitment) in record.commitments.iter_mut().zip(fields(&v, "commitments")) {
        *slot = commitment;
    }
    store(&mut rpc, cache, record);
    let nullifiers = fields(&v, "nullifiers");
    let n = nullifiers.len();
    let ix = TransactIxData {
        expiry_unix_ts: u64::MAX,
        tx_viewing_pk: [0; 33],
        salt: [0; 16],
        circuit: CircuitId::ConfidentialEddsaCached(
            n as u8,
            2,
            3,
            CachedInputs {
                input_bitmap: v["bitmap"].as_u64().unwrap(),
            },
        ),
        private_tx_hash: bytes(&v["private_tx_hash"]),
        proof: ProofCompressed::try_from(Proof {
            a: bytes(&v["proof_a"]),
            b: bytes(&v["proof_b"]),
            c: bytes(&v["proof_c"]),
            commitment: None,
        })
        .unwrap()
        .to_transact_proof(),
        inputs: nullifiers
            .into_iter()
            .map(|nullifier_hash| InputUtxo {
                nullifier_hash,
                tree_index: 0,
            })
            .collect(),
        outputs: fields(&v, "outputs")
            .into_iter()
            .map(|utxo_hash| TransactOutput {
                utxo_hash,
                owner_tag: OwnerTag::Inline(rpc.payer.pubkey().to_bytes()),
                data: None,
            })
            .collect(),
        interface_transfers: vec![],
        data_hash: None,
        ring_data_hash: None,
        messages: vec![],
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
    };
    let mut instruction = Transact {
        payer: rpc.payer.pubkey(),
        output_tree,
        input_trees: vec![tree],
        owner_signers: vec![],
        interface_transfer_accounts: vec![],
        data: ix.clone(),
    }
    .instruction();
    instruction.accounts.push(AccountMeta::new(cache, false));
    SpendFixture {
        rpc,
        cache,
        instruction,
        ix,
        tree,
    }
}

#[test]
fn real_proofs_spend_cached_mixed_and_36_inputs_and_prevent_replay() {
    for name in ["all", "mixed", "wide"] {
        let SpendFixture {
            mut rpc,
            cache,
            instruction,
            mut ix,
            tree,
        } = spend_fixture(name, false);
        let mut expected = state(&rpc, &cache);
        rpc.create_and_send_default_payer_transaction_with_budget(
            &[instruction.clone()],
            &[],
            ComputeBudgetConfig::new(1_400_000),
        )
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        expected.frozen = 1;
        assert_eq!(state(&rpc, &cache), expected);
        let after_tree = rpc.account_data(&tree).unwrap();
        reject(
            &mut rpc,
            instruction.clone(),
            ShieldedPoolError::NullifierAlreadyQueued,
        );
        assert_eq!(rpc.account_data(&tree).unwrap(), after_tree);
        // The ordinary path cannot spend these nullifiers either.
        ix.circuit = CircuitId::ConfidentialEddsa(ix.inputs.len() as u8, 2, 3);
        let mut fallback = instruction;
        fallback.accounts.pop();
        fallback.data = vec![tag::TRANSACT];
        fallback.data.extend(ix.serialize().unwrap());
        reject(
            &mut rpc,
            fallback,
            ShieldedPoolError::NullifierAlreadyQueued,
        );
    }
}

#[test]
fn frozen_cache_allows_remaining_unspent_entries() {
    let SpendFixture {
        mut rpc,
        cache,
        instruction,
        ..
    } = spend_fixture("all", true);
    let before = state(&rpc, &cache);
    rpc.create_and_send_default_payer_transaction(&[instruction], &[])
        .unwrap();
    assert_eq!(state(&rpc, &cache), before);
}

#[test]
fn spend_rejects_missing_wrong_slots_tree_and_proof_atomically() {
    for case in [
        "empty",
        "wrong commitment",
        "wrong tree",
        "bitmap",
        "root index",
        "readonly",
        "proof",
    ] {
        let SpendFixture {
            mut rpc,
            cache,
            mut instruction,
            mut ix,
            tree,
        } = spend_fixture("all", false);
        let mut cache_state = state(&rpc, &cache);
        let error = match case {
            "empty" => {
                cache_state.commitments[0] = [0; 32];
                ShieldedPoolError::CacheSlotEmpty.into()
            }
            "wrong commitment" => {
                cache_state.commitments.swap(0, 1);
                ShieldedPoolError::TransactProofVerificationFailed.into()
            }
            "wrong tree" => {
                cache_state.tree_id = 8u16.to_le_bytes();
                ShieldedPoolError::CacheTreeMismatch.into()
            }
            "bitmap" => {
                ix.circuit =
                    CircuitId::ConfidentialEddsaCached(2, 2, 3, CachedInputs { input_bitmap: 4 });
                ShieldedPoolError::InvalidCacheBitmap.into()
            }
            "root index" => {
                ix.tree_contexts[0].utxo_tree_root_index = 1;
                ShieldedPoolError::InvalidCacheRootIndex.into()
            }
            "readonly" => {
                instruction.accounts.last_mut().unwrap().is_writable = false;
                pinocchio::error::ProgramError::from(
                    zolana_account_checks::AccountError::AccountNotMutable,
                )
            }
            _ => {
                ix.private_tx_hash[31] ^= 1;
                ShieldedPoolError::TransactProofVerificationFailed.into()
            }
        };
        store(&mut rpc, cache, cache_state);
        instruction.data = vec![tag::TRANSACT];
        instruction.data.extend(ix.serialize().unwrap());
        let before_tree = rpc.account_data(&tree).unwrap();
        reject(&mut rpc, instruction, error);
        assert_eq!(state(&rpc, &cache), cache_state);
        assert_eq!(rpc.account_data(&tree).unwrap(), before_tree);
    }
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
fn real_merge_writes_one_slot_and_binds_destination_and_slot() {
    for ring in [false, true] {
        for case in [
            "success",
            "slot",
            "destination",
            "tree",
            "owner",
            "owner_kind",
            "readonly",
            "alias",
            "mode",
            "missing",
            "extra",
            "unexpected",
        ] {
            let Pool {
                mut rpc,
                tree,
                authority,
                ..
            } = Pool::initialized();
            let output_tree = rpc.create_tree(&authority).unwrap();
            let v = vector(if ring { "merge_ring" } else { "merge" });
            let ring_program_id =
                Address::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID);
            if ring {
                rpc.load_ring_test_program().unwrap();
                rpc.create_activated_ring_config(&authority, &authority.pubkey(), &authority, true)
                    .unwrap();
            }
            for (address, id) in [(tree, 7u16), (output_tree, 11u16)] {
                let mut account = rpc.svm.get_account(&address).unwrap();
                let offset = tree_id_offset();
                account
                    .data
                    .get_mut(offset..offset + 2)
                    .unwrap()
                    .copy_from_slice(&id.to_le_bytes());
                if address == tree {
                    let mut loaded =
                        TreeAccount::from_bytes(&mut account.data, address.to_bytes()).unwrap();
                    loaded.utxo_tree().root_history[0] = bytes(&v["state_root"]);
                    loaded.nullifier_tree().root_history.roots[0] = bytes(&v["nullifier_root"]);
                }
                rpc.svm.set_account(address, account).unwrap();
            }
            let owner = Address::new_from_array(zolana_test_utils::transact::fe(42));
            let user_record = write_user_record(&mut rpc, owner, None, true);
            let cache = Address::new_from_array([if case == "destination" { 92 } else { 91 }; 32]);
            let mut expected = CacheAccount {
                discriminator: CACHE,
                bump: 0,
                frozen: 0,
                owner_kind: if ring { 1 } else { 0 },
                tree_id: (if case == "tree" { 7u16 } else { 11u16 }).to_le_bytes(),
                owner: if ring {
                    ring_program_id.to_bytes()
                } else {
                    owner.to_bytes()
                },
                operation_id: [0; 32],
                rent_sponsor: rpc.payer.pubkey().to_bytes(),
                close_authority: owner.to_bytes(),
                commitments: [[0; 32]; 36],
            };
            if case == "owner" {
                expected.owner = [8; 32];
            }
            if case == "owner_kind" {
                expected.owner_kind ^= 1;
            }
            rpc.svm
                .set_account(
                    cache,
                    solana_account::Account {
                        lamports: 100_000_000,
                        data: bytemuck::bytes_of(&expected).to_vec(),
                        owner: rpc.program_id,
                        executable: false,
                        rent_epoch: 0,
                    },
                )
                .unwrap();
            let data = MergeTransactIxData {
                cache_slot: if matches!(case, "mode" | "unexpected") {
                    None
                } else {
                    Some(if case == "slot" { 4 } else { 5 })
                },
                expiry_unix_ts: u64::MAX,
                proof: ProofCompressed::try_from(Proof {
                    a: bytes(&v["proof_a"]),
                    b: bytes(&v["proof_b"]),
                    c: bytes(&v["proof_c"]),
                    commitment: None,
                })
                .unwrap()
                .to_merge_proof()
                .unwrap(),
                output_utxo_hash: bytes(&v["output"]),
                eddsa_owner: true,
                private_tx_hash: bytes(&v["private_tx_hash"]),
                nullifiers: fields(&v, "nullifiers"),
                utxo_tree_root_index: 0,
                nullifier_tree_root_index: 0,
            };
            let mut ix = if ring {
                MergeRing {
                    input_tree: tree,
                    output_tree,
                    payer: rpc.payer.pubkey(),
                    ring_program_id,
                    data,
                    output_ring_data_hash: bytes(&v["output_ring_data_hash"]),
                }
                .instruction()
            } else {
                MergeTransact {
                    input_tree: tree,
                    output_tree,
                    payer: rpc.payer.pubkey(),
                    user_record,
                    data,
                }
                .instruction()
            };
            if !matches!(case, "mode" | "missing") {
                ix.accounts.push(if case == "readonly" {
                    AccountMeta::new_readonly(cache, false)
                } else {
                    AccountMeta::new(if case == "alias" { output_tree } else { cache }, false)
                });
            }
            if case == "extra" {
                ix.accounts
                    .push(AccountMeta::new_readonly(Address::new_unique(), false));
            }
            let before_input = rpc.account_data(&tree).unwrap();
            let before = rpc.account_data(&output_tree).unwrap();
            if case == "success" {
                rpc.create_and_send_default_payer_transaction(&[ix.clone()], &[])
                    .unwrap();
                expected.commitments[5] = bytes(&v["output"]);
                assert_eq!(state(&rpc, &cache), expected);
                let mut after = rpc.account_data(&output_tree).unwrap();
                let mut output =
                    TreeAccount::from_bytes(&mut after, output_tree.to_bytes()).unwrap();
                assert_eq!(
                    output.utxo_tree().next_index(),
                    1,
                    "merge still appends its output normally"
                );
                reject(&mut rpc, ix, ShieldedPoolError::CacheSlotOccupied);
            } else {
                reject(
                    &mut rpc,
                    ix,
                    match case {
                        "tree" => ShieldedPoolError::CacheTreeMismatch.into(),
                        "owner" | "owner_kind" => ShieldedPoolError::CacheOwnerMismatch.into(),
                        "readonly" => pinocchio::error::ProgramError::from(
                            zolana_account_checks::AccountError::AccountNotMutable,
                        ),
                        "alias" => ShieldedPoolError::InvalidCache.into(),
                        "missing" => pinocchio::error::ProgramError::from(
                            zolana_account_checks::AccountError::NotEnoughAccountKeys,
                        ),
                        "extra" | "unexpected" => ShieldedPoolError::InvalidMergeShape.into(),
                        _ => ShieldedPoolError::TransactProofVerificationFailed.into(),
                    },
                );
                assert_eq!(state(&rpc, &cache), expected);
                assert_eq!(rpc.account_data(&output_tree).unwrap(), before);
                assert_eq!(rpc.account_data(&tree).unwrap(), before_input);
            }
        }
    }
}

#[test]
fn mixed_spend_does_not_require_unselected_cache_slots() {
    let SpendFixture {
        mut rpc,
        cache,
        instruction,
        ..
    } = spend_fixture("mixed", false);
    let mut expected = state(&rpc, &cache);
    expected.commitments[1] = [0; 32];
    store(&mut rpc, cache, expected);
    rpc.create_and_send_default_payer_transaction(&[instruction], &[])
        .unwrap();
    expected.frozen = 1;
    assert_eq!(state(&rpc, &cache), expected);
}

#[test]
fn cache_cannot_alias_other_instruction_accounts() {
    for (account_index, error) in [
        (0, ShieldedPoolError::InvalidSettlementAccounts),
        (1, ShieldedPoolError::InvalidCache),
        (4, ShieldedPoolError::InvalidCache),
        (5, ShieldedPoolError::InvalidCache),
    ] {
        let SpendFixture {
            mut rpc,
            cache,
            mut instruction,
            tree,
            ..
        } = spend_fixture("all", false);
        let before = state(&rpc, &cache);
        let before_tree = rpc.account_data(&tree).unwrap();
        let alias = instruction
            .accounts
            .get(account_index)
            .expect("fixture account")
            .pubkey;
        instruction.accounts.last_mut().unwrap().pubkey = alias;
        reject(&mut rpc, instruction, error);
        assert_eq!(state(&rpc, &cache), before);
        assert_eq!(rpc.account_data(&tree).unwrap(), before_tree);
    }
}

#[test]
fn sol_withdrawal_to_cache_still_requires_a_valid_proof() {
    use zolana_interface::instruction::{
        InterfaceTransfer, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    };
    let SpendFixture {
        mut rpc,
        cache,
        instruction,
        mut ix,
        tree,
    } = spend_fixture("all", false);
    ix.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 1 }];
    let mut instruction = Transact {
        payer: rpc.payer.pubkey(),
        output_tree: instruction.accounts[1].pubkey,
        input_trees: vec![tree],
        owner_signers: vec![],
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts { recipient: cache },
        )],
        data: ix,
    }
    .instruction();
    instruction.accounts.push(AccountMeta::new(cache, false));
    let before = state(&rpc, &cache);
    let before_tree = rpc.account_data(&tree).unwrap();
    reject(
        &mut rpc,
        instruction,
        ShieldedPoolError::TransactProofVerificationFailed,
    );
    assert_eq!(state(&rpc, &cache), before);
    assert_eq!(rpc.account_data(&tree).unwrap(), before_tree);
}

#[test]
fn cached_input_selection_uses_global_offsets_across_tree_groups() {
    for (bitmap, error) in [
        (1, ShieldedPoolError::StaleNullifierRoot),
        (2, ShieldedPoolError::InvalidCacheRootIndex),
    ] {
        let SpendFixture {
            mut rpc,
            cache,
            instruction,
            mut ix,
            tree,
        } = spend_fixture("all", false);
        let second_tree = instruction.accounts[1].pubkey;
        ix.inputs[1].tree_index = 1;
        ix.circuit = CircuitId::ConfidentialEddsaCached(
            2,
            2,
            3,
            CachedInputs {
                input_bitmap: bitmap,
            },
        );
        ix.tree_contexts.push(TreeContext {
            utxo_tree_root_index: 1,
            nullifier_tree_root_index: 0,
        });
        let mut instruction = Transact {
            payer: rpc.payer.pubkey(),
            output_tree: second_tree,
            input_trees: vec![tree, second_tree],
            owner_signers: vec![],
            interface_transfer_accounts: vec![],
            data: ix,
        }
        .instruction();
        instruction.accounts.push(AccountMeta::new(cache, false));
        let before = state(&rpc, &cache);
        let before_tree = rpc.account_data(&tree).unwrap();
        let before_second_tree = rpc.account_data(&second_tree).unwrap();
        reject(&mut rpc, instruction, error);
        assert_eq!(state(&rpc, &cache), before);
        assert_eq!(rpc.account_data(&tree).unwrap(), before_tree);
        assert_eq!(rpc.account_data(&second_tree).unwrap(), before_second_tree);
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

#[test]
fn cached_transact_requires_exactly_one_trailing_cache() {
    for case in ["missing", "extra", "unexpected"] {
        let SpendFixture {
            mut rpc,
            cache,
            mut instruction,
            mut ix,
            tree,
        } = spend_fixture("all", false);
        match case {
            "missing" => {
                instruction.accounts.pop();
            }
            "extra" => instruction
                .accounts
                .push(AccountMeta::new_readonly(Address::new_unique(), false)),
            _ => {
                ix.circuit = CircuitId::ConfidentialEddsa(2, 2, 3);
                instruction.data = vec![tag::TRANSACT];
                instruction.data.extend(ix.serialize().unwrap());
            }
        }
        let before_cache = state(&rpc, &cache);
        let before_tree = rpc.account_data(&tree).unwrap();
        reject(
            &mut rpc,
            instruction,
            ShieldedPoolError::InvalidSettlementAccounts,
        );
        assert_eq!(state(&rpc, &cache), before_cache);
        assert_eq!(rpc.account_data(&tree).unwrap(), before_tree);
    }
}
