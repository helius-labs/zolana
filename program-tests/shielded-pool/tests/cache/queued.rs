//! All witnesses and proofs precede submission, including outputs that do not yet exist on chain.
use num_bigint::BigUint;
use shielded_pool_tests::support::transact::{proof_env, tree_progress, tree_roots};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    ClientError, ComputeBudgetConfig, Proof, ProverClient, PublicInputs, PublicTransfers,
    TransferInputs, STATE_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        CacheAccess, CacheWrite, CircuitId, CreateCacheData, InterfaceTransfer, TransactProof,
    },
    shape::Shape,
    state::{
        cache::{bind_cache_write, CacheAccount},
        read_tree_id,
    },
};
use zolana_keypair::{hash::owner_hash, NullifierKey, PublicKey};
use zolana_merkle_tree::indexed::IndexedMerkleTree;
use zolana_program::instruction::{
    CreateCache, Transact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
};
use zolana_program_test::{Rejection, ZolanaProgramTest};
use zolana_test_utils::transact::*;
use zolana_transaction::{instructions::transact::PrivateTxHash, Mint, Utxo};

type Step = (
    usize,
    &'static [(usize, usize)],
    &'static [(Option<usize>, u64)],
);

#[derive(Clone)]
struct Note {
    utxo: Utxo,
    hash: [u8; 32],
}

struct Owner {
    key: PublicKey,
    pk_hash: [u8; 32],
    nullifier_key: NullifierKey,
    nullifier_pk: [u8; 32],
    field: [u8; 32],
}

impl Owner {
    fn of(payer: Pubkey) -> Self {
        let key = PublicKey::from_ed25519(payer.as_array());
        let nullifier_key = NullifierKey::from_secret([21; 31]);
        let nullifier_pk = nullifier_key.pubkey().expect("nullifier public key");
        Self {
            key,
            pk_hash: key.owner_proof_input_hash().expect("owner pk hash"),
            field: owner_hash(&key, &nullifier_pk).expect("owner hash"),
            nullifier_key,
            nullifier_pk,
        }
    }
}

struct Tree {
    account: Pubkey,
    id: u16,
    state_root: [u8; 32],
    nullifier_root: [u8; 32],
}

impl Tree {
    fn read(rpc: &ZolanaProgramTest, account: Pubkey) -> Self {
        let id = read_tree_id(&rpc.account_data(&account).expect("tree")).expect("tree id");
        let (state_root, nullifier_root) = tree_roots(rpc, &account, 0);
        Self {
            account,
            id,
            state_root,
            nullifier_root,
        }
    }
}

struct StepSpec<'a> {
    index: usize,
    n_inputs: usize,
    reads: &'a [(usize, usize)],
    outputs: &'a [(Option<usize>, u64)],
    deposit: u64,
    input_tree: &'a Tree,
    output_tree: &'a Tree,
    write_cache: Option<Address>,
}

struct Prepared {
    builder: Transact,
    witness: TransferInputs,
    written: Vec<(usize, Note)>,
    unwritten: u64,
}

fn prepare(
    payer: Pubkey,
    owner: &Owner,
    nf_tree: &IndexedMerkleTree<Poseidon, usize>,
    spec: StepSpec<'_>,
    notes: &mut [Option<Note>],
) -> Prepared {
    let mut reads = vec![None; spec.n_inputs];
    let mut inputs = Vec::new();
    let mut nullifiers = Vec::new();
    let mut commitments = vec![[0; 32]; spec.n_inputs];
    for ((position, commitment), read) in commitments.iter_mut().enumerate().zip(&mut reads) {
        match spec.reads.iter().find(|(input, _)| *input == position) {
            Some((_, slot)) => {
                let note = notes
                    .get_mut(*slot)
                    .expect("slot")
                    .take()
                    .expect("unspent predecessor output");
                *commitment = note.hash;
                *read = Some((u8::try_from(*slot).expect("slot"), note.hash));
                let nullifier = owner
                    .nullifier_key
                    .nullifier(&note.hash, &note.utxo.blinding)
                    .expect("nullifier");
                let non_inclusion = nf_tree
                    .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
                    .expect("precomputed non-inclusion");
                inputs.push(
                    transfer_input(TransferInputArgs {
                        utxo: &note.utxo,
                        owner_field: &owner.field,
                        state_path: &vec![[0; 32]; STATE_TREE_HEIGHT],
                        state_path_index: 0,
                        non_inclusion: &non_inclusion,
                        tree_id: spec.input_tree.id,
                        nullifier: &nullifier,
                        owner_pk_hash: &owner.pk_hash,
                        nullifier_key: &owner.nullifier_key,
                    })
                    .expect("cached input"),
                );
                nullifiers.push(nullifier);
            }
            None => {
                let seed = u8::try_from(100 + spec.index * 4 + position).expect("dummy seed");
                let (input, nullifier) =
                    dummy_input(&[seed; 31], nf_tree, spec.input_tree.id).expect("dummy input");
                inputs.push(input);
                nullifiers.push(nullifier);
            }
        }
    }
    let first_nullifier = *nullifiers.first().expect("input");
    let mut outputs: Vec<_> = spec
        .outputs
        .iter()
        .map(|(_, amount)| real_output(owner.key, owner.nullifier_pk, Mint::SOL, *amount, [23; 31]))
        .collect();
    derive_test_output_blindings(&first_nullifier, &mut outputs).expect("derive future outputs");
    let hashes: Vec<_> = outputs
        .iter()
        .map(|output| output.hash(spec.output_tree.id).expect("output hash"))
        .collect();
    let mut witness_outputs: Vec<_> = outputs
        .iter()
        .map(|output| transfer_output(output, spec.output_tree.id).expect("output witness"))
        .collect();
    let (transfers, settlements, legs) = if spec.deposit != 0 {
        (
            vec![InterfaceTransfer::SolDeposit {
                amount: spec.deposit,
            }],
            vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient: payer },
            )],
            vec![sol_leg(&payer)],
        )
    } else {
        (vec![], vec![], vec![])
    };
    let mut data = new_transact_ix_data(
        nullifiers.iter().copied().map(input_utxo).collect(),
        0,
        transfers,
        inline_outputs(&hashes, &vec![payer.to_bytes(); outputs.len()]),
    );
    let pairs: Vec<_> = spec
        .outputs
        .iter()
        .enumerate()
        .filter_map(|(output, (slot, _))| {
            slot.map(|slot| CacheWrite {
                output: u8::try_from(output).expect("output"),
                slot: u8::try_from(slot).expect("slot"),
            })
        })
        .collect();
    let write_slots = cache_write_slots(&pairs).expect("cache writes");
    let selection = cache_read_selection(spec.input_tree.id, &reads).expect("cache reads");
    data.circuit = CircuitId::ConfidentialEddsaCached(
        spec.n_inputs as u8,
        outputs.len() as u8,
        3,
        CacheAccess {
            read_bitmap: selection.read_bitmap,
            write_slots,
        },
    );
    let owners = output_owner_pk_hashes(&data.outputs).expect("output owners");
    set_output_owner_tags(
        &mut witness_outputs,
        &owners,
        &vec![owner.nullifier_pk; outputs.len()],
    );
    let write_cache = spec.write_cache.map(|cache| cache.to_bytes());
    let external = bind_cache_write(
        external_data_hash(&data, &legs).expect("external data"),
        write_cache.as_ref().map(|cache| (cache, &write_slots)),
    )
    .expect("cache write binding");
    let private = PrivateTxHash::new(
        &commitments,
        &hashes,
        &external,
        &test_private_tx_blinding(&first_nullifier).expect("private blinding"),
    )
    .hash()
    .expect("private hash");
    data.private_tx_hash = private;
    let mut signers = vec![[0; 32]; Shape::new(spec.n_inputs, outputs.len()).signer_width()];
    *signers.first_mut().expect("payer") = owner.pk_hash;
    let tree_slots = single_tree_slots(
        spec.input_tree.id,
        spec.input_tree.state_root,
        spec.input_tree.nullifier_root,
    );
    let (assets, amounts) = sol_public_slots(fe(spec.deposit));
    let public = PublicInputs {
        nullifiers: &nullifiers,
        output_hashes: &hashes,
        tree_slots: &tree_slots,
        output_tree_id: spec.output_tree.id,
        private_tx: &private,
        external_data_hash: &external,
        public_transfers: &PublicTransfers { assets, amounts },
        ring_program_id: &[0; 32],
        input_flags: &fe(1),
        signer_pk_hashes: &signers,
        output_owner_pk_hashes: Some(&owners),
        cached_inputs: selection.public_fields,
    }
    .hash()
    .expect("public hash");
    let mut witness = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs,
        outputs: witness_outputs,
        tree_slots,
        output_tree_id: spec.output_tree.id,
        blinding_seed: TEST_BLINDING_SEED,
        external_data_hash: external,
        private_tx_hash: private,
        public_slot_assets: assets,
        public_slot_amounts: amounts,
        signer_pk_hashes: signers,
        public_input_hash: public,
    });
    witness.cache = selection.proof_inputs;
    let written = spec
        .outputs
        .iter()
        .zip(outputs)
        .zip(hashes)
        .filter_map(|(((slot, amount), output), hash)| {
            slot.map(|slot| {
                (
                    slot,
                    Note {
                        utxo: Utxo {
                            owner: owner.key,
                            asset: Mint::SOL,
                            amount: *amount,
                            blinding: output.blinding,
                            ring_program_id: None,
                            data: Default::default(),
                        },
                        hash,
                    },
                )
            })
        })
        .collect();
    let unwritten = spec
        .outputs
        .iter()
        .filter(|(slot, _)| slot.is_none())
        .map(|(_, amount)| amount)
        .sum();
    Prepared {
        builder: Transact {
            payer,
            input_trees: vec![spec.input_tree.account],
            output_tree: spec.output_tree.account,
            owner_signers: vec![],
            interface_transfer_accounts: settlements,
            data,
        },
        witness,
        written,
        unwritten,
    }
}

fn record_writes(
    notes: &mut [Option<Note>],
    expected: &mut CacheAccount,
    written: &[(usize, Note)],
) {
    for (slot, note) in written {
        assert!(
            notes
                .get(*slot)
                .expect("slot")
                .as_ref()
                .is_none_or(|note| note.utxo.amount == 0),
            "do not evict a delayed nonzero dependency"
        );
        *notes.get_mut(*slot).expect("slot") = Some(note.clone());
        *expected.utxo_hashes.get_mut(*slot).expect("slot") = note.hash;
    }
}

fn prove_with_backpressure(witness: &TransferInputs) -> Proof {
    let prover = ProverClient::local();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        match prover.prove_transfer(witness) {
            Ok(proof) => return proof,
            Err(ClientError::ProverServer(message))
                if message.starts_with("status 429 ") && std::time::Instant::now() < deadline =>
            {
                // The standalone test prover has bounded sync capacity and no
                // Redis queue. Retry admission only, without changing witnesses.
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(error) => panic!("prove queued transaction: {error}"),
        }
    }
}

fn cache_state(rpc: &ZolanaProgramTest, cache: Address) -> CacheAccount {
    *bytemuck::from_bytes(&rpc.account_data(&cache).expect("cache"))
}

fn create_cache(
    rpc: &mut ZolanaProgramTest,
    writer: &Keypair,
    nonce: u64,
    tree_id: u16,
) -> Address {
    let create = CreateCache {
        payer: rpc.payer.pubkey(),
        data: CreateCacheData {
            write_authority: writer.pubkey(),
            nonce,
            tree_id,
            expires_at: rpc.svm.get_sysvar::<solana_clock::Clock>().unix_timestamp + 3600,
        },
    };
    rpc.create_and_send_default_payer_transaction(&[create.instruction()], &[])
        .expect("create empty cache");
    create.cache()
}

fn send(rpc: &mut ZolanaProgramTest, ix: Instruction, writer: &Keypair) {
    let signers: Vec<&dyn Signer> = if ix
        .accounts
        .iter()
        .any(|meta| meta.is_signer && meta.pubkey == writer.pubkey())
    {
        vec![writer]
    } else {
        vec![]
    };
    rpc.create_and_send_default_payer_transaction_with_budget(
        &[ix],
        &signers,
        ComputeBudgetConfig::new(1_400_000),
    )
    .unwrap_or_else(|error| panic!("cached transaction failed: {error}"));
}

fn assert_rejected_atomically(
    rpc: &mut ZolanaProgramTest,
    ix: Instruction,
    writer: &Keypair,
    code: Option<u32>,
) {
    let before: Vec<_> = ix
        .accounts
        .iter()
        .filter(|meta| meta.is_writable && meta.pubkey != rpc.payer.pubkey())
        .map(|meta| (meta.pubkey, rpc.svm.get_account(&meta.pubkey)))
        .collect();
    rpc.svm.expire_blockhash();
    let signers: Vec<&dyn Signer> = if ix
        .accounts
        .iter()
        .any(|meta| meta.is_signer && meta.pubkey == writer.pubkey())
    {
        vec![writer]
    } else {
        vec![]
    };
    let error = rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &signers,
            ComputeBudgetConfig::new(1_400_000),
        )
        .expect_err("invalid queued transaction must fail");
    if let Some(code) = code {
        Rejection::custom(code).assert_litesvm(error);
    }
    for (address, account) in before {
        assert_eq!(
            rpc.svm.get_account(&address),
            account,
            "failed transaction changed {address}"
        );
    }
}

fn with_circuit(ix: &Instruction, edit: impl FnOnce(&mut CacheAccess)) -> Instruction {
    let mut ix = ix.clone();
    let mut data =
        zolana_interface::instruction::TransactIxData::deserialize(ix.data.get(1..).expect("body"))
            .expect("decode");
    if let CircuitId::ConfidentialEddsaCached(_, _, _, access) = &mut data.circuit {
        edit(access);
    }
    ix.data = std::iter::once(zolana_interface::instruction::tag::TRANSACT)
        .chain(data.serialize().expect("encode"))
        .collect();
    ix
}

#[test]
fn ten_proofs_in_parallel_then_sequential_splits_and_delayed_spends() {
    let mut pool = proof_env();
    let payer = pool.rpc.payer.pubkey();
    pool.rpc
        .airdrop(&zolana_interface::SOL_INTERFACE_PUBKEY, 1_000_000)
        .expect("fund SOL interface rent reserve");
    let writer = Keypair::new();
    pool.rpc
        .airdrop(&writer.pubkey(), 1_000_000)
        .expect("fund separate writer");
    let owner = Owner::of(payer);
    let cache = create_cache(&mut pool.rpc, &writer, 701, pool.tree_id);
    let other_cache = create_cache(&mut pool.rpc, &writer, 702, pool.tree_id);
    let initial_cache = cache_state(&pool.rpc, cache);
    let initial_progress = tree_progress(&pool.rpc, &pool.tree);
    let tree = Tree::read(&pool.rpc, pool.tree);
    let nf_tree = nullifier_tree().expect("nullifier tree");
    assert_eq!(nf_tree.root(), tree.nullifier_root);

    let steps: [Step; 11] = [
        (1, &[], &[(Some(0), 60), (Some(1), 40)]),
        (1, &[(0, 0)], &[(Some(2), 30), (Some(0), 30)]),
        (2, &[(1, 0)], &[(None, 0), (Some(0), 30)]),
        (
            3,
            &[(2, 1), (0, 2)],
            &[(Some(1), 70), (None, 0), (Some(3), 0)],
        ),
        (2, &[(0, 0), (1, 1)], &[(Some(0), 50), (Some(1), 50)]),
        (1, &[(0, 0)], &[(Some(20), 20), (Some(2), 30)]),
        (1, &[(0, 20)], &[(Some(0), 20)]),
        (
            3,
            &[(1, 1), (2, 2)],
            &[(Some(35), 80), (Some(2), 0), (Some(3), 0)],
        ),
        (2, &[(0, 35), (1, 0)], &[(Some(0), 75), (Some(1), 25)]),
        (2, &[(0, 0), (1, 1)], &[(Some(0), 90), (Some(1), 10)]),
        (2, &[(1, 1), (0, 0)], &[(None, 90), (None, 10)]),
    ];
    let mut notes: Vec<Option<Note>> = vec![None; 36];
    let mut expected = initial_cache;
    let mut prepared = Vec::new();
    let mut total_inputs = 0;
    let mut total_outputs = 0;
    let mut unwritten = 0;
    for (index, (n_inputs, reads, outputs)) in steps.into_iter().enumerate() {
        let writes = outputs.iter().any(|(slot, _)| slot.is_some());
        let step = prepare(
            payer,
            &owner,
            &nf_tree,
            StepSpec {
                index,
                n_inputs,
                reads,
                outputs,
                deposit: if index == 0 { 100 } else { 0 },
                input_tree: &tree,
                output_tree: &tree,
                write_cache: writes.then_some(cache),
            },
            &mut notes,
        );
        record_writes(&mut notes, &mut expected, &step.written);
        unwritten += step.unwritten;
        total_inputs += n_inputs as u64;
        total_outputs += outputs.len() as u64;
        prepared.push((
            step.builder,
            step.witness,
            !reads.is_empty(),
            writes,
            expected,
        ));
    }

    // No chain access in any proof task. A barrier makes all proving requests
    // concurrent; join every request before the first submission.
    let writer_address = writer.pubkey();
    let barrier = std::sync::Barrier::new(prepared.len());
    let proved: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = prepared
            .into_iter()
            .map(|(mut builder, witness, reads, writes, expected)| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    let proof = prove_with_backpressure(&witness);
                    builder.data.proof = pack_transact_proof(&proof).expect("pack proof");
                    let ix = match (reads, writes) {
                        (true, true) => {
                            builder.instruction_with_caches(cache, cache, writer_address)
                        }
                        (false, true) => {
                            builder.instruction_with_cache_write(cache, writer_address)
                        }
                        (true, false) => builder.instruction_with_cache_read(other_cache),
                        (false, false) => builder.instruction(),
                    };
                    (ix, expected)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("proof worker"))
            .collect()
    });
    assert_eq!(proved.len(), 11);
    assert_eq!(cache_state(&pool.rpc, cache), initial_cache);
    assert_eq!(tree_progress(&pool.rpc, &pool.tree), initial_progress);

    // A future transaction cannot spend a commitment before its predecessor writes it.
    assert_rejected_atomically(
        &mut pool.rpc,
        proved.get(3).expect("tx4").0.clone(),
        &writer,
        Some(ShieldedPoolError::CacheSlotEmpty as u32),
    );
    let first = &proved.first().expect("tx1").0;
    let mut missing_writer = first.clone();
    missing_writer.accounts.pop();
    assert_rejected_atomically(
        &mut pool.rpc,
        missing_writer,
        &writer,
        Some(ShieldedPoolError::InvalidSettlementAccounts as u32),
    );
    let mut extra_read_cache = first.clone();
    let tail = extra_read_cache.accounts.len() - 2;
    extra_read_cache.accounts.insert(
        tail,
        solana_instruction::AccountMeta::new_readonly(cache, false),
    );
    assert_rejected_atomically(
        &mut pool.rpc,
        extra_read_cache,
        &writer,
        Some(ShieldedPoolError::InvalidSettlementAccounts as u32),
    );
    let mut missing_read_cache = proved.get(1).expect("tx2").0.clone();
    let tail = missing_read_cache.accounts.len() - 3;
    missing_read_cache.accounts.remove(tail);
    assert_rejected_atomically(
        &mut pool.rpc,
        missing_read_cache,
        &writer,
        Some(ShieldedPoolError::InvalidSettlementAccounts as u32),
    );
    let mut unsigned_writer = first.clone();
    unsigned_writer
        .accounts
        .last_mut()
        .expect("writer")
        .is_signer = false;
    assert_rejected_atomically(
        &mut pool.rpc,
        unsigned_writer,
        &writer,
        Some(u32::from(
            zolana_account_checks::AccountError::InvalidSigner,
        )),
    );
    let mut wrong_writer = first.clone();
    wrong_writer.accounts.last_mut().expect("writer").pubkey = payer;
    assert_rejected_atomically(
        &mut pool.rpc,
        wrong_writer,
        &writer,
        Some(ShieldedPoolError::CacheWriteAuthorityMismatch as u32),
    );
    let mut wrong_destination = first.clone();
    wrong_destination
        .accounts
        .iter_mut()
        .find(|meta| meta.pubkey == cache)
        .expect("cache")
        .pubkey = other_cache;
    assert_rejected_atomically(
        &mut pool.rpc,
        wrong_destination,
        &writer,
        Some(ShieldedPoolError::TransactProofVerificationFailed as u32),
    );
    let tampers: [fn(&mut CacheAccess); 3] = [
        |access: &mut CacheAccess| {
            if let Some(entry) = access.write_slots.first_mut() {
                entry.slot = 5;
            }
        },
        |access: &mut CacheAccess| {
            if let Some(entry) = access.write_slots.first_mut() {
                entry.output = 1;
            }
            if let Some(entry) = access.write_slots.get_mut(1) {
                entry.output = 0;
            }
        },
        |access: &mut CacheAccess| {
            if let Some(entry) = access.write_slots.get_mut(1) {
                *entry = CacheWrite::NONE;
            }
        },
    ];
    for tamper in tampers {
        assert_rejected_atomically(
            &mut pool.rpc,
            with_circuit(first, tamper),
            &writer,
            Some(ShieldedPoolError::TransactProofVerificationFailed as u32),
        );
    }
    // The writer, expiry and tree are checked before the proof, so even an
    // instruction whose proof cannot verify fails with the cache's own error.
    let mut unprovable = first.clone();
    let mut data = zolana_interface::instruction::TransactIxData::deserialize(
        unprovable.data.get(1..).expect("body"),
    )
    .expect("decode");
    data.proof = TransactProof::zeroed();
    unprovable.data = std::iter::once(zolana_interface::instruction::tag::TRANSACT)
        .chain(data.serialize().expect("encode"))
        .collect();
    let mut unprovable_wrong_writer = unprovable.clone();
    unprovable_wrong_writer
        .accounts
        .last_mut()
        .expect("writer")
        .pubkey = payer;
    assert_rejected_atomically(
        &mut pool.rpc,
        unprovable_wrong_writer,
        &writer,
        Some(ShieldedPoolError::CacheWriteAuthorityMismatch as u32),
    );
    for (invalid, error) in [
        (
            CacheAccount {
                expires_at: 0i64.to_le_bytes(),
                ..initial_cache
            },
            ShieldedPoolError::CacheExpired,
        ),
        (
            CacheAccount {
                tree_id: pool.tree_id.wrapping_add(1).to_le_bytes(),
                ..initial_cache
            },
            ShieldedPoolError::CacheTreeMismatch,
        ),
    ] {
        let mut account = pool.rpc.svm.get_account(&cache).expect("cache");
        account.data = bytemuck::bytes_of(&invalid).to_vec();
        pool.rpc
            .svm
            .set_account(cache, account)
            .expect("change cache configuration");
        for instruction in [first, &unprovable] {
            assert_rejected_atomically(
                &mut pool.rpc,
                instruction.clone(),
                &writer,
                Some(error as u32),
            );
        }
    }
    let mut account = pool.rpc.svm.get_account(&cache).expect("cache");
    account.data = bytemuck::bytes_of(&initial_cache).to_vec();
    pool.rpc
        .svm
        .set_account(cache, account)
        .expect("restore cache configuration");
    let (read_only, writing) = proved.split_last().expect("read-only step");
    for (index, (instruction, expected)) in writing.iter().enumerate() {
        pool.rpc
            .create_and_send_default_payer_transaction_with_budget(
                std::slice::from_ref(instruction),
                &[&writer],
                ComputeBudgetConfig::new(1_400_000),
            )
            .unwrap_or_else(|error| panic!("queued tx {} failed: {error}", index + 1));
        assert_eq!(
            cache_state(&pool.rpc, cache),
            *expected,
            "full cache after tx {}",
            index + 1
        );
    }
    let mut copy = pool.rpc.svm.get_account(&other_cache).expect("other cache");
    copy.data = pool.rpc.svm.get_account(&cache).expect("cache").data;
    pool.rpc
        .svm
        .set_account(other_cache, copy)
        .expect("copy cache contents");
    let final_cache = cache_state(&pool.rpc, cache);
    send(&mut pool.rpc, read_only.0.clone(), &writer);
    assert_eq!(cache_state(&pool.rpc, cache), final_cache);
    assert_eq!(read_only.1, final_cache);
    assert_eq!(
        tree_progress(&pool.rpc, &pool.tree),
        (
            initial_progress.0 + total_outputs,
            initial_progress.1 + total_inputs
        )
    );
    assert_eq!(
        notes
            .iter()
            .flatten()
            .map(|note| note.utxo.amount)
            .sum::<u64>()
            + unwritten,
        100
    );
    assert_rejected_atomically(
        &mut pool.rpc,
        proved.first().expect("tx1").0.clone(),
        &writer,
        None,
    );
    assert_rejected_atomically(&mut pool.rpc, read_only.0.clone(), &writer, None);
}

#[test]
fn a_read_cache_and_a_write_cache_may_differ_in_tree_and_writer() {
    let mut pool = proof_env();
    let payer = pool.rpc.payer.pubkey();
    pool.rpc
        .airdrop(&zolana_interface::SOL_INTERFACE_PUBKEY, 1_000_000)
        .expect("fund SOL interface rent reserve");
    let writer_a = Keypair::new();
    let writer_b = Keypair::new();
    for writer in [&writer_a, &writer_b] {
        pool.rpc
            .airdrop(&writer.pubkey(), 1_000_000)
            .expect("fund writer");
    }
    let second_tree = pool
        .rpc
        .create_tree(&pool.authority)
        .expect("create the second tree");
    let tree_x = Tree::read(&pool.rpc, pool.tree);
    let tree_y = Tree::read(&pool.rpc, second_tree);
    assert_ne!(tree_x.id, tree_y.id);
    let owner = Owner::of(payer);
    let cache_a = create_cache(&mut pool.rpc, &writer_a, 801, tree_x.id);
    let cache_b = create_cache(&mut pool.rpc, &writer_b, 802, tree_y.id);
    let nf_tree = nullifier_tree().expect("nullifier tree");
    let mut notes_a: Vec<Option<Note>> = vec![None; 36];
    let mut notes_b: Vec<Option<Note>> = vec![None; 36];
    let mut expected_a = cache_state(&pool.rpc, cache_a);
    let mut expected_b = cache_state(&pool.rpc, cache_b);

    let deposit = prepare(
        payer,
        &owner,
        &nf_tree,
        StepSpec {
            index: 0,
            n_inputs: 1,
            reads: &[],
            outputs: &[(Some(3), 70), (Some(9), 30)],
            deposit: 100,
            input_tree: &tree_x,
            output_tree: &tree_x,
            write_cache: Some(cache_a),
        },
        &mut notes_a,
    );
    record_writes(&mut notes_a, &mut expected_a, &deposit.written);
    let mut builder = deposit.builder;
    builder.data.proof =
        pack_transact_proof(&prove_with_backpressure(&deposit.witness)).expect("pack proof");
    send(
        &mut pool.rpc,
        builder.instruction_with_cache_write(cache_a, writer_a.pubkey()),
        &writer_a,
    );
    assert_eq!(cache_state(&pool.rpc, cache_a), expected_a);

    let across = prepare(
        payer,
        &owner,
        &nf_tree,
        StepSpec {
            index: 1,
            n_inputs: 2,
            reads: &[(1, 9)],
            outputs: &[(Some(4), 30), (None, 0)],
            deposit: 0,
            input_tree: &tree_x,
            output_tree: &tree_y,
            write_cache: Some(cache_b),
        },
        &mut notes_a,
    );
    record_writes(&mut notes_b, &mut expected_b, &across.written);
    let mut builder = across.builder;
    builder.data.proof =
        pack_transact_proof(&prove_with_backpressure(&across.witness)).expect("pack proof");
    assert_rejected_atomically(
        &mut pool.rpc,
        builder.instruction_with_caches(cache_a, cache_b, writer_a.pubkey()),
        &writer_a,
        Some(ShieldedPoolError::CacheWriteAuthorityMismatch as u32),
    );
    assert_rejected_atomically(
        &mut pool.rpc,
        builder.instruction_with_caches(cache_a, cache_a, writer_a.pubkey()),
        &writer_a,
        Some(ShieldedPoolError::CacheTreeMismatch as u32),
    );
    assert_rejected_atomically(
        &mut pool.rpc,
        builder.instruction_with_cache_write(cache_b, writer_b.pubkey()),
        &writer_b,
        Some(ShieldedPoolError::InvalidSettlementAccounts as u32),
    );
    send(
        &mut pool.rpc,
        builder.instruction_with_caches(cache_a, cache_b, writer_b.pubkey()),
        &writer_b,
    );
    assert_eq!(cache_state(&pool.rpc, cache_a), expected_a);
    assert_eq!(cache_state(&pool.rpc, cache_b), expected_b);

    let back = prepare(
        payer,
        &owner,
        &nf_tree,
        StepSpec {
            index: 2,
            n_inputs: 1,
            reads: &[(0, 4)],
            outputs: &[(Some(10), 30)],
            deposit: 0,
            input_tree: &tree_y,
            output_tree: &tree_x,
            write_cache: Some(cache_a),
        },
        &mut notes_b,
    );
    record_writes(&mut notes_a, &mut expected_a, &back.written);
    let mut builder = back.builder;
    builder.data.proof =
        pack_transact_proof(&prove_with_backpressure(&back.witness)).expect("pack proof");
    send(
        &mut pool.rpc,
        builder.instruction_with_caches(cache_b, cache_a, writer_a.pubkey()),
        &writer_a,
    );
    assert_eq!(cache_state(&pool.rpc, cache_a), expected_a);
    assert_eq!(cache_state(&pool.rpc, cache_b), expected_b);
}
