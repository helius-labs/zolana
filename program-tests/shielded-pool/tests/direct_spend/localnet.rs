use anyhow::{anyhow, ensure, Result};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use std::time::{Duration, Instant};
use zolana_client::{
    prover::direct_spend as direct,
    prover::{ProofCompressed, ProveRequest},
    ClientError, MerkleContext, MerkleProof, ProverClient, Rpc, SolanaRpc, ZolanaIndexer,
};
use zolana_event_parser::indexed_events_from_instruction_groups;
use zolana_hasher::{primitives::solana_owner_identity, Hasher, Poseidon};
use zolana_interface::{
    direct_spend::{self as wire, field, Payload, Payment, PaymentInputs, PrepareCertificate},
    instruction::builders::{direct_spend as instructions, historical_nullifiers},
    verifying_keys::Bsb22Commitment,
    SHIELDED_POOL_PROGRAM_ID, SOL_ASSET_FIELD,
};
use zolana_keypair::{NullifierKey, ShieldedKeypair, ViewingKey};
use zolana_smart_account_client::execute_sync_ix;
use zolana_test_utils::{
    benchmark::{deposit_notes, restart_prover, BenchmarkConfig, NOTE_AMOUNT},
    harness::{BootstrapConfig, LocalnetHarness, ProtocolSetup},
    localnet::send_transaction,
    test_validator_asserts::{
        assert_transaction_compute_units, wait_for_indexed_transaction, wait_for_merkle_proofs,
        wait_for_non_inclusion_proofs,
    },
};
use zolana_transaction::ProofInputUtxo;
use zolana_tree::{
    nullifier_filter::{NullifierFilter, DEFAULT_BIT_BYTES},
    pending_nullifiers::PendingNullifiers,
    NullifierTreeInitParams,
};

const AMOUNT: u64 = NOTE_AMOUNT;

struct Fixture {
    rpc: SolanaRpc,
    indexer: ZolanaIndexer,
    owner: Keypair,
    recipient: ShieldedKeypair,
    tree: Pubkey,
    tree_address: Address,
    tree_id: u16,
    output_tree: Pubkey,
    output_tree_id: u16,
    notes: Vec<ProofInputUtxo>,
    inputs: Vec<direct::Input>,
    key: NullifierKey,
}

impl Fixture {
    fn new(count: usize, interleaved: bool, admitted: bool) -> Result<Self> {
        let config = BootstrapConfig {
            label: "zolana-direct-spend-bench",
            extra_programs: Vec::new(),
            ring_activation_is_permissionless: false,
            fund_merge_vault: false,
        };
        let (mut rpc, indexer) = LocalnetHarness::<()>::start_stack(&config)?;
        let setup = LocalnetHarness::<()>::setup_protocol_accounts(&mut rpc, &config)?;
        let input_params = NullifierTreeInitParams {
            input_queue_batch_size: 1_000,
            input_queue_zkp_batch_size: 10,
            height: 40,
        };
        let (tree, tree_address, tree_id) =
            LocalnetHarness::<()>::create_tree(&mut rpc, &setup, Some(input_params))?;
        let (output_tree, output_tree_id) = (tree, tree_id);

        let pending_size = PendingNullifiers::account_size(input_params.input_queue_batch_size)
            .ok_or_else(|| anyhow!("invalid pending-nullifier table size"))?;
        loop {
            let enable = instructions::enable_pending_nullifiers(
                setup.payer.pubkey(),
                setup.accounts.protocol_vault,
                tree,
            );
            let enable = execute_sync_ix(
                &setup.accounts.protocol_settings,
                0,
                &[setup.authority.pubkey()],
                &[enable],
            );
            send_transaction(
                &mut rpc,
                &[enable],
                &setup.payer.pubkey(),
                &[&setup.payer, &setup.authority],
            )?;
            let size = rpc
                .get_account(Address::new_from_array(
                    zolana_interface::pda::pending_nullifiers(&tree)
                        .0
                        .to_bytes(),
                ))?
                .ok_or_else(|| anyhow!("pending-nullifier table missing"))?
                .data
                .len();
            if size == pending_size {
                break;
            }
            if size > pending_size {
                return Err(anyhow!("pending-nullifier table grew beyond its target"));
            }
        }

        if admitted {
            allocate_filter(&rpc, &setup, tree)?;
        }

        let owner = setup.payer;
        let key = NullifierKey::from_secret([19; 31]);
        let owner_hash = Poseidon::hashv(&[
            &solana_owner_identity(&owner.pubkey().to_bytes())?,
            &key.pubkey()?,
        ])?;
        let notes = deposit_notes(&mut rpc, &owner, tree, owner_hash, count, interleaved)?
            .into_iter()
            .map(|output| {
                let note = ProofInputUtxo {
                    domain: field(3),
                    tree_id: field(tree_id.into()),
                    owner_hash,
                    asset: SOL_ASSET_FIELD,
                    amount: field(output.output.amount),
                    blinding: output.output.blinding,
                    data_hash: [0; 32],
                    ring_data_hash: [0; 32],
                    ring_program_id: [0; 32],
                };
                ensure!(
                    note.hash()? == output.utxo_hash,
                    "deposit output hash mismatch"
                );
                Ok(note)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            rpc,
            indexer,
            owner,
            recipient: ShieldedKeypair::new_ed25519()?,
            tree,
            tree_address,
            tree_id,
            output_tree,
            output_tree_id,
            notes,
            inputs: Vec::new(),
            key,
        })
    }

    fn resolve_inputs(&mut self) -> Result<(u128, u128)> {
        let hash_start = Instant::now();
        let notes = self
            .notes
            .iter()
            .cloned()
            .map(direct::InputNote::new)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let hashes = notes
            .iter()
            .map(direct::InputNote::commitment)
            .collect::<Vec<_>>();
        let hash_ms = hash_start.elapsed().as_millis();
        let fetch_start = Instant::now();
        let state_proofs = wait_for_merkle_proofs(&self.indexer, self.tree_address, &hashes);
        let fetch_ms = fetch_start.elapsed().as_millis();
        let context = MerkleContext {
            tree_type: 0,
            tree: Address::new_from_array(self.tree.to_bytes()),
        };
        self.inputs = notes
            .into_iter()
            .zip(state_proofs)
            .map(|(note, proof)| {
                note.with_proof(MerkleProof {
                    merkle_context: context.clone(),
                    ..proof
                })
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((hash_ms, fetch_ms))
    }

    fn payment(&self, inputs: PaymentInputs) -> Result<(Payment, Vec<direct::Output>)> {
        let recipient = self.recipient.pubkey().to_bytes();
        let nullifier_pk = self.recipient.nullifier_key.pubkey()?;
        let owner_hash =
            Poseidon::hashv(&[&solana_owner_identity(&recipient).unwrap(), &nullifier_pk]).unwrap();
        let outputs = [self.notes.len() as u64 * AMOUNT, 0]
            .into_iter()
            .map(|amount| direct::Output {
                note: ProofInputUtxo {
                    domain: field(3),
                    tree_id: field(self.output_tree_id.into()),
                    owner_hash,
                    asset: SOL_ASSET_FIELD,
                    amount: field(amount),
                    blinding: zolana_keypair::random_blinding(),
                    data_hash: [0; 32],
                    ring_data_hash: [0; 32],
                    ring_program_id: [0; 32],
                },
                nullifier_pk,
            })
            .collect::<Vec<_>>();
        let wallet_outputs = outputs
            .iter()
            .map(|output| zolana_transaction::SppProofOutputUtxo {
                asset: zolana_transaction::SOL_MINT,
                amount: u64::from_be_bytes(output.note.amount[24..].try_into().unwrap()),
                blinding: output.note.blinding,
                owner_address: Some(self.recipient.shielded_address().unwrap()),
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let viewing_key = ViewingKey::new();
        let encrypted =
            zolana_transaction::instructions::transact::slots::encrypt_transaction_data(
                &wallet_outputs,
                &zolana_transaction::AssetRegistry::default(),
                &viewing_key,
                self.output_tree_id,
            )?;
        let public = encrypted
            .outputs
            .iter()
            .zip(&encrypted.resolved_owner_tags)
            .map(|(output, tag)| wire::Output {
                recipient,
                utxo: zolana_interface::event::OutputUtxo {
                    view_tag: *tag,
                    utxo_hash: output.utxo_hash,
                    data: output.data.clone().unwrap(),
                },
            })
            .collect();
        Ok((
            Payment {
                inputs,
                output_tree: self.output_tree.to_bytes(),
                expiry_slot: u64::MAX,
                max_forester_fee: 0,
                outputs: public,
                tx_viewing_pk: *viewing_key.pubkey().as_bytes(),
                salt: encrypted.salt,
            },
            outputs,
        ))
    }
}

fn allocate_filter(rpc: &SolanaRpc, setup: &ProtocolSetup, tree: Pubkey) -> Result<()> {
    let filter_size = NullifierFilter::account_size(DEFAULT_BIT_BYTES).unwrap();
    let allocations = filter_size.div_ceil(zolana_interface::state::TREE_ALLOCATION_STEP);
    let concurrency = std::env::var("E2E_BENCH_SETUP_CONCURRENCY")
        .map_or(Ok(8), |value| value.parse::<usize>())?;
    ensure!(
        (1..=32).contains(&concurrency),
        "setup concurrency must be within 1..32"
    );
    let interval = confirmation_interval()?.unwrap_or(Duration::from_millis(250));
    let enable = historical_nullifiers::enable_nullifier_filter(
        setup.payer.pubkey(),
        setup.accounts.protocol_vault,
        tree,
    );
    let instructions = [execute_sync_ix(
        &setup.accounts.protocol_settings,
        0,
        &[setup.authority.pubkey()],
        &[enable],
    )];
    let signers: [&dyn Signer; 2] = [&setup.payer, &setup.authority];
    let budget = |allocation: usize| {
        // Distinct headers prevent replaying an earlier allocation's signature.
        zolana_client::ComputeBudgetConfig::new(1_400_000 - allocation as u32)
            .with_heap_size(256 * 1024)
    };
    send_instructions(
        rpc,
        setup.payer.pubkey(),
        &signers,
        &instructions,
        budget(0),
    )?;
    for start in (1..allocations).step_by(concurrency) {
        let (blockhash, _) = rpc.get_latest_blockhash()?;
        let mut signatures = Vec::with_capacity(concurrency);
        for allocation in start..(start + concurrency).min(allocations) {
            let transaction = zolana_client::sign_transaction(
                zolana_client::compile_message(
                    &setup.payer.pubkey(),
                    &instructions,
                    blockhash,
                    budget(allocation),
                )?,
                &signers,
            )?;
            let signature = send_signed(rpc, &transaction)?;
            signatures.push(signature);
        }
        for signature in signatures {
            rpc.wait_for_signature_with_interval(&signature, interval)?;
        }
    }
    let filter = zolana_interface::pda::nullifier_filter(&tree).0;
    let mut account = rpc
        .get_account(Address::new_from_array(filter.to_bytes()))?
        .ok_or_else(|| anyhow!("nullifier filter missing"))?;
    ensure!(
        account.data.len() == filter_size,
        "nullifier filter allocation incomplete"
    );
    ensure!(
        NullifierFilter::from_bytes(&mut account.data, &tree.to_bytes())?.next_sequence() == 1,
        "new filter already contains spent notes"
    );
    println!("BENCH_FILTER_SETUP transactions={allocations} concurrency={concurrency}");
    Ok(())
}

fn confirmation_interval() -> Result<Option<Duration>> {
    std::env::var("E2E_BENCH_POLL_MS")
        .ok()
        .map(|value| {
            let millis = value.parse::<u64>()?;
            ensure!(millis > 0, "confirmation poll interval must be positive");
            Ok(Duration::from_millis(millis))
        })
        .transpose()
}

fn prove_compressed(request: &impl ProveRequest) -> Result<ProofCompressed> {
    let url =
        std::env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| "http://127.0.0.1:3001".to_owned());
    let proof = ProverClient::new(url).prove(request)?;
    Ok(ProofCompressed::try_from(proof)?)
}

fn prove(request: &impl ProveRequest) -> Result<wire::Proof> {
    Ok(prove_compressed(request)?.try_into()?)
}

struct Chunk {
    nonce: [u8; 32],
    plan: direct::CertificatePlan,
    root: wire::Root,
    freshness: direct::Request,
}

fn chunks(fixture: &Fixture) -> Result<(Vec<Chunk>, u128)> {
    let mut plans = Vec::new();
    for start in (0..fixture.inputs.len()).step_by(wire::CERTIFICATE_INPUTS) {
        let end = (start + wire::CERTIFICATE_INPUTS).min(fixture.inputs.len());
        let nonce = field(start as u64 + 1);
        let buffer = instructions::spend_buffer(&fixture.owner.pubkey(), &nonce);
        let plan = direct::certificate(
            fixture.owner.pubkey().to_bytes(),
            buffer.to_bytes(),
            fixture.tree.to_bytes(),
            fixture.tree_id,
            &fixture.key,
            &fixture.inputs[start..end],
            field(start as u64 + 23),
            wire::CERTIFICATE_INPUTS,
        )?;
        plans.push((nonce, plan));
    }
    let nullifiers = plans
        .iter()
        .flat_map(|(_, plan)| plan.statement.nullifiers.iter().copied())
        .collect::<Vec<_>>();
    let fetch_start = Instant::now();
    let proofs = wait_for_non_inclusion_proofs(&fixture.indexer, fixture.tree_address, &nullifiers);
    let fetch_ms = fetch_start.elapsed().as_millis();
    let mut offset = 0;
    let chunks = plans
        .into_iter()
        .map(|(nonce, plan)| {
            let end = offset + plan.statement.nullifiers.len();
            let (root, freshness) = direct::freshness(
                &plan.statement,
                fixture.tree_id,
                &proofs[offset..end],
                wire::CERTIFICATE_INPUTS,
            )?;
            offset = end;
            Ok(Chunk {
                nonce,
                plan,
                root,
                freshness,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((chunks, fetch_ms))
}

fn prove_many(requests: &[&direct::Request], concurrency: usize) -> Result<Vec<wire::Proof>> {
    let mut proofs = Vec::with_capacity(requests.len());
    for batch in requests.chunks(concurrency) {
        let results = std::thread::scope(|scope| {
            let handles = batch
                .iter()
                .map(|request| scope.spawn(move || prove(*request)))
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| anyhow!("prover worker panicked"))?
                })
                .collect::<Result<Vec<_>>>()
        })?;
        proofs.extend(results);
    }
    Ok(proofs)
}

fn send_batch(
    fixture: &mut Fixture,
    instructions: &[solana_instruction::Instruction],
) -> Result<solana_signature::Signature> {
    send_instructions(
        &fixture.rpc,
        fixture.owner.pubkey(),
        &[&fixture.owner],
        instructions,
        direct::COMPUTE_BUDGET,
    )
}

fn send_instructions(
    rpc: &SolanaRpc,
    payer: Pubkey,
    signers: &[&dyn Signer],
    instructions: &[solana_instruction::Instruction],
    budget: zolana_client::ComputeBudgetConfig,
) -> Result<solana_signature::Signature> {
    let signature = if let Some(interval) = confirmation_interval()? {
        let (blockhash, _) = rpc.get_latest_blockhash()?;
        let transaction = zolana_client::sign_transaction(
            zolana_client::compile_message(&payer, instructions, blockhash, budget)?,
            signers,
        )?;
        let signature = send_signed(rpc, &transaction)?;
        rpc.wait_for_signature_with_interval(&signature, interval)?;
        signature
    } else {
        rpc.create_and_send_transaction(instructions, payer, signers, budget)?
    };
    Ok(signature)
}

fn send_signed(
    rpc: &SolanaRpc,
    transaction: &solana_transaction::versioned::VersionedTransaction,
) -> Result<solana_signature::Signature> {
    for attempt in 0..=4 {
        match rpc.send_transaction_with_config(
            transaction,
            zolana_client::RpcSendTransactionConfig {
                preflight_commitment: Some(rpc.client().commitment().commitment),
                ..Default::default()
            },
        ) {
            Ok(signature) => return Ok(signature),
            Err(ClientError::SolanaRpcTransaction { ref source, .. })
                if attempt < 4
                    && source.get_transaction_error() == Some(TransactionError::AccountInUse) =>
            {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error.into()),
        }
    }
    unreachable!()
}

fn certificate_batches(
    fixture: &Fixture,
    chunks: &[Chunk],
    proofs: &[wire::Proof],
) -> Result<Vec<Vec<solana_instruction::Instruction>>> {
    let mut batches = Vec::new();
    for (chunk, pair) in chunks.iter().zip(proofs.chunks_exact(2)) {
        let owner = fixture.owner.pubkey();
        let buffer = instructions::spend_buffer(&owner, &chunk.nonce);
        let mut batch = instructions::upload_spend(
            owner,
            chunk.nonce,
            &Payload::Certificate {
                statement: chunk.plan.statement.clone(),
                proof: pair[0].clone(),
            },
        )
        .map_err(|error| anyhow!(error))?;
        batch.push(instructions::prepare_certificate(
            owner,
            buffer,
            fixture.tree,
            &PrepareCertificate {
                freshness: chunk.root,
                proof: pair[1].clone(),
            },
        ));
        batches.push(batch);
    }
    Ok(batches)
}

fn submit_batches(
    fixture: &mut Fixture,
    batches: Vec<Vec<solana_instruction::Instruction>>,
) -> Result<Vec<solana_signature::Signature>> {
    pack_batches(fixture, batches)?
        .into_iter()
        .map(|batch| send_batch(fixture, &batch))
        .collect()
}

fn pack_batches(
    fixture: &Fixture,
    batches: Vec<Vec<solana_instruction::Instruction>>,
) -> Result<Vec<Vec<solana_instruction::Instruction>>> {
    let mut packed: Vec<Vec<solana_instruction::Instruction>> = Vec::new();
    for batch in batches {
        let mut combined = packed.last().cloned().unwrap_or_default();
        combined.extend_from_slice(&batch);
        let fits = zolana_client::transaction_size(
            &fixture.owner.pubkey(),
            &combined,
            direct::COMPUTE_BUDGET,
        )?
        .fits();
        if fits && !packed.is_empty() {
            *packed.last_mut().unwrap() = combined;
        } else {
            anyhow::ensure!(
                zolana_client::transaction_size(
                    &fixture.owner.pubkey(),
                    &batch,
                    direct::COMPUTE_BUDGET
                )?
                .fits(),
                "instruction group exceeds transaction limits"
            );
            packed.push(batch);
        }
    }
    for batch in &packed {
        let size = zolana_client::transaction_size(
            &fixture.owner.pubkey(),
            &batch,
            direct::COMPUTE_BUDGET,
        )?;
        println!(
            "packed transaction: {} bytes, {} addresses",
            size.bytes, size.addresses
        );
    }
    Ok(packed)
}

fn start_chunked_upload(
    fixture: &mut Fixture,
    upload: &instructions::SpendUpload,
    concurrency: usize,
) -> Result<(Vec<solana_signature::Signature>, u128)> {
    let mut batches = vec![upload.allocate_chunked()];
    batches.extend(upload.start_chunks().into_iter().map(|chunk| vec![chunk]));
    let mut packed = pack_batches(fixture, batches)?;
    let started = Instant::now();
    let mut signatures = vec![send_batch(fixture, &packed.remove(0))?];
    let allocation_ms = started.elapsed().as_millis();
    signatures.extend(submit_parallel_batches(fixture, packed, concurrency)?);
    Ok((signatures, allocation_ms))
}

fn submit_parallel_batches(
    fixture: &Fixture,
    packed: Vec<Vec<solana_instruction::Instruction>>,
    concurrency: usize,
) -> Result<Vec<solana_signature::Signature>> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let next = AtomicUsize::new(0);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        for _ in 0..concurrency.min(packed.len()) {
            let sender = sender.clone();
            let (next, packed, rpc, owner) = (&next, &packed, &fixture.rpc, &fixture.owner);
            scope.spawn(move || loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(batch) = packed.get(index) else {
                    break;
                };
                let result =
                    send_instructions(rpc, owner.pubkey(), &[owner], batch, direct::COMPUTE_BUDGET);
                if sender.send((index, result)).is_err() {
                    break;
                }
            });
        }
        drop(sender);
        let mut results = receiver.into_iter().collect::<Vec<_>>();
        results.sort_by_key(|(index, _)| *index);
        ensure!(
            results.len() == packed.len(),
            "upload worker did not finish"
        );
        results.into_iter().map(|(_, result)| result).collect()
    })
}

struct Timing {
    started: Instant,
    witness_ms: u128,
    input_hash_ms: u128,
    witness_stages: WitnessStages,
    membership_fetch_ms: u128,
    nullifier_fetch_ms: u128,
    preparation_ms: u128,
    certificate_prove_ms: u128,
    prove_ms: u128,
    submit_ms: u128,
    prefix_upload_ms: u128,
    allocation_ms: u128,
    chunked: bool,
    overlap: bool,
    confirmed_ms: u128,
    proofs: usize,
}

#[derive(Default, serde::Serialize)]
struct WitnessStages {
    certificate_ms: u128,
    output_ms: u128,
    balance_ms: u128,
    fusion_ms: u128,
}

struct Spend {
    timing: Timing,
    outputs: Vec<direct::Output>,
    signatures: Vec<solana_signature::Signature>,
    preparation_signatures: Vec<solana_signature::Signature>,
}

fn spend(fixture: &mut Fixture, mode: &str, concurrency: usize, prepared: bool) -> Result<Spend> {
    let started = Instant::now();
    let (input_hash_ms, membership_fetch_ms) = fixture.resolve_inputs()?;
    let owner = fixture.owner.pubkey();
    let nonce = zolana_keypair::random_blinding();
    let buffer = instructions::spend_buffer(&owner, &nonce);
    if mode == "gkr" || mode.starts_with("admitted") {
        let admitted = mode != "gkr";
        let dag = mode == "admitted-dag10";
        ensure!(
            !prepared,
            "GKR is a fused payment and cannot use prepared certificates"
        );
        let capacity = if !dag && fixture.inputs.len() <= 144 {
            144
        } else {
            512
        };
        let stage = Instant::now();
        let plan = direct::certificate(
            owner.to_bytes(),
            buffer.to_bytes(),
            fixture.tree.to_bytes(),
            fixture.tree_id,
            &fixture.key,
            &fixture.inputs,
            zolana_keypair::random_blinding(),
            capacity,
        )?;
        let mut witness_stages = WitnessStages {
            certificate_ms: stage.elapsed().as_millis(),
            ..Default::default()
        };
        let (root, freshness, nullifier_fetch_ms) = if admitted {
            (
                wire::Root {
                    index: 0,
                    value: [0; 32],
                },
                None,
                0,
            )
        } else {
            let fetch_start = Instant::now();
            let nips = wait_for_non_inclusion_proofs(
                &fixture.indexer,
                fixture.tree_address,
                &plan.statement.nullifiers,
            );
            let fetch_ms = fetch_start.elapsed().as_millis();
            let (root, request) =
                direct::freshness(&plan.statement, fixture.tree_id, &nips, capacity)?;
            (root, Some(request), fetch_ms)
        };
        let stage = Instant::now();
        let (payment, outputs) = fixture.payment(PaymentInputs::Notes {
            certificate: plan.statement,
            freshness: root,
        })?;
        witness_stages.output_ms = stage.elapsed().as_millis();
        let stage = Instant::now();
        let balance = direct::balance(
            &payment,
            owner.to_bytes(),
            buffer.to_bytes(),
            fixture.output_tree_id,
            &[&plan.opening],
            &outputs,
            1,
        )?;
        witness_stages.balance_ms = stage.elapsed().as_millis();
        let stage = Instant::now();
        let request = if let Some(freshness) = freshness {
            direct::payment(
                plan.request,
                freshness,
                balance,
                &payment,
                owner.to_bytes(),
                buffer.to_bytes(),
                fixture.tree_id,
                fixture.output_tree_id,
                &plan.opening,
            )?
            .with_gkr()?
        } else if dag {
            direct::admitted_dag_payment(
                plan.request,
                balance,
                &payment,
                owner.to_bytes(),
                buffer.to_bytes(),
                fixture.tree_id,
                fixture.output_tree_id,
                &plan.opening,
                &fixture.inputs,
            )?
        } else {
            direct::admitted_payment(
                plan.request,
                balance,
                &payment,
                owner.to_bytes(),
                buffer.to_bytes(),
                fixture.tree_id,
                fixture.output_tree_id,
                &plan.opening,
            )?
        };
        witness_stages.fusion_ms = stage.elapsed().as_millis();
        let witness_ms = started.elapsed().as_millis();
        let overlap = std::env::var("E2E_BENCH_OVERLAP").as_deref() != Ok("0");
        let chunked = std::env::var("E2E_BENCH_CHUNKED").as_deref() != Ok("0");
        let payload = |statement, proof, commitment| {
            if dag {
                Payload::DagPayment {
                    statement,
                    proof,
                    commitment,
                    inputs: capacity as u16,
                }
            } else if admitted {
                Payload::AdmittedPayment {
                    statement,
                    proof,
                    commitment,
                    inputs: capacity as u16,
                }
            } else {
                Payload::GkrPayment {
                    statement,
                    proof,
                    commitment,
                    inputs: capacity as u16,
                }
            }
        };
        let staged_payload = payload(
            payment.clone(),
            wire::Proof {
                a: [0; 32],
                b: [0; 128],
                c: [0; 32],
            },
            Bsb22Commitment {
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
        );
        let upload = instructions::SpendUpload::new(owner, nonce, &staged_payload)
            .map_err(|error| anyhow!(error))?;
        let (proof, prove_ms, prefix_upload_ms, allocation_ms, mut signatures) =
            std::thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    let start = Instant::now();
                    let proof = prove_compressed(&request)?;
                    Ok::<_, anyhow::Error>((proof, start.elapsed().as_millis()))
                });
                let start = Instant::now();
                let mut signatures = Vec::new();
                let mut allocation_ms = 0;
                if overlap && chunked {
                    (signatures, allocation_ms) =
                        start_chunked_upload(fixture, &upload, concurrency)?;
                } else if overlap {
                    signatures = submit_batches(
                        fixture,
                        upload.start().into_iter().map(|ix| vec![ix]).collect(),
                    )?;
                }
                let prefix_upload_ms = start.elapsed().as_millis();
                let (proof, prove_ms) = worker
                    .join()
                    .map_err(|_| anyhow!("prover worker panicked"))??;
                Ok::<_, anyhow::Error>((
                    proof,
                    prove_ms,
                    prefix_upload_ms,
                    allocation_ms,
                    signatures,
                ))
            })?;
        let commitment = proof
            .commitment
            .ok_or_else(|| anyhow!("GKR proof has no commitment"))?;
        let submit_start = Instant::now();
        let payload = payload(
            payment,
            wire::Proof {
                a: proof.a,
                b: proof.b,
                c: proof.c,
            },
            Bsb22Commitment {
                commitment: commitment.commitment,
                commitment_pok: commitment.commitment_pok,
            },
        );
        let mut allocation_ms = allocation_ms;
        if chunked && !overlap {
            let (uploaded, elapsed) = start_chunked_upload(fixture, &upload, concurrency)?;
            signatures.extend(uploaded);
            allocation_ms = elapsed;
        }
        let mut batch = if chunked {
            upload.finish_chunks(&payload)
        } else if overlap {
            upload.finish(&payload)
        } else {
            instructions::upload_spend(owner, nonce, &payload)
        }
        .map_err(|error| anyhow!(error))?;
        let mut commit =
            instructions::commit_spend(owner, buffer, fixture.tree, fixture.output_tree, &[]);
        if admitted {
            historical_nullifiers::use_nullifier_filter(&mut commit, &fixture.tree)
                .map_err(|error| anyhow!(error))?;
        }
        batch.push(commit);
        signatures.extend(submit_batches(
            fixture,
            batch.into_iter().map(|ix| vec![ix]).collect(),
        )?);
        return Ok(Spend {
            timing: Timing {
                started,
                witness_ms,
                input_hash_ms,
                witness_stages,
                membership_fetch_ms,
                nullifier_fetch_ms,
                prove_ms,
                submit_ms: submit_start.elapsed().as_millis(),
                prefix_upload_ms,
                allocation_ms,
                chunked,
                overlap,
                confirmed_ms: started.elapsed().as_millis(),
                preparation_ms: 0,
                certificate_prove_ms: 0,
                proofs: 1,
            },
            outputs,
            signatures,
            preparation_signatures: Vec::new(),
        });
    }

    let (chunks, nullifier_fetch_ms) = chunks(fixture)?;
    let certificate_requests = chunks
        .iter()
        .flat_map(|chunk| [&chunk.plan.request, &chunk.freshness])
        .collect::<Vec<_>>();
    let certificates = chunks
        .iter()
        .map(|chunk| instructions::spend_buffer(&owner, &chunk.nonce))
        .collect::<Vec<_>>();
    let (payment, outputs) = fixture.payment(PaymentInputs::Certificates(
        certificates.iter().map(|key| key.to_bytes()).collect(),
    ))?;
    let request = direct::balance(
        &payment,
        owner.to_bytes(),
        buffer.to_bytes(),
        fixture.output_tree_id,
        &chunks
            .iter()
            .map(|chunk| &chunk.plan.opening)
            .collect::<Vec<_>>(),
        &outputs,
        wire::MAX_CERTIFICATES,
    )?;
    let witness_ms = started.elapsed().as_millis();
    let mut preparation_ms = 0;
    let mut certificate_prove_ms = 0;
    let mut preparation_signatures = Vec::new();
    if prepared {
        let start = Instant::now();
        let proofs = prove_many(&certificate_requests, concurrency)?;
        certificate_prove_ms = start.elapsed().as_millis();
        let batches = certificate_batches(fixture, &chunks, &proofs)?;
        preparation_signatures = submit_batches(fixture, batches)?;
        preparation_ms = start.elapsed().as_millis();
    }
    let mut requests = if prepared {
        Vec::new()
    } else {
        certificate_requests
    };
    requests.push(&request);
    let proof_start = Instant::now();
    let mut proofs = prove_many(&requests, concurrency)?;
    let prove_ms = proof_start.elapsed().as_millis();
    let payment_proof = proofs.pop().unwrap();
    let submit_start = Instant::now();
    let mut batches = if prepared {
        Vec::new()
    } else {
        certificate_batches(fixture, &chunks, &proofs)?
    };
    let mut batch = instructions::upload_spend(
        owner,
        nonce,
        &Payload::Payment {
            statement: payment,
            proof: payment_proof,
        },
    )
    .map_err(|error| anyhow!(error))?;
    batch.push(instructions::commit_spend(
        owner,
        buffer,
        fixture.tree,
        fixture.output_tree,
        &certificates,
    ));
    batches.push(batch);
    let signatures = submit_batches(fixture, batches)?;
    Ok(Spend {
        timing: Timing {
            started,
            witness_ms,
            input_hash_ms,
            witness_stages: WitnessStages::default(),
            membership_fetch_ms,
            nullifier_fetch_ms,
            preparation_ms,
            certificate_prove_ms,
            prove_ms,
            submit_ms: submit_start.elapsed().as_millis(),
            prefix_upload_ms: 0,
            allocation_ms: 0,
            chunked: false,
            overlap: false,
            confirmed_ms: started.elapsed().as_millis(),
            proofs: chunks.len() * 2 + 1,
        },
        outputs,
        signatures,
        preparation_signatures,
    })
}

struct Observation {
    visible_ms: u128,
    indexer_ms: u128,
    decrypt_ms: u128,
    transaction_cu: Vec<u64>,
}

fn observe(fixture: &mut Fixture, spend: &Spend) -> Result<Observation> {
    let inputs = fixture.notes.len();
    let signature = *spend.signatures.last().unwrap();
    let indexer_start = Instant::now();
    let indexed = wait_for_indexed_transaction(
        &fixture.indexer,
        fixture.recipient.signing_pubkey().confidential_view_tag()?,
        signature,
    );
    let indexer_ms = indexer_start.elapsed().as_millis();
    let decrypt_start = Instant::now();
    let balances = zolana_transaction::decrypt_transactions(
        &fixture.recipient,
        std::slice::from_ref(&indexed),
        &zolana_transaction::AssetRegistry::default(),
    )?;
    assert_eq!(
        balances
            .get_balance(zolana_transaction::SOL_MINT)
            .map(|balance| balance.amount),
        Some(inputs as u64 * AMOUNT)
    );
    let decrypt_ms = decrypt_start.elapsed().as_millis();
    let visible_ms = spend.timing.started.elapsed().as_millis();
    let transaction_cu = spend
        .preparation_signatures
        .iter()
        .chain(&spend.signatures)
        .map(|signature| {
            assert_transaction_compute_units(&fixture.rpc, signature, "packed spend", 1_400_000)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let groups = fixture.rpc.fetch_confirmed_instruction_groups(&signature)?;
    let events = indexed_events_from_instruction_groups(
        Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        &groups.groups,
    );
    let events = events
        .iter()
        .map(|event| event.decoded.as_ref().map_err(|error| anyhow!("{error:?}")))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(
        events.iter().map(|event| event.inputs.len()).sum::<usize>(),
        inputs
    );
    assert_eq!(
        events
            .iter()
            .map(|event| event.outputs.len())
            .sum::<usize>(),
        2
    );
    let output_hashes = spend
        .outputs
        .iter()
        .map(|output| output.note.hash())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let indexed = wait_for_merkle_proofs(
        &fixture.indexer,
        Address::new_from_array(fixture.output_tree.to_bytes()),
        &output_hashes,
    );
    assert_eq!(indexed.len(), 2);
    Ok(Observation {
        visible_ms,
        indexer_ms,
        decrypt_ms,
        transaction_cu,
    })
}

fn report(
    config: &BenchmarkConfig,
    mode: &str,
    run: usize,
    phase: &str,
    prepared: bool,
    setup_ms: u128,
    warmup_ms: u128,
    result: &Spend,
    observation: &Observation,
) {
    let timing = &result.timing;
    let transaction_cu = &observation.transaction_cu;
    println!(
        "E2E_PIPELINE {}",
        serde_json::json!({
            "variant": mode, "run": run, "phase": phase, "inputs": config.inputs,
            "concurrency": config.concurrency, "layout": config.layout(), "prepared": prepared,
        "gomaxprocs": config.gomaxprocs, "prover_concurrency": config.prover_concurrency,
            "warm_keys": config.warm_keys && phase == "measured", "warmup_ms": warmup_ms,
            "key_state": if config.warm_keys && phase == "measured" { "warm" } else { "cold" },
            "poll_ms": std::env::var("E2E_BENCH_POLL_MS").ok(),
            "indexer_poll_ms": std::env::var("E2E_BENCH_INDEXER_POLL_MS").ok(),
            "setup_ms": setup_ms, "witness_ms": timing.witness_ms, "preparation_ms": timing.preparation_ms,
            "membership_fetch_ms": timing.membership_fetch_ms,
            "input_hash_ms": timing.input_hash_ms, "witness_stages": timing.witness_stages,
            "nullifier_fetch_ms": timing.nullifier_fetch_ms,
            "witness_local_ms": timing.witness_ms.saturating_sub(timing.membership_fetch_ms + timing.nullifier_fetch_ms),
            "certificate_prove_ms": timing.certificate_prove_ms, "prove_ms": timing.prove_ms,
            "submit_ms": timing.submit_ms, "prefix_upload_ms": timing.prefix_upload_ms,
            "allocation_ms": timing.allocation_ms, "chunked": timing.chunked,
            "overlap": timing.overlap, "confirmed_ms": timing.confirmed_ms,
            "recipient_indexer_ms": observation.indexer_ms, "recipient_decrypt_ms": observation.decrypt_ms,
            "indexed_ms": observation.visible_ms, "total_ms": observation.visible_ms, "proofs": timing.proofs,
            "final_transaction_cu": transaction_cu.last(), "total_cu": transaction_cu.iter().sum::<u64>(),
            "transactions": result.preparation_signatures.len() + result.signatures.len(),
            "send_transactions": result.signatures.len(),
        })
    );
}

#[test]
#[ignore]
fn direct_spend_e2e_benchmark() -> Result<()> {
    let config = BenchmarkConfig::from_env()?;
    let mode = std::env::var("E2E_BENCH_MODE").unwrap_or_else(|_| "direct".into());
    let prepared = std::env::var("E2E_BENCH_PREPARED").as_deref() == Ok("1");
    ensure!(
        ["direct", "gkr", "admitted", "admitted-dag10"].contains(&mode.as_str()),
        "unknown benchmark mode"
    );
    for run in 1..=config.runs {
        let setup = Instant::now();
        let mut fixture = Fixture::new(
            config.inputs,
            config.interleaved,
            mode.starts_with("admitted"),
        )?;
        restart_prover()?;
        let mut setup_ms = setup.elapsed().as_millis();
        let mut warmup_ms = 0;
        if config.warm_keys {
            let warmup = spend(&mut fixture, &mode, config.concurrency, prepared)?;
            let observation = observe(&mut fixture, &warmup)?;
            warmup_ms = warmup.timing.started.elapsed().as_millis();
            report(
                &config,
                &mode,
                run,
                "warmup",
                prepared,
                setup_ms,
                0,
                &warmup,
                &observation,
            );
            let setup = Instant::now();
            fixture = Fixture::new(
                config.inputs,
                config.interleaved,
                mode.starts_with("admitted"),
            )?;
            setup_ms += setup.elapsed().as_millis();
        }
        let result = spend(&mut fixture, &mode, config.concurrency, prepared)?;
        let observation = observe(&mut fixture, &result)?;
        report(
            &config,
            &mode,
            run,
            "measured",
            prepared,
            setup_ms,
            warmup_ms,
            &result,
            &observation,
        );
    }
    Ok(())
}
