use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::time::{Duration, Instant};
use zolana_client::{
    prover::direct_spend as direct,
    prover::{ProofCompressed, ProveRequest},
    MerkleContext, MerkleProof, ProverClient, Rpc, SolanaRpc, ZolanaIndexer,
};
use zolana_event_parser::indexed_events_from_instruction_groups;
use zolana_hasher::{primitives::solana_owner_identity, Hasher, Poseidon};
use zolana_interface::{
    direct_spend::{self as wire, field, Payload, Payment, PaymentInputs, PrepareCertificate},
    instruction::{builders::direct_spend as instructions, Deposit},
    SHIELDED_POOL_PROGRAM_ID, SOL_ASSET_FIELD,
};
use zolana_keypair::{NullifierKey, ShieldedKeypair, ViewingKey};
use zolana_program_test::{deposit_outputs_from_event, ZolanaProgramTest};
use zolana_smart_account_client::execute_sync_ix;
use zolana_test_utils::{
    harness::{BootstrapConfig, LocalnetHarness},
    localnet::send_transaction,
    test_validator_asserts::{
        assert_transaction_compute_units, wait_for_indexed_transaction, wait_for_merkle_proofs,
        wait_for_non_inclusion_proofs,
    },
};
use zolana_transaction::ProofInputUtxo;
use zolana_tree::{pending_nullifiers::PendingNullifiers, NullifierTreeInitParams};

const AMOUNT: u64 = 1_000_000_000;

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
    fn new(count: usize) -> Result<Self> {
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

        let owner = setup.payer;
        let key = NullifierKey::from_secret([19; 31]);
        let owner_hash = Poseidon::hashv(&[
            &solana_owner_identity(&owner.pubkey().to_bytes())?,
            &key.pubkey()?,
        ])?;
        let mut notes = Vec::with_capacity(count);
        for start in (0..count).step_by(8) {
            let deposits = (start..(start + 8).min(count))
                .map(|_| ZolanaProgramTest::sol_shield_data(AMOUNT, owner_hash))
                .collect::<Vec<_>>();
            let ix = Deposit {
                tree,
                depositor: owner.pubkey(),
                deposits,
            }
            .instruction()?;
            let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
            let signature = send_transaction(&mut rpc, &[budget, ix], &owner.pubkey(), &[&owner])?;
            let groups = rpc.fetch_confirmed_instruction_groups(&signature)?;
            let events = indexed_events_from_instruction_groups(
                Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
                &groups.groups,
            );
            let event = events
                .first()
                .ok_or_else(|| anyhow!("deposit emitted no event"))?;
            for output in deposit_outputs_from_event(event)? {
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
                if note.hash()? != output.utxo_hash {
                    return Err(anyhow!("deposit output hash mismatch"));
                }
                notes.push(note);
            }
        }
        if notes.len() != count {
            return Err(anyhow!("expected {count} deposits, got {}", notes.len()));
        }

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

    fn resolve_inputs(&mut self) -> Result<()> {
        let hashes = self
            .notes
            .iter()
            .map(ProofInputUtxo::hash)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let state_proofs = wait_for_merkle_proofs(&self.indexer, self.tree_address, &hashes);
        let context = MerkleContext {
            tree_type: 0,
            tree: Address::new_from_array(self.tree.to_bytes()),
        };
        self.inputs = self
            .notes
            .iter()
            .cloned()
            .zip(state_proofs)
            .map(|(note, proof)| direct::Input {
                proof: MerkleProof {
                    merkle_context: context.clone(),
                    ..proof
                },
                note,
            })
            .collect();
        Ok(())
    }

    fn payment(&self, certificates: Vec<[u8; 32]>) -> Result<(Payment, Vec<direct::Output>)> {
        let recipient = self.recipient.pubkey().to_bytes();
        let nullifier_pk = self.recipient.nullifier_key.pubkey()?;
        let owner_hash =
            Poseidon::hashv(&[&solana_owner_identity(&recipient).unwrap(), &nullifier_pk]).unwrap();
        let outputs = [self.notes.len() as u64 * AMOUNT, 0]
            .into_iter()
            .enumerate()
            .map(|(index, amount)| direct::Output {
                note: ProofInputUtxo {
                    domain: field(3),
                    tree_id: field(self.output_tree_id.into()),
                    owner_hash,
                    asset: SOL_ASSET_FIELD,
                    amount: field(amount),
                    blinding: field(50_000 + index as u64),
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
                inputs: PaymentInputs::Certificates(certificates),
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

fn prove(request: &impl ProveRequest) -> Result<wire::Proof> {
    let url =
        std::env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| "http://127.0.0.1:3001".to_owned());
    let proof = ProverClient::new(url).prove(request)?;
    Ok(ProofCompressed::try_from(proof)?.try_into()?)
}

struct Chunk {
    nonce: [u8; 32],
    plan: direct::CertificatePlan,
    root: wire::Root,
    freshness: direct::Request,
}

fn chunks(fixture: &Fixture) -> Result<Vec<Chunk>> {
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
    let proofs = wait_for_non_inclusion_proofs(&fixture.indexer, fixture.tree_address, &nullifiers);
    let mut offset = 0;
    plans
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
        .collect()
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
    let poll_ms = std::env::var("E2E_BENCH_POLL_MS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?;
    let signature = if let Some(interval) = poll_ms {
        let (blockhash, _) = fixture.rpc.get_latest_blockhash()?;
        let transaction = zolana_client::sign_transaction(
            zolana_client::compile_message(
                &fixture.owner.pubkey(),
                instructions,
                blockhash,
                direct::COMPUTE_BUDGET,
            )?,
            &[&fixture.owner],
        )?;
        let signature = fixture.rpc.send_transaction_with_config(
            &transaction,
            zolana_client::RpcSendTransactionConfig {
                preflight_commitment: Some(fixture.rpc.client().commitment().commitment),
                ..Default::default()
            },
        )?;
        fixture
            .rpc
            .wait_for_signature_with_interval(&signature, Duration::from_millis(interval))?;
        signature
    } else {
        fixture.rpc.create_and_send_transaction(
            instructions,
            fixture.owner.pubkey(),
            &[&fixture.owner],
            direct::COMPUTE_BUDGET,
        )?
    };
    Ok(signature)
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
    let mut signatures = Vec::with_capacity(packed.len());
    for batch in packed {
        let size = zolana_client::transaction_size(
            &fixture.owner.pubkey(),
            &batch,
            direct::COMPUTE_BUDGET,
        )?;
        println!(
            "packed transaction: {} bytes, {} addresses",
            size.bytes, size.addresses
        );
        signatures.push(send_batch(fixture, &batch)?);
    }
    Ok(signatures)
}

#[test]
#[ignore]
fn direct_spend_e2e_benchmark() -> Result<()> {
    let inputs = std::env::var("E2E_BENCH_INPUTS")
        .unwrap_or_else(|_| "144".into())
        .parse::<usize>()?;
    let concurrency = std::env::var("E2E_BENCH_CONCURRENCY")
        .unwrap_or_else(|_| "4".into())
        .parse::<usize>()?;
    let prepared = std::env::var("E2E_BENCH_PREPARED").is_ok_and(|value| value == "1");
    let warm_keys = std::env::var("E2E_BENCH_WARM_KEYS").is_ok_and(|value| value == "1");
    assert!(inputs > 0 && inputs <= wire::MAX_INPUTS && concurrency > 0);
    let setup_start = Instant::now();
    let mut fixture = Fixture::new(inputs)?;
    let setup_ms = setup_start.elapsed().as_millis();
    let total_start = Instant::now();
    fixture.resolve_inputs()?;
    let chunks = chunks(&fixture)?;
    let certificate_requests = chunks
        .iter()
        .flat_map(|chunk| [&chunk.plan.request, &chunk.freshness])
        .collect::<Vec<_>>();
    let certificates = chunks
        .iter()
        .map(|chunk| instructions::spend_buffer(&fixture.owner.pubkey(), &chunk.nonce))
        .collect::<Vec<_>>();
    let witness_ms = total_start.elapsed().as_millis();
    let mut preparation_ms = 0;
    let mut preparation_signatures = Vec::new();
    let mut certificate_prove_ms = 0;
    let mut preparation_warmup_ms = 0;
    if prepared {
        let start = Instant::now();
        if warm_keys {
            prove_many(&certificate_requests[..2], 1)?;
            preparation_warmup_ms = start.elapsed().as_millis();
        }
        let proof_start = Instant::now();
        let proofs = prove_many(&certificate_requests, concurrency)?;
        certificate_prove_ms = proof_start.elapsed().as_millis();
        let batches = certificate_batches(&fixture, &chunks, &proofs)?;
        preparation_signatures = submit_batches(&mut fixture, batches)?;
        preparation_ms = start.elapsed().as_millis() - preparation_warmup_ms;
    }
    let send_start = Instant::now();
    let nonce = field(9999);
    let buffer = instructions::spend_buffer(&fixture.owner.pubkey(), &nonce);
    let (payment, outputs) =
        fixture.payment(certificates.iter().map(|key| key.to_bytes()).collect())?;
    let request = direct::balance(
        &payment,
        fixture.owner.pubkey().to_bytes(),
        buffer.to_bytes(),
        fixture.output_tree_id,
        &chunks
            .iter()
            .map(|chunk| &chunk.plan.opening)
            .collect::<Vec<_>>(),
        &outputs,
        wire::MAX_CERTIFICATES,
    )?;
    let mut requests = if prepared {
        Vec::new()
    } else {
        certificate_requests
    };
    requests.push(&request);
    let warmup_start = Instant::now();
    if warm_keys {
        let mut warmup = if prepared {
            Vec::new()
        } else {
            requests[..2].to_vec()
        };
        warmup.push(&request);
        prove_many(&warmup, 1)?;
    }
    let warmup_ms = warmup_start.elapsed().as_millis();
    let proof_start = Instant::now();
    let mut proofs = prove_many(&requests, concurrency)?;
    let prove_ms = proof_start.elapsed().as_millis();
    let payment_proof = proofs.pop().unwrap();
    let submit_start = Instant::now();
    let mut batches = if prepared {
        Vec::new()
    } else {
        certificate_batches(&fixture, &chunks, &proofs)?
    };
    let owner = fixture.owner.pubkey();
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
    let signatures = submit_batches(&mut fixture, batches)?;
    let signature = *signatures.last().unwrap();
    let submit_ms = submit_start.elapsed().as_millis();
    let confirmed_ms = send_start.elapsed().as_millis() - warmup_ms;
    let indexed = wait_for_indexed_transaction(
        &fixture.indexer,
        fixture.recipient.signing_pubkey().confidential_view_tag()?,
        signature,
    );
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
    let indexed_ms = send_start.elapsed().as_millis() - warmup_ms;
    let total_ms = total_start.elapsed().as_millis() - warmup_ms - preparation_warmup_ms;
    let transaction_cu = preparation_signatures
        .iter()
        .chain(&signatures)
        .map(|signature| {
            assert_transaction_compute_units(&fixture.rpc, signature, "packed spend", 1_400_000)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let preparation_cu: u64 = transaction_cu[..preparation_signatures.len()].iter().sum();
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
    let output_hashes = outputs
        .iter()
        .map(|output| output.note.hash())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let indexed = wait_for_merkle_proofs(
        &fixture.indexer,
        Address::new_from_array(fixture.output_tree.to_bytes()),
        &output_hashes,
    );
    assert_eq!(indexed.len(), 2);
    println!(
        "E2E_PIPELINE {}",
        serde_json::json!({
            "inputs": inputs, "concurrency": concurrency, "prepared": prepared, "warm_keys": warm_keys,
            "poll_ms": std::env::var("E2E_BENCH_POLL_MS").ok(),
            "setup_ms": setup_ms, "witness_ms": witness_ms, "preparation_ms": preparation_ms,
            "certificate_prove_ms": certificate_prove_ms, "warmup_ms": warmup_ms + preparation_warmup_ms, "prove_ms": prove_ms,
            "submit_ms": submit_ms, "confirmed_ms": confirmed_ms, "indexed_ms": indexed_ms, "total_ms": total_ms,
            "preparation_cu": preparation_cu, "final_transaction_cu": transaction_cu.last(), "total_cu": transaction_cu.iter().sum::<u64>(),
            "transactions": preparation_signatures.len() + signatures.len(), "send_transactions": signatures.len(),
        })
    );
    Ok(())
}
