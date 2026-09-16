use anyhow::{anyhow, Result};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::time::Instant;
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
use zolana_keypair::NullifierKey;
use zolana_program_test::{deposit_outputs_from_event, ZolanaProgramTest};
use zolana_smart_account_client::execute_sync_ix;
use zolana_test_utils::{
    harness::{BootstrapConfig, LocalnetHarness},
    localnet::send_transaction,
    test_validator_asserts::{
        assert_transaction_compute_units, wait_for_merkle_proofs, wait_for_non_inclusion_proofs,
    },
};
use zolana_transaction::ProofInputUtxo;
use zolana_tree::{pending_nullifiers::PendingNullifiers, NullifierTreeInitParams};

const AMOUNT: u64 = 1_000_000_000;

struct Fixture {
    rpc: SolanaRpc,
    indexer: ZolanaIndexer,
    owner: Keypair,
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
        let (output_tree, _, output_tree_id) =
            LocalnetHarness::<()>::create_tree(&mut rpc, &setup, None)?;

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

    fn upload(&mut self, nonce: [u8; 32], payload: Payload) -> Result<(Pubkey, u64)> {
        let mut cu = 0;
        let owner = self.owner.pubkey();
        for ix in
            instructions::upload_spend(owner, nonce, &payload).map_err(|error| anyhow!(error))?
        {
            let signature = send_transaction(&mut self.rpc, &[ix], &owner, &[&self.owner])?;
            cu +=
                assert_transaction_compute_units(&self.rpc, &signature, "direct upload", 200_000)?;
        }
        Ok((instructions::spend_buffer(&owner, &nonce), cu))
    }

    fn payment(&self, certificates: Vec<[u8; 32]>) -> (Payment, Vec<direct::Output>) {
        let recipient = self.owner.pubkey().to_bytes();
        let nullifier_pk = self.key.pubkey().unwrap();
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
        let public = outputs
            .iter()
            .map(|output| wire::Output {
                recipient,
                utxo: zolana_interface::event::OutputUtxo {
                    view_tag: [0; 32],
                    utxo_hash: output.note.hash().unwrap(),
                    data: Vec::new(),
                },
            })
            .collect();
        (
            Payment {
                inputs: PaymentInputs::Certificates(certificates),
                output_tree: self.output_tree.to_bytes(),
                expiry_slot: u64::MAX,
                max_forester_fee: 0,
                outputs: public,
                tx_viewing_pk: [0; 33],
                salt: [0; 16],
            },
            outputs,
        )
    }
}

fn prove(request: &impl ProveRequest) -> Result<wire::Proof> {
    let url =
        std::env::var("ZOLANA_PROVER_URL").unwrap_or_else(|_| "http://127.0.0.1:3001".to_owned());
    let proof = ProverClient::new(url).prove(request)?;
    Ok(ProofCompressed::try_from(proof)?.try_into()?)
}

fn prepare(
    fixture: &mut Fixture,
    start: usize,
    certificates: &mut Vec<Pubkey>,
    openings: &mut Vec<direct::Opening>,
) -> Result<u64> {
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
    let certificate_proof = prove(&plan.request)?;
    let nullifiers = plan.statement.nullifiers.clone();
    let freshness_proofs =
        wait_for_non_inclusion_proofs(&fixture.indexer, fixture.tree_address, &nullifiers);
    let (root, freshness) = direct::freshness(
        &plan.statement,
        fixture.tree_id,
        &freshness_proofs,
        wire::CERTIFICATE_INPUTS,
    )?;
    let freshness_proof = prove(&freshness)?;
    let (_, mut cu) = fixture.upload(
        nonce,
        Payload::Certificate {
            statement: plan.statement,
            proof: certificate_proof,
        },
    )?;
    let ix = instructions::prepare_certificate(
        fixture.owner.pubkey(),
        buffer,
        fixture.tree,
        &PrepareCertificate {
            freshness: root,
            proof: freshness_proof,
        },
    );
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let heap = ComputeBudgetInstruction::request_heap_frame(256 * 1024);
    let signature = send_transaction(
        &mut fixture.rpc,
        &[heap, budget, ix],
        &fixture.owner.pubkey(),
        &[&fixture.owner],
    )?;
    cu += assert_transaction_compute_units(&fixture.rpc, &signature, "direct prepare", 1_400_000)?;
    certificates.push(buffer);
    openings.push(plan.opening);
    Ok(cu)
}

#[test]
#[ignore]
fn direct_spend_e2e_benchmark() -> Result<()> {
    let inputs = std::env::var("E2E_BENCH_INPUTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(72);
    assert!(inputs > 0 && inputs <= wire::MAX_INPUTS);

    let setup_start = Instant::now();
    let mut fixture = Fixture::new(inputs)?;
    let setup_ms = setup_start.elapsed().as_millis();

    let spend_start = Instant::now();
    fixture.resolve_inputs()?;
    let mut certificates = Vec::new();
    let mut openings = Vec::new();
    let mut total_cu = 0;
    for start in (0..inputs).step_by(wire::CERTIFICATE_INPUTS) {
        total_cu += prepare(&mut fixture, start, &mut certificates, &mut openings)?;
    }

    let nonce = field(9999);
    let buffer = instructions::spend_buffer(&fixture.owner.pubkey(), &nonce);
    let (payment, outputs) =
        fixture.payment(certificates.iter().map(|key| key.to_bytes()).collect());
    let request = direct::balance(
        &payment,
        fixture.owner.pubkey().to_bytes(),
        buffer.to_bytes(),
        fixture.output_tree_id,
        &openings.iter().collect::<Vec<_>>(),
        &outputs,
        wire::MAX_CERTIFICATES,
    )?;
    let proof = prove(&request)?;
    let (_, upload_cu) = fixture.upload(
        nonce,
        Payload::Payment {
            statement: payment,
            proof,
        },
    )?;
    total_cu += upload_cu;
    let ix = instructions::commit_spend(
        fixture.owner.pubkey(),
        buffer,
        fixture.tree,
        fixture.output_tree,
        &certificates,
    );
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let heap = ComputeBudgetInstruction::request_heap_frame(256 * 1024);
    let signature = send_transaction(
        &mut fixture.rpc,
        &[heap, budget, ix],
        &fixture.owner.pubkey(),
        &[&fixture.owner],
    )?;
    let commit_cu =
        assert_transaction_compute_units(&fixture.rpc, &signature, "direct commit", 1_400_000)?;
    total_cu += commit_cu;
    let spend_ms = spend_start.elapsed().as_millis();
    println!(
        "E2E_BENCH variant=direct inputs={inputs} certificates={} merge_transactions=0 merged_outputs=0 commit_cu={commit_cu} total_cu={total_cu} setup_ms={setup_ms} spend_ms={spend_ms}",
        certificates.len()
    );
    Ok(())
}
