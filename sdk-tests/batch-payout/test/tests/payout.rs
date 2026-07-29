//! Batch-payout dapp e2e: the program checks its admin policy, then CPIs
//! shielded-pool `BatchTransact` with N pure-shielded (1,1) entries and
//! proofs. This file also shows external apps how to build compact batch
//! entries from the public SDK crates alone.
//!
//! Needs `just build-programs` (skips when a binary is missing) and the local
//! prover key `transfer_confidential_1_1.key`.

use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{
    prover::field::{be, right_align_slice},
    spawn_prover, ProofCompressed, ProverClient, TransferInput, TransferInputs, TransferOutput,
    NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice, primitives::hash_bytes, sha256::Sha256BE, Hasher,
    Poseidon,
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{
            CircuitId, ExternalDataHash, InputUtxo, OwnerTag, TransactIxData, TransactOutput,
            TransactProof,
        },
        tag::TRANSACT,
    },
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey};
use zolana_merkle_tree::{indexed::IndexedMerkleTree, MerkleTree};
use zolana_program_test::{test_blinding, ProgramTestError, ZolanaProgramTest};
use zolana_transaction::{
    instructions::transact::{spp_proof_inputs::BN254_MODULUS_DEC, PrivateTxHash},
    Data, SppProofOutputUtxo, Utxo, SOL_MINT,
};
use zolana_tree::TreeAccount;

const TRANSFER_AMOUNT: u64 = 1_000_000;
const N: usize = 2;

fn fe(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn start_prover() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var(
            "ZOLANA_PROVER_KEYS_DIR",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../prover/server/proving-keys"
            ),
        );
    });
    spawn_prover().expect("start prover");
}

fn program_test() -> Option<ZolanaProgramTest> {
    let rpc = match ZolanaProgramTest::with_batch_syscalls() {
        Ok(rpc) => rpc,
        Err(ProgramTestError::MissingProgram(_)) => {
            eprintln!("skipping payout test: shielded_pool_program.so missing");
            return None;
        }
        Err(e) => panic!("program test boot failed: {e}"),
    };
    Some(rpc)
}

/// Register the payout program binary next to the shielded pool.
fn add_payout_program(rpc: &mut ZolanaProgramTest) -> Option<()> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../target/deploy/batch_payout_program.so"
    );
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("skipping payout test: batch_payout_program.so missing");
        return None;
    };
    let program_id = Pubkey::new_from_array(batch_payout_program::ID.to_bytes());
    rpc.svm
        .add_program(program_id, &bytes)
        .expect("add payout program");
    Some(())
}

/// The i-th deterministic deposit owned by `spender`.
fn entry_utxo(spender: &Keypair, i: usize) -> (Utxo, NullifierKey, [u8; 32]) {
    let owner = PublicKey::from_ed25519(&spender.pubkey().to_bytes());
    let nullifier_key = NullifierKey::from_secret([30 + i as u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo = Utxo {
        owner,
        asset: SOL_MINT,
        amount: TRANSFER_AMOUNT,
        blinding: test_blinding(100 + i as u8),
        zone_program_id: None,
        data: Data::default(),
    };
    let owner_field = owner_hash(&owner, &nullifier_pk).expect("owner field");
    (utxo, nullifier_key, owner_field)
}

struct Env {
    rpc: ZolanaProgramTest,
    tree: Pubkey,
    spender: Keypair,
}

/// Boot with `N` deposits so each batch entry spends its own UTXO.
fn boot() -> Option<Env> {
    let mut rpc = program_test()?;
    add_payout_program(&mut rpc)?;
    start_prover();
    let authority = Keypair::new();
    rpc.create_protocol_config(&authority)
        .expect("create protocol config");
    let tree = rpc
        .create_tree(zolana_interface::state::tree_account_size() as u64, &authority)
        .expect("create tree");
    let spender = Keypair::new_from_array([77u8; 32]);
    rpc.airdrop(&spender.pubkey(), 10_000_000_000)
        .expect("fund spender");
    for i in 0..N {
        let (utxo, nullifier_key, owner_field) = entry_utxo(&spender, i);
        let event = rpc
            .deposit_sol(
                &tree.pubkey(),
                &spender,
                TRANSFER_AMOUNT,
                owner_field,
                utxo.blinding,
            )
            .expect("proofless deposit");
        let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
        let utxo_hash = utxo
            .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
            .expect("utxo hash");
        assert_eq!(event.utxo_hash, utxo_hash);
    }
    Some(Env {
        rpc,
        tree: tree.pubkey(),
        spender,
    })
}

/// Build `N` compact (1,1) entries with proofs. Each entry spends deposit
/// `i` into one fresh output. The public-input chain mirrors the on-chain
/// reconstruction, so the proofs bind the fee payer and the tree roots.
fn build_entries(env: &Env) -> Result<Vec<TransactIxData>> {
    let spender_bytes = env.spender.pubkey().to_bytes();
    let zero = [0u8; 32];
    let (utxo_root, nullifier_root) = {
        let mut data = env.rpc.account_data(&env.tree).expect("tree account");
        let account = TreeAccount::from_bytes(&mut data, env.tree.to_bytes()).expect("load tree");
        (
            account.get_utxo_tree_root(N as u16).expect("utxo root"),
            account.get_nullifier_tree_root(0).expect("nullifier root"),
        )
    };

    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    let mut prepared = Vec::with_capacity(N);
    for i in 0..N {
        let (utxo, nullifier_key, owner_field) = entry_utxo(&env.spender, i);
        let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
        let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
        state_tree.append(&utxo_hash).expect("append leaf");
        prepared.push((utxo, nullifier_key, owner_field, utxo_hash));
    }
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let modulus_minus_one = BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10)
        .expect("bn254 modulus")
        - 1u32;
    let nf_tree = IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(
        NULLIFIER_TREE_HEIGHT,
        0,
        modulus_minus_one,
    )?;
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");

    let owner = PublicKey::from_ed25519(&spender_bytes);
    let owner_pk_hash = hash_bytes(&spender_bytes).expect("owner pk hash");
    let payer_pubkey_hash = Sha256BE::hash(&spender_bytes).expect("payer hash");

    let mut entries = Vec::with_capacity(N);
    for (i, (utxo, nullifier_key, owner_field, utxo_hash)) in prepared.iter().enumerate() {
        let state_path: Vec<[u8; 32]> = state_tree
            .get_proof_of_leaf(i, true)
            .expect("state proof")
            .to_vec();
        let nullifier = nullifier_key
            .nullifier(utxo_hash, &utxo.blinding)
            .expect("nullifier");
        let non_inclusion = nf_tree
            .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
            .expect("non-inclusion proof");
        let input = TransferInput {
            utxo: zolana_client::ProofInputUtxo::new(
                *owner_field,
                &utxo.asset,
                utxo.amount,
                &utxo.blinding,
            )?
            .with_zone(zero, &utxo.zone_program_id)?,
            is_dummy: be(&fe(0)),
            state_path_elements: state_path.iter().map(be).collect(),
            state_path_index: be(&fe(i as u64)),
            nullifier_low_value: be(&non_inclusion.leaf_lower_range_value),
            nullifier_next_value: be(&non_inclusion.leaf_higher_range_value),
            nullifier_low_path_elements: non_inclusion.merkle_proof.iter().map(be).collect(),
            nullifier_low_path_index: be(&fe(non_inclusion.leaf_index as u64)),
            utxo_tree_root: be(&utxo_root),
            nullifier_tree_root: be(&nullifier_root),
            nullifier: be(&nullifier),
            owner_pk_hash: be(&owner_pk_hash),
            nullifier_secret: be(&right_align_slice(nullifier_key.secret())?),
        };

        // One fresh output owned by the spender preserves the amount.
        let output_nullifier_pk = NullifierKey::from_secret([60 + i as u8; 31])
            .pubkey()
            .expect("output nullifier pubkey");
        let mut output_blinding = [0u8; 32];
        output_blinding[1..].copy_from_slice(&[80 + i as u8; 31]);
        let output = SppProofOutputUtxo {
            asset: SOL_MINT,
            amount: TRANSFER_AMOUNT,
            blinding: output_blinding,
            owner_address: Some(zolana_keypair::ShieldedAddress {
                signing_pubkey: owner,
                nullifier_pubkey: output_nullifier_pk,
                viewing_pubkey: zolana_keypair::ViewingKey::from_bytes(&[5u8; 32])
                    .expect("viewing key")
                    .pubkey(),
            }),
            ..Default::default()
        };
        let output_hash = output.hash().map_err(|e| anyhow!("output hash: {e:?}"))?;

        let mut ix_data = TransactIxData {
            proof: TransactProof::zeroed(),
            expiry_unix_ts: u64::MAX,
            private_tx_hash: zero,
            circuit: CircuitId::ConfidentialEddsa(1, 1, N_PUBLIC_SLOTS as u8),
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            inputs: vec![InputUtxo {
                nullifier_hash: nullifier,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: N as u16,
                eddsa_signer_index: 0,
            }],
            interface_transfers: vec![],
            data_hash: None,
            zone_data_hash: None,
            outputs: vec![TransactOutput {
                utxo_hash: output_hash,
                owner_tag: OwnerTag::Inline(spender_bytes),
                data: None,
            }],
            messages: vec![],
        };

        let resolved: Vec<_> = ix_data
            .outputs
            .iter()
            .map(|output| output.into_resolved(|_| None).expect("resolve owner tag"))
            .collect();
        let external_data_hash = ExternalDataHash {
            spp_instruction_discriminator: TRANSACT,
            expiry_unix_ts: ix_data.expiry_unix_ts,
            interface_transfers: &[],
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk: &ix_data.tx_viewing_pk,
            salt: &ix_data.salt,
            outputs: &resolved,
            messages: &ix_data.messages,
        }
        .hash()
        .map_err(|e| anyhow!("external data hash: {e:?}"))?;
        let output_owner_pk_hash =
            hash_bytes(&spender_bytes).map_err(|e| anyhow!("output owner: {e:?}"))?;
        let private_tx = PrivateTxHash::new(&[*utxo_hash], &[output_hash], &external_data_hash)
            .hash()
            .map_err(|e| anyhow!("private tx hash: {e:?}"))?;

        // Mirror of the confidential public-input chain for one input and one
        // output with no public movement slots.
        let public_input_hash = {
            let one = fe(1);
            let mut chain = vec![
                create_hash_chain_from_slice(&[nullifier]).expect("nullifier chain"),
                create_hash_chain_from_slice(&[output_hash]).expect("output chain"),
                create_hash_chain_from_slice(&[utxo_root]).expect("utxo root chain"),
                create_hash_chain_from_slice(&[nullifier_root]).expect("nullifier root chain"),
                private_tx,
                external_data_hash,
            ];
            for _ in 0..N_PUBLIC_SLOTS {
                chain.push(zero);
                chain.push(zero);
            }
            chain.extend_from_slice(&[
                zero,
                payer_pubkey_hash,
                one,
                create_hash_chain_from_slice(&[owner_pk_hash]).expect("input owner chain"),
                create_hash_chain_from_slice(&[output_owner_pk_hash]).expect("output owner chain"),
            ]);
            create_hash_chain_from_slice(&chain).expect("public input hash")
        };

        let mut witness_output = TransferOutput {
            utxo: zolana_client::ProofInputUtxo::try_from(&output)
                .map_err(|e| anyhow!("witness output: {e:?}"))?,
            is_dummy: be(&fe(0)),
            hash: be(&output_hash),
            owner_pk_hash: be(&zero),
            nullifier_pk: be(&zero),
        };
        witness_output.owner_pk_hash = be(&output_owner_pk_hash);
        witness_output.nullifier_pk = be(&output_nullifier_pk);

        let prover_inputs = TransferInputs {
            inputs: vec![input],
            outputs: vec![witness_output],
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            public_assets: [zero; N_PUBLIC_SLOTS].map(|asset| be(&asset)),
            public_amounts: [zero; N_PUBLIC_SLOTS].map(|amount| be(&amount)),
            zone_program_id: be(&zero),
            payer_pubkey_hash: be(&payer_pubkey_hash),
            allow_dummy_inputs: be(&fe(1)),
            public_input_hash: be(&public_input_hash),
        };
        let proof = ProverClient::local().prove_transfer(&prover_inputs)?;
        ix_data.proof = ProofCompressed::try_from(proof)?.to_transact_proof();
        ix_data.private_tx_hash = private_tx;
        entries.push(ix_data);
    }
    Ok(entries)
}

/// The `BatchTransact` body: count byte plus length-framed entries.
fn batch_body(entries: &[TransactIxData]) -> Vec<u8> {
    let mut body = vec![entries.len() as u8];
    for entry in entries {
        let bytes = entry.serialize().expect("serialize entry");
        body.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        body.extend_from_slice(&bytes);
    }
    body
}

fn payout_program_id() -> Pubkey {
    Pubkey::new_from_array(batch_payout_program::ID.to_bytes())
}

fn config_address() -> Pubkey {
    Pubkey::find_program_address(
        &[batch_payout_program::PAYOUT_CONFIG_SEED],
        &payout_program_id(),
    )
    .0
}

fn init_ix(payer: Pubkey, admin: Pubkey) -> Instruction {
    Instruction {
        program_id: payout_program_id(),
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(admin, true),
            AccountMeta::new(config_address(), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: vec![batch_payout_program::tag::INIT],
    }
}

/// `[admin, config]` then the `BatchTransact` account layout.
fn payout_ix(admin: Pubkey, env: &Env, entries: &[TransactIxData]) -> Instruction {
    let mut data = vec![batch_payout_program::tag::PAYOUT];
    data.extend_from_slice(&batch_body(entries));
    Instruction {
        program_id: payout_program_id(),
        accounts: vec![
            AccountMeta::new_readonly(admin, true),
            AccountMeta::new_readonly(config_address(), false),
            AccountMeta::new(env.spender.pubkey(), true),
            AccountMeta::new(env.tree, false),
            AccountMeta::new(env.tree, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
            AccountMeta::new_readonly(
                Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
                false,
            ),
        ],
        data,
    }
}

fn send(
    env: &mut Env,
    instructions: &[Instruction],
    signers: &[&Keypair],
) -> Result<(), String> {
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let mut all = vec![compute];
    all.extend_from_slice(instructions);
    let payer = signers.first().expect("fee payer").pubkey();
    let message = Message::new(&all, Some(&payer));
    let tx = Transaction::new(signers, message, env.rpc.svm.latest_blockhash());
    env.rpc
        .svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

fn tree_indices(env: &Env) -> (u64, u64) {
    let mut data = env.rpc.account_data(&env.tree).expect("tree account");
    let mut account = TreeAccount::from_bytes(&mut data, env.tree.to_bytes()).expect("load tree");
    let output_index = account.utxo_tree().next_index();
    let nullifier_index = account.nullifer_tree().queue_batches.next_index;
    (output_index, nullifier_index)
}

#[test]
fn payout_applies_batch_behind_admin_gate() {
    let Some(mut env) = boot() else {
        return;
    };
    let admin = Keypair::new();
    env.rpc.airdrop(&admin.pubkey(), 1_000_000_000).expect("fund admin");
    let payer = env.rpc.payer.insecure_clone();
    send(&mut env, &[init_ix(payer.pubkey(), admin.pubkey())], &[&payer, &admin])
        .expect("init config");

    let entries = build_entries(&env).expect("build entries");
    let (out_before, null_before) = tree_indices(&env);

    // A non-admin signer must not trigger the payout.
    let outsider = Keypair::new();
    env.rpc
        .airdrop(&outsider.pubkey(), 1_000_000_000)
        .expect("fund outsider");
    let spender = env.spender.insecure_clone();
    let outsider_ix = payout_ix(outsider.pubkey(), &env, &entries);
    let rejected = send(&mut env, &[outsider_ix], &[&outsider, &spender]);
    assert!(rejected.is_err(), "outsider payout must fail");

    // The admin payout settles both entries in one CPI.
    let admin_ix = payout_ix(admin.pubkey(), &env, &entries);
    let accepted = send(&mut env, &[admin_ix], &[&admin, &spender]);
    assert!(accepted.is_ok(), "admin payout failed: {accepted:?}");
    let (out_after, null_after) = tree_indices(&env);
    assert_eq!(out_after, out_before + N as u64, "outputs appended");
    assert_eq!(null_after, null_before + N as u64, "nullifiers queued");
}
