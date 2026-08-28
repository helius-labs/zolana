//! Litesvm program-test for the `transact` instruction: boot a protocol config
//! and pool tree, build a valid (2,3) Groth16 proof on the Solana-only eddsa
//! rail, assemble the `transact` instruction data, and send it to the program.
//!
//! The two inputs are circuit dummies (`is_dummy = 1`), so they need no real
//! UTXOs or merkle proofs, but they carry distinct non-zero nullifiers plus the
//! real on-chain tree roots and the payer's owner hash. The proof is therefore
//! bound to exactly what the program reconstructs on-chain: the `external_data`
//! hash (via the shared [`ExternalDataHash`] from the interface crate), the
//! payer pubkey hash, the per-input owner hashes, the tree roots, and the
//! nullifier/output hash chains.
//!
//! Requires `cargo build-sbf -p shielded-pool-program`.

use shielded_pool_tests::support::transact::{
    proof_env, tree_progress, tree_roots, write_ring_config_account, Pool,
};

use num_bigint::BigUint;

use groth16_solana::groth16::Groth16Verifier;
use shielded_pool_program::testing::MAX_SIGNERS;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{error::InstructionError, AccountMeta};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::STATE_TREE_HEIGHT;
use zolana_client::{
    prover::field::be, ProverClient, PublicInputs, PublicTransfers, TransferOutput,
};
use zolana_hasher::Poseidon;
use zolana_hasher::{
    hash_chain::{create_hash_chain_from_slice, create_right_hash_chain_from_slice},
    primitives::hash_bytes,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{
            CircuitId, ExternalDataHash, InterfaceTransfer, OwnerTag, TransactIxData,
        },
        tag, Transact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    },
    state::{discriminator::RING_CONFIG, RingConfig},
    NULLIFIER_MARKER_SIZE, N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{test_blinding, Rejection};
use zolana_test_utils::nullifier_marker::{
    assert_nullifier_markers, marker_addresses, nullifier_marker_rent,
};
use zolana_test_utils::transact::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo, fe,
    inline_outputs, new_transact_ix_data, nullifier_tree, output_owner_pk_hashes,
    pack_transact_proof, prove_and_verify_transfer, resolve_outputs, set_output_owner_tags,
    sol_public_slots, spend_input, SpendInputArgs, TransferProverInputsArgs,
};
use zolana_transaction::{instructions::transact::PrivateTxHash, Data, Utxo, SOL_MINT};
use zolana_tree::TreeAccount;

/// Build a valid (2,3) eddsa-rail `transact` instruction data with a real proof:
/// one real zero-value input (a proofless SOL deposit the payer just made --
/// PR164 requires at least one real input for the dummy-participant gate) plus
/// one dummy input, and three dummy outputs, bound to the on-chain roots and
/// the payer. Shared by the positive and negative scenarios.
fn build_valid_transact_ix_for_owner_with_discriminator(
    env: &mut Pool,
    input_owner: Pubkey,
    discriminator: u8,
) -> TransactIxData {
    let payer = env.rpc.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let input_owner_bytes = input_owner.to_bytes();
    let zero = [0u8; 32];

    // The real input: a zero-value SOL deposit owned by `input_owner` (fixed
    // blinding / nullifier secret keep the run deterministic).
    let blinding = test_blinding(7);
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let owner_public_key = PublicKey::from_ed25519(&input_owner_bytes);
    let owner_pk_hash = owner_public_key
        .owner_proof_input_hash()
        .expect("owner pk hash");
    let owner_field = owner_hash(&owner_public_key, &nullifier_pk).expect("owner field");
    let utxo = Utxo {
        owner: owner_public_key,
        asset: SOL_MINT,
        amount: 0,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    env.rpc
        .deposit_sol(&env.tree.pubkey(), &payer, 0, owner_field, blinding)
        .expect("proofless zero deposit");

    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
    let (utxo_root, nullifier_root) = tree_roots(&env.rpc, &env.tree.pubkey(), 1);
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&utxo_hash).expect("append state leaf");
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("state proof")
        .to_vec();
    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &blinding)
        .expect("nullifier");
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
        .expect("non-inclusion proof");

    let roots = (utxo_root, nullifier_root);
    let (dummy_input_1, dummy_nullifier) =
        dummy_input(&[2u8; 31], &nf_tree, roots).expect("dummy input");
    let real_input = spend_input(SpendInputArgs {
        utxo: &utxo,
        owner_field: &owner_field,
        state_path: &state_path,
        state_path_index: 0,
        non_inclusion: &non_inclusion,
        roots,
        nullifier: &nullifier,
        owner_pk_hash: &owner_pk_hash,
        nullifier_key: &nullifier_key,
    })
    .expect("real input");

    // Three dummy outputs with distinct blindings; they carry the input
    // owner's tag (the AssertDummyTags rule; see `set_output_owner_tags`).
    let dummy_outputs: Vec<(TransferOutput, [u8; 32])> = [[1u8; 31], [2u8; 31], [3u8; 31]]
        .iter()
        .map(|blinding| dummy_transfer_output(blinding).expect("dummy output"))
        .collect();
    let output_hashes: Vec<[u8; 32]> = dummy_outputs.iter().map(|(_, hash)| *hash).collect();
    let mut outputs: Vec<TransferOutput> = dummy_outputs.into_iter().map(|(out, _)| out).collect();

    let mut transact_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(nullifier, 1),
            eddsa_input_utxo(dummy_nullifier, 1),
        ],
        Vec::new(),
        inline_outputs(&output_hashes, &[input_owner_bytes; 3]),
    );

    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.outputs).expect("output owner pk hashes");
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &[zero, zero, zero]);

    let external_data_hash = external_data_hash_for_discriminator(&transact_ix_data, discriminator);

    // The real input contributes its utxo hash to private_tx_hash; the dummy
    // input and all outputs contribute zero.
    let private_tx =
        PrivateTxHash::new(&[utxo_hash, zero], &[zero, zero, zero], &external_data_hash)
            .hash()
            .expect("private tx hash");

    // The signer run the proof binds: payer first, then the input owner when
    // it differs from the payer, zero-padded to the circuit width.
    let payer_hash = hash_bytes(&payer_bytes).expect("payer hash");
    let owner_signer_hash = hash_bytes(&input_owner_bytes).expect("input owner hash");
    let signer_hashes = if input_owner_bytes == payer_bytes {
        [payer_hash, zero, zero]
    } else {
        [payer_hash, owner_signer_hash, zero]
    };
    let (public_slot_assets, public_slot_amounts) = sol_public_slots(zero);
    let public_input_hash = PublicInputs {
        nullifiers: &[nullifier, dummy_nullifier],
        output_hashes: &output_hashes,
        utxo_roots: &[utxo_root, utxo_root],
        nullifier_tree_roots: &[nullifier_root, nullifier_root],
        private_tx: &private_tx,
        external_data_hash: &external_data_hash,
        public_transfers: &PublicTransfers {
            assets: public_slot_assets,
            amounts: public_slot_amounts,
        },
        ring_program_id: &zero,
        allow_dummy_inputs: &fe(1),
        signer_pk_hashes: &signer_hashes,
        output_owner_pk_hashes: Some(&owner_pk_hashes),
    }
    .hash()
    .expect("public input hash");

    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![real_input, dummy_input_1],
        outputs,
        external_data_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        signer_pk_hashes: signer_hashes.to_vec(),
        public_input_hash,
    });
    transact_ix_data.proof =
        prove_and_verify_transfer(&prover_inputs, public_input_hash, "transact")
            .expect("prove transact");
    transact_ix_data.private_tx_hash = private_tx;
    transact_ix_data
}

fn build_valid_transact_ix_for_owner(env: &mut Pool, input_owner: Pubkey) -> TransactIxData {
    build_valid_transact_ix_for_owner_with_discriminator(env, input_owner, tag::TRANSACT)
}

fn build_valid_transact_ix(env: &mut Pool) -> TransactIxData {
    let input_owner = env.rpc.payer.pubkey();
    build_valid_transact_ix_for_owner(env, input_owner)
}

/// Write a structurally valid ring config at a signer-controlled test address.
fn write_signed_ring_config(env: &mut Pool, ring_program: Pubkey, enabled: bool) -> Keypair {
    let ring_config = Keypair::new();
    let config = RingConfig {
        discriminator: RING_CONFIG,
        authority: Address::new_from_array(env.rpc.payer.pubkey().to_bytes()),
        program_id: Address::new_from_array(ring_program.to_bytes()),
        ring_authority_transact_is_enabled: u8::from(enabled),
        paused: 0,
        bump: 0,
    };
    write_ring_config_account(
        &mut env.rpc,
        ring_config.pubkey(),
        Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        bytemuck::bytes_of(&config).to_vec(),
    );
    ring_config
}

/// The ring-rail `ExternalDataHash` for a pure shielded transfer: identical to
/// the confidential one except for the instruction discriminator, which the
/// program folds from the tag it dispatched on.
fn external_data_hash_for_discriminator(
    transact_ix_data: &TransactIxData,
    discriminator: u8,
) -> [u8; 32] {
    let resolved = resolve_outputs(transact_ix_data).expect("resolve outputs");
    ExternalDataHash {
        spp_instruction_discriminator: discriminator,
        expiry_unix_ts: transact_ix_data.expiry_unix_ts,
        interface_transfers: &[],
        data_hash: None,
        ring_data_hash: None,
        tx_viewing_pk: &transact_ix_data.tx_viewing_pk,
        salt: &transact_ix_data.salt,
        outputs: &resolved,
        messages: &transact_ix_data.messages,
    }
    .hash()
    .expect("ring external data hash")
}

/// Build valid ring-rail instruction data with a real proof bound to the ring
/// test program: one real zero-value ring-owned input (a proofless ring
/// deposit through the fixture ring program -- PR164 requires a real input for
/// the dummy-participant gate and ring-owns every real input) plus enough dummy
/// inputs and outputs to fill the requested shape. Outputs are tagged with the
/// payer (the participant). The public `ring_program_id` element is the only
/// ring-dependent value, so the same witness feeds the cross-ring negatives.
fn build_valid_ring_ix<const IS_AUTHORITY: bool>(
    env: &mut Pool,
    ring_program: Pubkey,
    n_inputs: usize,
    n_outputs: usize,
) -> TransactIxData {
    assert!(n_inputs > 0, "ring proof needs at least one input");
    // Ring-owned real input: load the fixture ring program and deposit zero
    // lamports to the payer through it (the deposit's ring_config pins
    // `ring_program_id` to the fixture program, which is what the proof binds).
    env.rpc
        .load_ring_test_program()
        .expect("load ring test program");
    let ring_authority = env.authority.insecure_clone();
    env.rpc
        .create_ring_config(&ring_authority, &ring_authority.pubkey(), true)
        .expect("create ring config");

    let payer = env.rpc.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];
    let ring = solana_address::Address::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID);

    let blinding = test_blinding(7);
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let owner_public_key = PublicKey::from_ed25519(&payer_bytes);
    let owner_pk_hash = owner_public_key
        .owner_proof_input_hash()
        .expect("owner pk hash");
    let owner_field = owner_hash(&owner_public_key, &nullifier_pk).expect("owner field");
    let utxo = Utxo {
        owner: owner_public_key,
        asset: SOL_MINT,
        amount: 0,
        blinding,
        ring_program_id: Some(ring),
        data: Data::default(),
    };
    let deposit_data = env.rpc.ring_sol_shield_data(0, owner_field, blinding);
    env.rpc
        .ring_deposit(&env.tree.pubkey(), &payer, &deposit_data)
        .expect("ring zero deposit");

    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
    let (utxo_root, nullifier_root) = tree_roots(&env.rpc, &env.tree.pubkey(), 1);
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&utxo_hash).expect("append state leaf");
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("state proof")
        .to_vec();
    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &blinding)
        .expect("nullifier");
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
        .expect("non-inclusion proof");

    let roots = (utxo_root, nullifier_root);
    let real_input = spend_input(SpendInputArgs {
        utxo: &utxo,
        owner_field: &owner_field,
        state_path: &state_path,
        state_path_index: 0,
        non_inclusion: &non_inclusion,
        roots,
        nullifier: &nullifier,
        owner_pk_hash: &owner_pk_hash,
        nullifier_key: &nullifier_key,
    })
    .expect("real input");
    let mut prover_inputs = vec![real_input];
    let mut nullifiers = vec![nullifier];
    for offset in 0..n_inputs - 1 {
        let seed = 12u8
            .checked_add(u8::try_from(offset).expect("supported ring input count"))
            .expect("dummy-input seed");
        let (input, dummy_nullifier) =
            dummy_input(&[seed; 31], &nf_tree, roots).expect("dummy input");
        prover_inputs.push(input);
        nullifiers.push(dummy_nullifier);
    }

    // Dummy outputs with distinct blindings, tagged with the payer (the
    // participant every input binds to).
    let dummy_outputs: Vec<(TransferOutput, [u8; 32])> = (1..=n_outputs)
        .map(|position| {
            let seed = u8::try_from(position).expect("supported ring output count");
            dummy_transfer_output(&[seed; 31]).expect("dummy output")
        })
        .collect();
    let output_hashes: Vec<[u8; 32]> = dummy_outputs.iter().map(|(_, hash)| *hash).collect();
    let mut outputs: Vec<TransferOutput> = dummy_outputs.into_iter().map(|(out, _)| out).collect();

    let view_tags: Vec<[u8; 32]> = (0..n_outputs).map(|_| payer_bytes).collect();
    let mut transact_ix_data = new_transact_ix_data(
        nullifiers
            .iter()
            .map(|nullifier| eddsa_input_utxo(*nullifier, 1))
            .collect(),
        Vec::new(),
        inline_outputs(&output_hashes, &view_tags),
    );
    let n_inputs = u8::try_from(n_inputs).expect("supported ring input count");
    let n_outputs = u8::try_from(n_outputs).expect("supported ring output count");
    transact_ix_data.circuit = if IS_AUTHORITY {
        CircuitId::RingAuthority(n_inputs, n_outputs, N_PUBLIC_SLOTS as u8)
    } else {
        CircuitId::RingEddsa(n_inputs, n_outputs, N_PUBLIC_SLOTS as u8)
    };

    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.outputs).expect("output owner pk hashes");
    let nullifier_pks = vec![zero; usize::from(n_outputs)];
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &nullifier_pks);

    let discriminator = if IS_AUTHORITY {
        tag::RING_AUTHORITY_TRANSACT
    } else {
        tag::RING_TRANSACT
    };
    let external_data_hash = external_data_hash_for_discriminator(&transact_ix_data, discriminator);
    let private_input_hashes: Vec<[u8; 32]> = std::iter::once(utxo_hash)
        .chain(std::iter::repeat(zero).take(usize::from(n_inputs) - 1))
        .collect();
    let private_output_hashes = vec![zero; usize::from(n_outputs)];
    let private_tx = PrivateTxHash::new(
        &private_input_hashes,
        &private_output_hashes,
        &external_data_hash,
    )
    .hash()
    .expect("private tx hash");

    let payer_hash = hash_bytes(&payer_bytes).expect("payer hash");
    // The program folds `hash_bytes` of the SIGNING config's stored program id
    // into the `ring_program_id` public-input element.
    let ring_field = hash_bytes(&ring_program.to_bytes()).expect("ring program field");

    // Public-input layout: the 6-element base chain, the interleaved public
    // transfer slots (all idle here), then ring/signer/dummy-policy, then the
    // variant appendix (RingEddsa: the output-owner chain; RingAuthority:
    // nothing — its signer element is the bare payer hash).
    let signer_hashes: Vec<[u8; 32]> = std::iter::once(payer_hash)
        .chain(std::iter::repeat(zero).take(usize::from(n_inputs)))
        .collect();
    let (public_slot_assets, public_slot_amounts) = sol_public_slots(zero);
    let mut chain = vec![
        create_hash_chain_from_slice(&nullifiers).expect("nullifier chain"),
        create_hash_chain_from_slice(&output_hashes).expect("output chain"),
        create_hash_chain_from_slice(&vec![utxo_root; usize::from(n_inputs)])
            .expect("utxo root chain"),
        create_hash_chain_from_slice(&vec![nullifier_root; usize::from(n_inputs)])
            .expect("nullifier root chain"),
        private_tx,
        external_data_hash,
    ];
    for (asset, amount) in public_slot_assets.iter().zip(public_slot_amounts.iter()) {
        chain.push(*asset);
        chain.push(*amount);
    }
    if IS_AUTHORITY {
        chain.extend_from_slice(&[ring_field, payer_hash, fe(1)]);
    } else {
        // RingEddsa binds only CONFIDENTIAL-MARKED output owners; these outputs
        // carry `data: None` (unmarked), so every published owner slot is 0.
        let published_owners = vec![zero; usize::from(n_outputs)];
        chain.push(ring_field);
        chain.push(create_right_hash_chain_from_slice(&signer_hashes).expect("signer hash chain"));
        chain.push(fe(1));
        chain.push(create_hash_chain_from_slice(&published_owners).expect("output owner chain"));
    }
    let public_input_hash = create_hash_chain_from_slice(&chain).expect("ring public input hash");

    let mut prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: prover_inputs,
        outputs,
        external_data_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        signer_pk_hashes: signer_hashes,
        public_input_hash,
    });
    prover_inputs.ring_program_id = be(&ring_field);
    if IS_AUTHORITY {
        // The authority rail proves no signatures: its witness carries only the
        // bare payer hash and publishes no output-owner hashes.
        prover_inputs.signer_pk_hashes = vec![be(&payer_hash)];
        prover_inputs.published_output_owner_pk_hashes = Vec::new();
    } else {
        // RingEddsa publishes only confidential-marked owner tags; these
        // outputs are unmarked, so every published slot is 0.
        prover_inputs.published_output_owner_pk_hashes = vec![be(&zero); usize::from(n_outputs)];
    }

    let prover = ProverClient::local();
    let proof = if IS_AUTHORITY {
        prover
            .prove_ring_authority(&prover_inputs)
            .expect("prove ring authority transact")
    } else {
        prover
            .prove_transfer_ring(&prover_inputs)
            .expect("prove ring transact")
    };
    // Local pairing gate against the committed ring verifying key: the proof
    // itself is valid, so an on-chain 7008 can only come from a binding
    // mismatch, not a bad proof.
    {
        let public_inputs = [public_input_hash];
        let verifying_key = transact_ix_data
            .circuit
            .verifying_key()
            .expect("supported ring verifying key");
        let mut verifier =
            Groth16Verifier::new(&proof.a, &proof.b, &proof.c, &public_inputs, verifying_key)
                .expect("construct ring verifier");
        verifier.verify().expect("ring proof verifies locally");
    }
    transact_ix_data.proof = pack_transact_proof(&proof).expect("pack ring proof");
    transact_ix_data.private_tx_hash = private_tx;
    transact_ix_data
}

#[test]
fn transact_sends_valid_proof() {
    let mut env = proof_env();

    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let transact_ix_data = build_valid_transact_ix(&mut env);
    let expected_nullifiers: Vec<[u8; 32]> = transact_ix_data
        .inputs
        .iter()
        .map(|input| input.nullifier_hash)
        .collect();
    let expected_output_hashes: Vec<[u8; 32]> = transact_ix_data
        .outputs
        .iter()
        .map(|output| output.utxo_hash)
        .collect();
    let (utxo_next_before, nullifier_next_before) = tree_progress(&env.rpc, &tree);
    let (utxo_root_before, _) = tree_roots(&env.rpc, &tree, 0);

    // Accounts: `[payer (signer), tree (writable)]`. Index 0 is the fee payer
    // and the eddsa signer the inputs reference (`eddsa_signer_index = 0`).
    let ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();

    let indexed = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect("transact with a valid proof");

    // Tree state: three outputs appended (advancing the utxo root into history
    // slot 3) and both input nullifiers queued.
    let (utxo_next_after, nullifier_next_after) = tree_progress(&env.rpc, &tree);
    assert_eq!(
        utxo_next_after,
        utxo_next_before + 3,
        "three outputs appended"
    );
    assert_eq!(
        nullifier_next_after,
        nullifier_next_before + 2,
        "two nullifiers queued"
    );
    let mut data = env.rpc.account_data(&tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    // The deposit consumed root-history slot 1, so the transact's root is slot 2.
    let utxo_root_after = account.get_utxo_tree_root(2).expect("post-transact root");
    assert_ne!(utxo_root_after, utxo_root_before, "utxo root advanced");

    // Event: one Transact event carrying exactly the instruction's nullifiers
    // and output hashes, anchored at the pre-transaction leaf index.
    let event = match indexed.events.as_slice() {
        [event] => event.decoded.as_ref().expect("decode transact event"),
        events => panic!("expected exactly one transact event, got {events:?}"),
    };
    let event_nullifiers: Vec<[u8; 32]> =
        event.inputs.iter().map(|input| input.nullifier).collect();
    assert_eq!(event_nullifiers, expected_nullifiers, "event nullifiers");
    let event_output_hashes: Vec<[u8; 32]> = event
        .outputs
        .iter()
        .map(|output| output.utxo_hash)
        .collect();
    assert_eq!(
        event_output_hashes, expected_output_hashes,
        "event output hashes"
    );
    assert_eq!(
        event.first_output_leaf_index, utxo_next_before,
        "event anchors the first appended leaf"
    );
    assert_eq!(
        event.output_tree,
        tree.to_bytes(),
        "event names the pool tree"
    );

    // Frame conditions (INV-TRANSACT-29/30): a pure shielded transfer settles
    // nothing. The journaled snapshots must show the tree and the two new
    // nullifier markers as the only accounts whose data changed, the payer
    // debited exactly the transaction fee (one signature at LiteSVM's default
    // rate) plus the forester fee (2 nullifier insertions at 20 lamports each),
    // which the program collects into the input tree via one System-Program CPI
    // (INV-TRANSACT-42), and the tree funding one marker's rent per input.
    const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
    const FORESTER_FEE_LAMPORTS: u64 = 40;
    let marker_rent = nullifier_marker_rent(&env.rpc).expect("nullifier marker rent");
    let markers = marker_addresses(&tree, &expected_nullifiers);
    let marker_rent_total = marker_rent * expected_nullifiers.len() as u64;
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let trace = env
        .rpc
        .last_transaction_trace()
        .expect("successful transact trace");
    let traced: Vec<Pubkey> = trace
        .accounts
        .iter()
        .map(|transition| transition.address)
        .collect();
    assert!(
        traced.contains(&payer)
            && traced.contains(&tree)
            && markers.iter().all(|marker| traced.contains(marker)),
        "trace must journal the payer, the tree and the nullifier markers, got {traced:?}"
    );
    for transition in &trace.accounts {
        if markers.contains(&transition.address) {
            assert_eq!(
                transition.before, None,
                "nullifier marker {} must not exist before the transact",
                transition.address
            );
            let after = transition
                .after
                .as_ref()
                .expect("nullifier marker after transact");
            assert_eq!(
                after.lamports, marker_rent,
                "nullifier marker holds exactly its rent"
            );
            assert_eq!(after.owner, program_id, "nullifier marker is program-owned");
            assert_eq!(
                after.data_len, NULLIFIER_MARKER_SIZE,
                "nullifier marker size"
            );
            continue;
        }
        let before = transition.before.as_ref().expect("account before transact");
        let after = transition.after.as_ref().expect("account after transact");
        if transition.address == tree {
            assert_eq!(
                before.lamports + FORESTER_FEE_LAMPORTS,
                after.lamports + marker_rent_total,
                "tree collects the forester reimbursement fee and funds one marker per input"
            );
            assert_eq!(before.owner, after.owner, "tree owner unchanged");
            assert_eq!(before.data_len, after.data_len, "tree size unchanged");
            assert_ne!(before.data_sha256, after.data_sha256, "tree data advanced");
        } else if transition.address == payer {
            assert_eq!(
                before.lamports,
                after.lamports + LAMPORTS_PER_SIGNATURE + FORESTER_FEE_LAMPORTS,
                "payer pays exactly the transaction fee plus the forester reimbursement fee"
            );
            assert_eq!(
                before.data_sha256, after.data_sha256,
                "payer data unchanged"
            );
            assert_eq!(before.owner, after.owner, "payer owner unchanged");
        } else {
            assert_eq!(
                before, after,
                "account {} must be untouched by a pure shielded transfer",
                transition.address
            );
        }
    }
    assert_nullifier_markers(&env.rpc, &tree, &expected_nullifiers).expect("nullifier markers");
}

/// A tampered output owner tag (changed after proving, so
/// `hash_bytes(resolved_owner_tag)` no longer matches the proof's committed
/// output-owner chain) must be rejected: the program reconstructs the owner tags
/// from the instruction's outputs and the resulting public input no longer
/// matches the proof.
#[test]
fn transact_rejects_tampered_output_owner_tag() {
    let mut env = proof_env();

    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let mut transact_ix_data = build_valid_transact_ix(&mut env);

    // Flip a recipient output's owner tag. The proof committed to the original
    // `hash_bytes(resolved_owner_tag)`, so the program's reconstruction now
    // disagrees.
    let tampered = transact_ix_data.outputs.get_mut(1).expect("second output");
    tampered.owner_tag = OwnerTag::Inline([0xAAu8; 32]);

    let ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("tampered output owner_tag must be rejected");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("tampered owner_tag transaction trace")
        .assert_rolled_back_except(&[payer]);
}

/// A public amount injected after proving (the classic unconstrained
/// public-input probe: the proof is valid, the claimed withdrawal is not) must
/// fail proof verification, not settle: the program recomputes the amount
/// field and `external_data_hash` from the instruction, so the public input no
/// longer matches the proof, and verification runs before any lamport moves.
#[test]
fn transact_rejects_tampered_public_amount() {
    let mut env = proof_env();

    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let mut transact_ix_data = build_valid_transact_ix(&mut env);

    // The proof was built for a pure shielded transfer (no interface
    // transfers). Claim a 1-lamport withdrawal to a fresh recipient after
    // proving: the program recomputes the public movement slots and the
    // external-data hash from the instruction, so the public input no longer
    // matches the proof.
    transact_ix_data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 1 }];
    let recipient = Keypair::new().pubkey();

    let ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts { recipient },
        )],
        data: transact_ix_data,
    }
    .instruction();

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("tampered public amount must be rejected");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);

    // No settlement happened: the claimed recipient received nothing and every
    // account except the fee payer rolled back.
    assert_eq!(
        env.rpc.svm.get_balance(&recipient).unwrap_or(0),
        0,
        "tampered withdrawal must not credit the recipient"
    );
    env.rpc
        .last_transaction_trace()
        .expect("tampered amount transaction trace")
        .assert_rolled_back_except(&[payer]);
}

/// Changing the proof-bound private transaction hash must fail atomically.
#[test]
fn transact_rejects_tampered_private_transaction_hash() {
    let mut env = proof_env();
    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let mut data = build_valid_transact_ix(&mut env);
    // A small valid field element: the recomputed public input hash no longer
    // matches the proof (an out-of-field value would fail earlier in the
    // Poseidon domain check, not at verification).
    data.private_tx_hash = fe(42);
    let ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction();

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("tampered private transaction hash must be rejected");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("tampered private hash transaction trace")
        .assert_rolled_back_except(&[payer]);
}

/// Changing proof-bound external data must fail atomically.
#[test]
fn transact_rejects_tampered_external_data() {
    let mut env = proof_env();
    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let mut data = build_valid_transact_ix(&mut env);
    data.data_hash = Some([0x5A; 32]);
    let ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction();

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("tampered external data must be rejected");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("tampered external data transaction trace")
        .assert_rolled_back_except(&[payer]);
}

/// An out-of-field output hash aborts before any state change.
#[test]
fn transact_rejects_out_of_field_output_hash() {
    let mut env = proof_env();

    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let mut transact_ix_data = build_valid_transact_ix(&mut env);

    // 0xFF..FF == 2^256 - 1, far above the BN254 modulus (~2^254), so the tree
    // append's Poseidon hash of this leaf cannot succeed.
    transact_ix_data
        .outputs
        .get_mut(0)
        .expect("first output")
        .utxo_hash = [0xFF; 32];

    let ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("out-of-field output hash must be rejected");
    Rejection::new(InstructionError::ProgramFailedToComplete).assert_litesvm(error);

    // A failed transaction commits nothing: the tree counters read the same
    // before and after (the builder's zero deposit already advanced the utxo
    // counter to 1); the journaled trace also shows all non-fee-payer accounts
    // rolled back.
    let (utxo_next, nullifier_next) = tree_progress(&env.rpc, &tree);
    assert_eq!(utxo_next, 1, "utxo tree must not advance past the deposit");
    assert_eq!(nullifier_next, 0, "nullifier queue must not advance");
    env.rpc
        .last_transaction_trace()
        .expect("out-of-field transaction trace")
        .assert_rolled_back_except(&[payer]);
}

#[test]
fn transact_rejects_unsigned_eddsa_input_owner() {
    let mut env = proof_env();

    let payer = env.rpc.payer.pubkey();
    let input_owner = Keypair::new();
    env.rpc
        .airdrop(&input_owner.pubkey(), 1_000_000)
        .expect("fund input owner account");
    // The builder appends owner signers after the SPP and System Program
    // accounts (index 5). Bind both proof inputs to the input owner and flip
    // its meta to unsigned: the loader's signer-run scan ends at the first
    // non-signer, so the flipped account becomes an unparsable leftover and
    // the instruction fails closed with InvalidTransactShape.
    let transact_ix_data = build_valid_transact_ix_for_owner(&mut env, input_owner.pubkey());
    let mut ix = Transact {
        payer,
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        owner_signers: vec![input_owner.pubkey()],
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();
    ix.accounts
        .get_mut(5)
        .expect("input owner account meta")
        .is_signer = false;

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("unsigned Ed25519 input owner must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidTransactShape).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("unsigned owner transaction trace")
        .assert_rolled_back_except(&[payer]);
}

/// INV-TRANSACT-05: the proof binds the signer run (payer first, then unique
/// owner signers) as a fixed-width hash chain. Substituting a different account
/// that DOES sign in the owner-signer slot passes the signer check, so the
/// chain binding is the only thing left to fail: the program folds the
/// substitute's hash and the public input no longer matches the proof.
#[test]
fn transact_rejects_a_substituted_input_signer() {
    let mut env = proof_env();

    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let bound_owner = Keypair::new();
    let substitute_owner = Keypair::new();
    env.rpc
        .airdrop(&substitute_owner.pubkey(), 1_000_000)
        .expect("fund substitute owner account");

    // Prove for `bound_owner` in the owner-signer run, then place the signing
    // substitute in that run instead.
    let transact_ix_data = build_valid_transact_ix_for_owner(&mut env, bound_owner.pubkey());
    let ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: vec![substitute_owner.pubkey()],
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&substitute_owner])
        .expect_err("a substituted input signer must fail proof verification");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    let (utxo_next, nullifier_next) = tree_progress(&env.rpc, &tree);
    assert_eq!(utxo_next, 1, "utxo tree must not advance past the deposit");
    assert_eq!(nullifier_next, 0, "nullifier queue must not advance");
    env.rpc
        .last_transaction_trace()
        .expect("substituted signer transaction trace")
        .assert_rolled_back_except(&[payer]);
}

/// INV-TRANSACT-20: the proof folds `hash_bytes(payer)` of accounts[0] as the
/// first element of the signer chain. Submitting the identical instruction
/// with a different signing payer must fail proof verification. The inputs are
/// bound to a separate owner in the signer run, so the payer hash is the only
/// public-input element that changes.
#[test]
fn transact_rejects_a_substituted_payer() {
    let mut env = proof_env();

    let tree = env.tree.pubkey();
    let fee_payer = env.rpc.payer.pubkey();
    let input_owner = Keypair::new();
    env.rpc
        .airdrop(&input_owner.pubkey(), 1_000_000)
        .expect("fund input owner account");
    let substitute_payer = Keypair::new();
    env.rpc
        .airdrop(&substitute_payer.pubkey(), 1_000_000)
        .expect("fund substitute payer account");

    // The proof binds the default payer's pubkey hash; the substitute signs at
    // index 0 in its place, so the on-chain recompute disagrees.
    let transact_ix_data = build_valid_transact_ix_for_owner(&mut env, input_owner.pubkey());
    let ix = Transact {
        payer: substitute_payer.pubkey(),
        input_tree: tree,
        output_tree: tree,
        owner_signers: vec![input_owner.pubkey()],
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&substitute_payer, &input_owner])
        .expect_err("a substituted payer must fail proof verification");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    let (utxo_next, nullifier_next) = tree_progress(&env.rpc, &tree);
    assert_eq!(utxo_next, 1, "utxo tree must not advance past the deposit");
    assert_eq!(nullifier_next, 0, "nullifier queue must not advance");
    env.rpc
        .last_transaction_trace()
        .expect("substituted payer transaction trace")
        .assert_rolled_back_except(&[fee_payer]);
}

/// INV-XC-15: a valid `transact` (tag 12) payload replayed byte-identically
/// under the `ring_transact` tag (15) must fail proof verification — the
/// external-data-hash preimage starts with the instruction discriminator and
/// the ring rail selects a different verifying-key family. The ring config is
/// fabricated at a keypair address (SPP-owned, exact size and discriminator)
/// and signs, so every check before proof verification passes.
#[test]
fn transact_rejects_replay_under_the_ring_transact_tag() {
    let mut env = proof_env();

    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let mut transact_ix_data = build_valid_transact_ix(&mut env);
    // Select the ring circuit family so the replay reaches proof verification:
    // the external-data hash the proof committed to uses the `transact`
    // discriminator, so verification must fail.
    transact_ix_data.circuit = CircuitId::RingEddsa(2, 3, N_PUBLIC_SLOTS as u8);
    let mut ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();
    *ix.data.first_mut().expect("instruction tag byte") = tag::RING_TRANSACT;

    // A structurally valid RingConfig at a keypair address: `load_ring_config`
    // accepts it, and the keypair signs in place of a ring's `ring_auth` PDA.
    // The ring loader reads it after the SPP + system-program prefix (index 5).
    let ring_config = write_signed_ring_config(&mut env, Pubkey::new_unique(), true);
    ix.accounts
        .insert(5, AccountMeta::new_readonly(ring_config.pubkey(), true));

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&ring_config])
        .expect_err("a transact proof replayed as ring_transact must be rejected");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    let (utxo_next, nullifier_next) = tree_progress(&env.rpc, &tree);
    assert_eq!(utxo_next, 1, "utxo tree must not advance past the deposit");
    assert_eq!(nullifier_next, 0, "nullifier queue must not advance");
    env.rpc
        .last_transaction_trace()
        .expect("cross-tag replay transaction trace")
        .assert_rolled_back_except(&[payer]);
}

/// INV-RING-TRANSACT-04: even when a confidential proof commits to the ring
/// instruction discriminator, it cannot be verified by the anonymous ring key
/// family. The signed RingConfig is valid, so the instruction reaches pairing.
#[test]
fn ring_transact_rejects_a_confidential_proof_bound_to_the_ring_tag() {
    let mut env = proof_env();

    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let mut transact_ix_data =
        build_valid_transact_ix_for_owner_with_discriminator(&mut env, payer, tag::RING_TRANSACT);
    transact_ix_data.circuit = CircuitId::RingEddsa(2, 3, N_PUBLIC_SLOTS as u8);
    let mut ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();
    *ix.data.first_mut().expect("instruction tag byte") = tag::RING_TRANSACT;

    let ring_config = write_signed_ring_config(&mut env, Pubkey::new_unique(), true);
    ix.accounts
        .insert(5, AccountMeta::new_readonly(ring_config.pubkey(), true));
    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&ring_config])
        .expect_err("a confidential proof must not verify on the ring rail");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    assert_eq!(
        tree_progress(&env.rpc, &tree),
        (1, 0),
        "rejected cross-family proof must roll back outputs and nullifiers"
    );
    env.rpc
        .last_transaction_trace()
        .expect("cross-family proof transaction trace")
        .assert_rolled_back_except(&[payer]);
}

/// INV-RING-TRANSACT-03: the `ring_program_id` public input comes from the
/// SIGNED RingConfig's stored `program_id`, never from instruction data. A
/// valid ring proof bound to ring A submitted with ring B's signed config
/// fails proof verification and rolls back; the byte-identical instruction
/// with ring A's config succeeds, isolating the ring binding as the only
/// difference.
#[test]
fn ring_transact_rejects_a_proof_bound_to_a_different_ring() {
    let mut env = proof_env();

    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    // The fixture ring program is the only real ring the deposit can bind; the
    // cross-ring negative uses an arbitrary second program id.
    let ring_a = Pubkey::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID);
    let ring_b = Pubkey::new_unique();

    let transact_ix_data = build_valid_ring_ix::<false>(&mut env, ring_a, 2, 3);
    let mut base_ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();
    *base_ix.data.first_mut().expect("instruction tag byte") = tag::RING_TRANSACT;

    let config_b = write_signed_ring_config(&mut env, ring_b, true);
    let mut wrong_ring_ix = base_ix.clone();
    wrong_ring_ix
        .accounts
        .insert(5, AccountMeta::new_readonly(config_b.pubkey(), true));
    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[wrong_ring_ix], &[&config_b])
        .expect_err("a ring proof submitted under a different ring's config must be rejected");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    let (utxo_next, nullifier_next) = tree_progress(&env.rpc, &tree);
    assert_eq!(utxo_next, 1, "utxo tree must not advance past the deposit");
    assert_eq!(nullifier_next, 0, "nullifier queue must not advance");
    env.rpc
        .last_transaction_trace()
        .expect("cross-ring transact transaction trace")
        .assert_rolled_back_except(&[payer]);

    // Positive control: the same bytes with the bound ring's signed config.
    let config_a = write_signed_ring_config(&mut env, ring_a, true);
    base_ix
        .accounts
        .insert(5, AccountMeta::new_readonly(config_a.pubkey(), true));
    env.rpc
        .create_and_send_default_payer_transaction(&[base_ix], &[&config_a])
        .expect("the same ring proof with the bound ring's config succeeds");
    let (utxo_next, nullifier_next) = tree_progress(&env.rpc, &tree);
    assert_eq!(utxo_next, 4, "deposit leaf plus three outputs appended");
    assert_eq!(nullifier_next, 2, "two nullifiers queued");
}

/// INV-RING-AUTH-07: `ring_authority_transact` binds the same
/// `ring_program_id` public input from the signing config, so a ring authority
/// cannot transition UTXOs proven for a different ring. A valid (2,2)
/// ring-authority proof bound to ring A fails under ring B's signed config and
/// succeeds under ring A's.
#[test]
fn ring_authority_transact_rejects_a_proof_bound_to_a_different_ring() {
    let mut env = proof_env();

    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let ring_a = Pubkey::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID);
    let ring_b = Pubkey::new_unique();

    // The ring-authority verifying keys cover only square shapes; use (2,2).
    let transact_ix_data = build_valid_ring_ix::<true>(&mut env, ring_a, 2, 2);
    let mut base_ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();
    *base_ix.data.first_mut().expect("instruction tag byte") = tag::RING_AUTHORITY_TRANSACT;

    // The authority variant requires `ring_authority_transact_is_enabled`.
    let config_b = write_signed_ring_config(&mut env, ring_b, true);
    let mut wrong_ring_ix = base_ix.clone();
    wrong_ring_ix
        .accounts
        .insert(5, AccountMeta::new_readonly(config_b.pubkey(), true));
    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[wrong_ring_ix], &[&config_b])
        .expect_err("a ring-authority proof under a different ring's config must be rejected");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    let (utxo_next, nullifier_next) = tree_progress(&env.rpc, &tree);
    assert_eq!(utxo_next, 1, "utxo tree must not advance past the deposit");
    assert_eq!(nullifier_next, 0, "nullifier queue must not advance");
    env.rpc
        .last_transaction_trace()
        .expect("cross-ring authority transaction trace")
        .assert_rolled_back_except(&[payer]);

    // Positive control: the same bytes with the bound ring's signed config.
    let config_a = write_signed_ring_config(&mut env, ring_a, true);
    base_ix
        .accounts
        .insert(5, AccountMeta::new_readonly(config_a.pubkey(), true));
    env.rpc
        .create_and_send_default_payer_transaction(&[base_ix], &[&config_a])
        .expect("the same ring-authority proof with the bound ring's config succeeds");
    let (utxo_next, nullifier_next) = tree_progress(&env.rpc, &tree);
    assert_eq!(utxo_next, 3, "deposit leaf plus two outputs appended");
    assert_eq!(nullifier_next, 2, "two nullifiers queued");
}

#[test]
fn ring_authority_transact_accepts_the_maximum_square_shape() {
    let mut env = proof_env();

    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let ring = Pubkey::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID);
    let transact_ix_data = build_valid_ring_ix::<true>(&mut env, ring, 4, 4);
    let mut ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();
    *ix.data.first_mut().expect("instruction tag byte") = tag::RING_AUTHORITY_TRANSACT;

    let ring_config = write_signed_ring_config(&mut env, ring, true);
    ix.accounts
        .insert(5, AccountMeta::new_readonly(ring_config.pubkey(), true));
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    env.rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[&ring_config])
        .expect("maximum-shape ring-authority transact");

    assert_eq!(
        tree_progress(&env.rpc, &tree),
        (5, 4),
        "one deposit plus four outputs and four queued nullifiers"
    );
}

#[test]
fn transact_rejects_an_overrunning_owner_signer_run() {
    let mut env = proof_env();

    let payer = env.rpc.payer.pubkey();
    let transact_ix_data = build_valid_transact_ix(&mut env);
    // The signer run is payer-first and deduplicated into a fixed-width
    // MAX_SIGNERS array; one more unique signer than fits must be rejected.
    let extra_signers: Vec<Keypair> = (0..MAX_SIGNERS).map(|_| Keypair::new()).collect();
    for signer in &extra_signers {
        env.rpc
            .airdrop(&signer.pubkey(), 1_000_000)
            .expect("fund owner signer");
    }
    let ix = Transact {
        payer,
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        owner_signers: extra_signers.iter().map(|signer| signer.pubkey()).collect(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();

    let signer_refs: Vec<&dyn Signer> = extra_signers
        .iter()
        .map(|signer| signer as &dyn Signer)
        .collect();
    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &signer_refs)
        .expect_err("an owner-signer run wider than MAX_SIGNERS must be rejected");
    Rejection::pool(ShieldedPoolError::InvalidTransactShape).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("out-of-range signer transaction trace")
        .assert_rolled_back_except(&[payer]);
}

/// Capacity gate (INV-TRANSACT-33): once the nullifier tree has strictly fewer
/// free leaves than the state tree, the on-chain `allow_dummy_inputs` public
/// input flips to false, so a proof built with dummy slots (the client-side
/// `allow_dummy_inputs = true` assumption) fails verification -- dummy-slot
/// proofs are locked out before the tree runs out of room to nullify them.
#[test]
fn transact_rejects_dummy_inputs_after_capacity_threshold() {
    let mut env = proof_env();

    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let transact_ix_data = build_valid_transact_ix(&mut env);

    // Move only the nullifier queue cursor so it has one fewer free leaf than
    // the state tree. The roots are unchanged, so the proof (built with the
    // normal `allow_dummy_inputs = true`) still reaches the program's
    // public-input verification -- only the flipped flag breaks it.
    let mut account = env.rpc.svm.get_account(&tree).expect("tree account");
    {
        let mut on_chain =
            TreeAccount::from_bytes(&mut account.data, tree.to_bytes()).expect("load tree");
        assert!(
            on_chain.allow_dummy_inputs().expect("dummy-input policy"),
            "fresh tree must allow dummy inputs"
        );
        let state_remaining = {
            let utxo = on_chain.utxo_tree();
            utxo.capacity() - utxo.next_index()
        };
        {
            let mut nullifier = on_chain.nullifer_tree();
            let next_leaf = nullifier
                .capacity
                .checked_sub(state_remaining)
                .expect("nullifier capacity exceeds state capacity")
                + 1;
            nullifier
                .queue_batches
                .get_current_batch_mut()
                .expect("current nullifier batch")
                .start_index = next_leaf;
        }
        assert!(
            !on_chain.allow_dummy_inputs().expect("dummy-input policy"),
            "fixture must cross the dummy-input threshold"
        );
    }
    env.rpc
        .svm
        .set_account(tree, account)
        .expect("write threshold tree account");

    let ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();

    let error = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("dummy inputs must be rejected after the capacity threshold");
    Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed).assert_litesvm(error);
    env.rpc
        .last_transaction_trace()
        .expect("capacity-gate transaction trace")
        .assert_rolled_back_except(&[payer]);
}
