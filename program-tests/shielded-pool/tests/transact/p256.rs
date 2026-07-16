//! Litesvm program-test for the P256 ownership rail of `transact`.
//!
//! A P256-owned UTXO is shielded via `deposit`, then a full withdrawal is built,
//! signed, and proved on the confidential P256 rail
//! (`transfer_p256_confidential_2_3`). The input is owned by a P256
//! [`ShieldedKeypair`], so the high-level client builder signs the transaction
//! with the P256 key, exposes the shared P256 signing key's raw x-coordinate
//! (`p256_signing_pk_x`), and produces a BSB22-committed Groth16 proof.
//!
//! Unlike the eddsa-rail tests, the witness is built by the production client
//! (`assemble` + `prove_transfer_p256`) rather than by hand: the P256 ECDSA
//! signature and message hash make a manual witness impractical, and reusing the
//! client exercises the exact `p256_signing_pk_x` wiring the program checks.
//!
//! The test asserts (1) the P256 rail is selected and the instruction exposes the
//! sender's raw confidential view tag as `p256_signing_pk_x`, (2) the committed proof
//! verifies against `transfer_p256_confidential_2_3`, and (3) the program's
//! 17-element confidential public-input hash, reconstructed from the instruction
//! and the on-chain tree roots/payer exactly as `transact::verify` does, equals
//! the value the proof commits to -- i.e. the program would accept this proof.
//! The eddsa rail's full on-chain `transact` flow is covered by `transact.rs` /
//! `shield_withdraw.rs`; the BSB22-committed P256 proof's on-chain Pedersen-PoK
//! pairing is exercised against a real validator by the `spp-test-validator`
//! suite (litesvm's syscall stubs do not evaluate it).
//!
//! Requires `cargo build-sbf -p shielded-pool-program`; the test skips (does not
//! fail) when the `.so` binary is missing.

#[path = "../common/setup.rs"]
mod common;
// The shared helper module is `#[path]`-included; this binary uses only a subset
// (the high-level client path), so silence unused-helper noise here.
#[path = "../common/transact.rs"]
#[allow(dead_code)]
mod transact_common;

use num_bigint::BigUint;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    assemble, ConfidentialTransfer, MerkleContext, MerkleProof, NonInclusionProof, ProverClient,
    ProverInputs, SpendProof, SppProofInputUtxo, WithdrawalTarget, STATE_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_keypair::{hash::owner_hash, shielded::ShieldedKeypair};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::ZolanaProgramTest;
use zolana_transaction::{AssetRegistry, Data, Utxo, SOL_MINT};
use zolana_tree::TreeAccount;

use crate::transact_common::{nullifier_tree, pack_proof, start_prover};

const AMOUNT: u64 = 1_000_000_000;

/// On-chain tree roots: the UTXO root at `utxo_index` and the nullifier root at
/// history index 0, exactly as the program reads them in `apply_tree`.
fn on_chain_roots(rpc: &ZolanaProgramTest, tree: &Pubkey, utxo_index: u16) -> ([u8; 32], [u8; 32]) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.get_utxo_tree_root(utxo_index).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
}

struct TransactEnv {
    rpc: ZolanaProgramTest,
    tree: Keypair,
}

impl TransactEnv {
    fn boot() -> Option<Self> {
        let mut rpc = common::program_test()?;
        start_prover().expect("start prover");
        let authority = Keypair::new();
        rpc.create_protocol_config(&authority)
            .expect("create protocol config");
        let tree = rpc
            .create_tree(common::tree_account_size(), &authority)
            .expect("create tree");
        Some(Self { rpc, tree })
    }
}

#[test]
fn p256_owned_input_withdraws_via_confidential_rail() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };

    let tree = env.tree.pubkey();
    let tree_address = Address::new_from_array(tree.to_bytes());
    let payer = env.rpc.payer.insecure_clone();
    let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
    let zero = [0u8; 32];

    // The shielded UTXO is owned by a P256 ShieldedKeypair (P256 signing key), so
    // the spend selects the confidential P256 rail.
    let sender = ShieldedKeypair::new().expect("sender keypair");
    let sender_nullifier_pk = sender.nullifier_key.pubkey().expect("sender nullifier pk");
    let blinding: [u8; 31] = [7u8; 31];
    let utxo = Utxo {
        owner: sender.signing_pubkey(),
        asset: SOL_MINT,
        amount: AMOUNT,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let owner_field =
        owner_hash(&sender.signing_pubkey(), &sender_nullifier_pk).expect("owner field");

    // Shield: deposit AMOUNT into the P256-owned UTXO.
    let event = env
        .rpc
        .deposit_sol(&tree, &payer, AMOUNT, owner_field, blinding)
        .expect("deposit");
    let utxo_hash = utxo
        .hash(&sender_nullifier_pk, &zero, &zero)
        .expect("utxo hash");
    assert_eq!(
        utxo_hash, event.utxo_hash,
        "client utxo hash matches on-chain"
    );

    // The UTXO is leaf 0; its inclusion proof is against the post-shield root at
    // history index 1. Reference trees seeded to match the on-chain roots.
    let (utxo_root, nullifier_root) = on_chain_roots(&env.rpc, &tree, 1);
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&utxo_hash).expect("append state leaf");
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");

    // Withdraw the full amount to an external SOL account via the high-level
    // client builder, padded to the (2,3) P256 shape.
    let recipient = Keypair::new().pubkey();

    let spend = SppProofInputUtxo::new(utxo, &sender);
    let mut transfer = ConfidentialTransfer::new(
        sender.shielded_address().expect("sender address"),
        vec![spend],
        payer_address,
    )
    .with_shape(zolana_transaction::instructions::transact::Shape::IN2_OUT3);
    transfer
        .withdraw(
            SOL_MINT,
            AMOUNT,
            WithdrawalTarget::Sol {
                user_sol_account: Address::new_from_array(recipient.to_bytes()),
            },
        )
        .expect("withdraw");
    let proof_inputs = transfer
        .sign(&sender, &AssetRegistry::default())
        .expect("sign p256 transaction");

    // One real input: build its state-inclusion + nullifier-non-inclusion proof
    // from the reference trees, with the on-chain root indices (utxo root at
    // history index 1, nullifier root at index 0).
    let commitments = proof_inputs.input_utxo_hashes().expect("input commitments");
    let commitment = commitments.first().expect("one input commitment");
    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("state proof")
        .to_vec();
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&commitment.nullifier))
        .expect("non inclusion proof");
    let spend_proof = SpendProof {
        state: MerkleProof {
            leaf: commitment.utxo_hash,
            merkle_context: MerkleContext {
                tree_type: 0,
                tree: tree_address,
            },
            path: state_path,
            leaf_index: 0,
            root: utxo_root,
            root_seq: 0,
            root_index: 1,
        },
        nullifier: NonInclusionProof {
            leaf: commitment.nullifier,
            merkle_context: MerkleContext {
                tree_type: 0,
                tree: tree_address,
            },
            path: non_inclusion.merkle_proof.to_vec(),
            low_element: non_inclusion.leaf_lower_range_value,
            low_element_index: non_inclusion.leaf_index as u64,
            high_element: non_inclusion.leaf_higher_range_value,
            high_element_index: 0,
            root: nullifier_root,
            root_seq: 0,
            root_index: 0,
        },
    };

    let assembled = assemble(proof_inputs, &[spend_proof]).expect("assemble");
    let expected_pi = assembled.public_input_hash;

    // The keypair-owned input selects the confidential P256 rail.
    let proof = match &assembled.prover_inputs {
        ProverInputs::P256(inputs) => ProverClient::local()
            .prove_transfer_p256(inputs)
            .expect("prove p256"),
        ProverInputs::Eddsa(_) => panic!("expected the P256 rail for a keypair-owned input"),
    };

    // The confidential P256 proof verifies against the committed verifying key
    // (`transfer_p256_confidential_2_3`, BSB22 Pedersen-PoK).
    {
        use groth16_solana::groth16::Groth16Verifier;
        use zolana_interface::verifying_keys::transfer_p256_confidential_2_3;
        let commitments = proof.commitment.expect("p256 proof carries a commitment");
        let public_inputs = [expected_pi];
        let mut verifier = Groth16Verifier::new_with_commitment(
            &proof.a,
            &proof.b,
            &proof.c,
            &commitments.commitment,
            &commitments.commitment_pok,
            &public_inputs,
            &transfer_p256_confidential_2_3::VERIFYINGKEY,
        )
        .expect("construct verifier");
        verifier.verify().expect("confidential p256 proof verifies");
    }

    let ix_data = assembled.with_proof(pack_proof(&proof).expect("pack proof"));

    // The instruction exposes the raw x-coordinate of the shared P256 signing key
    // (the sender's `confidential_view_tag`), which the program hashes on-chain to
    // recover the `p256_signing_pk_field` it folds into its public-input hash.
    let expected_x = sender
        .signing_pubkey()
        .confidential_view_tag()
        .expect("sender confidential view tag");
    assert_eq!(
        ix_data.p256_signing_pk_x,
        Some(expected_x),
        "exposed p256_signing_pk_x is the sender's raw confidential view tag (P256 x-coordinate)"
    );

    // Reconstruct the program's 17-element confidential public-input hash from the
    // instruction data and the on-chain state exactly as `transact::verify`
    // does, and assert it equals the value the proof commits to. This proves the
    // on-chain program would compute the identical public input for the P256 rail:
    // the eddsa rail's full on-chain `transact` flow is exercised by
    // `transact.rs` / `shield_withdraw.rs`; the BSB22-committed P256 proof's
    // on-chain pairing itself is verified against the committed vk above and on a
    // real validator by the `spp-test-validator` suite (litesvm's syscall stubs do
    // not evaluate the Pedersen-PoK pairing).
    {
        use zolana_hasher::{hash_chain::create_hash_chain_from_slice, sha256::Sha256BE, Hasher};
        use zolana_interface::instruction::{
            instruction_data::transact::{ExternalDataHash, ResolvedOutput},
            tag,
        };
        use zolana_keypair::hash::{hash_field, sha256};
        use zolana_transaction::instructions::transact::spp_proof_inputs::signed_to_field;

        // The program derives the P256 public input by hashing the raw x-coordinate
        // on-chain; mirror that here.
        let p256_x = ix_data
            .p256_signing_pk_x
            .expect("p256 signing pk x present");
        let p256_field = hash_field(&p256_x).expect("p256 signing pk field");
        let n_in = ix_data.inputs.len();
        let nullifiers: Vec<[u8; 32]> = ix_data.inputs.iter().map(|i| i.nullifier_hash).collect();
        // Every input is P256-owned (`eddsa_signer_index == 255`), so the program
        // routes its owner tag to the shared P256 signing key field.
        let input_owner: Vec<[u8; 32]> = vec![p256_field; n_in];
        let output_utxo_hashes: Vec<[u8; 32]> =
            ix_data.outputs.iter().map(|o| o.utxo_hash).collect();
        let output_owner = crate::transact_common::output_owner_pk_hashes(
            &ix_data.outputs,
            ix_data.p256_signing_pk_x.as_ref(),
        )
        .expect("output owner pk hashes");
        let resolved_outputs: Vec<ResolvedOutput> = ix_data
            .outputs
            .iter()
            .map(|output| {
                output
                    .into_resolved(ix_data.p256_signing_pk_x.as_ref(), |_| None)
                    .expect("resolve owner tag")
            })
            .collect();
        let external_data_hash = ExternalDataHash {
            spp_instruction_discriminator: tag::TRANSACT,
            expiry_unix_ts: ix_data.expiry_unix_ts,
            relayer_fee: ix_data.relayer_fee,
            public_sol_amount: ix_data.public_sol_amount,
            public_spl_amount: ix_data.public_spl_amount,
            user_sol_account: &recipient.to_bytes(),
            user_spl_token_account: &zero,
            spl_token_interface: &zero,
            data_hash: None,
            zone_data_hash: None,
            outputs: &resolved_outputs,
            messages: &ix_data.messages,
        }
        .hash()
        .expect("external data hash");
        let payer_pubkey_hash = Sha256BE::hash(&payer.pubkey().to_bytes()).expect("payer hash");
        let p256_message_hash = sha256(&ix_data.private_tx_hash);
        let chain = [
            create_hash_chain_from_slice(&nullifiers).unwrap(),
            create_hash_chain_from_slice(&output_utxo_hashes).unwrap(),
            create_hash_chain_from_slice(&vec![utxo_root; n_in]).unwrap(),
            create_hash_chain_from_slice(&vec![nullifier_root; n_in]).unwrap(),
            ix_data.private_tx_hash,
            hash_field(&p256_message_hash).unwrap(),
            external_data_hash,
            signed_to_field(ix_data.public_sol_amount.unwrap_or(0)),
            signed_to_field(ix_data.public_spl_amount.unwrap_or(0)),
            zero, // public_spl_asset_pubkey (no mint)
            zero, // zone_program_id
            payer_pubkey_hash,
            create_hash_chain_from_slice(&input_owner).unwrap(),
            create_hash_chain_from_slice(&output_owner).unwrap(),
            p256_field,
        ];
        let program_public_input = create_hash_chain_from_slice(&chain).unwrap();
        assert_eq!(
            program_public_input, expected_pi,
            "program-reconstructed public input matches the proof's"
        );
    }
}
