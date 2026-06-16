//! Litesvm program-test for a SOL shield then unshield (withdrawal) via the
//! `transact` instruction with a real Groth16 proof.
//!
//! Flow: `proofless_shield` deposits SOL into one UTXO owned by the payer's
//! Ed25519 key, then `transact` spends that UTXO (a real, non-dummy input) to
//! withdraw the full amount to an external account. The input carries a real
//! state-inclusion proof against the on-chain UTXO tree root and a real
//! nullifier non-inclusion proof against the on-chain nullifier tree root, both
//! built from in-test reference trees and gated against the on-chain roots. The
//! Solana-only eddsa rail is used: the payer signs and the program reconstructs
//! its owner hash.
//!
//! Requires `cargo build-sbf -p shielded-pool-program` to have produced the
//! `.so` binary; the test skips (does not fail) when it is missing.

#[path = "../common/mod.rs"]
#[allow(dead_code)] // shared helpers; this target uses only a subset
mod common;

use groth16_solana::groth16::Groth16Verifier;
use light_hasher::{sha256::Sha256BE, Hasher, Poseidon};
use light_merkle_tree_reference::indexed::IndexedMerkleTree;
use light_merkle_tree_reference::MerkleTree;
use num_bigint::BigUint;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::private_transaction::field::{
    be, hash_chain, right_align_slice, signed_to_field, BN254_MODULUS_DEC,
};
use zolana_client::{
    spawn_prover, Proof, ProofCompressed, ProverClient, TransferInput, TransferInputs,
    TransferOutput, UtxoInputs, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_interface::instruction::instruction_data::transact::{
    ExternalDataHash, InputUtxo, OutputUtxo, TransactIxData,
};
use zolana_interface::instruction::tag;
use zolana_interface::pda;
use zolana_interface::verifying_keys::transfer_2_3;
use zolana_keypair::hash::{hash_field, owner_hash};
use zolana_keypair::pubkey::PublicKey;
use zolana_keypair::NullifierKey;
use zolana_program_test::ZolanaProgramTest;
use zolana_transaction::transaction::private_tx_hash;
use zolana_transaction::{Data, Utxo, SOL_MINT};
use zolana_tree::TreeAccount;

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);
const AMOUNT: u64 = 1_000_000_000;

fn start_prover() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var(
            "ZOLANA_PROVER_KEYS_DIR",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../prover/server/proving-keys"
            ),
        );
    });
    spawn_prover().expect("start prover");
}

/// A field element holding `value` in its low 8 bytes (big-endian).
fn fe(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Read on-chain tree roots: the UTXO root at `utxo_index` and the nullifier
/// root at history index 0, exactly as the program reads them in `apply_tree`.
fn on_chain_roots(rpc: &ZolanaProgramTest, tree: &Pubkey, utxo_index: u16) -> ([u8; 32], [u8; 32]) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.get_utxo_tree_root(utxo_index).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
}

fn pack_proof(proof: &Proof) -> [u8; 192] {
    let compressed = ProofCompressed::try_from(*proof).expect("compress proof");
    let mut out = [0u8; 192];
    out[0..32].copy_from_slice(&compressed.a);
    out[32..96].copy_from_slice(&compressed.b);
    out[96..128].copy_from_slice(&compressed.c);
    if let Some(commitment) = compressed.commitment {
        out[128..160].copy_from_slice(&commitment.commitment);
        out[160..192].copy_from_slice(&commitment.commitment_pok);
    }
    out
}

/// Mirror of `transact::verify::TransactProof::public_input_hash` for the eddsa
/// rail, parameterized by the public SOL amount field (non-zero for a withdrawal).
#[allow(clippy::too_many_arguments)]
fn transact_public_input_hash(
    nullifiers: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
    utxo_roots: &[[u8; 32]],
    nullifier_tree_roots: &[[u8; 32]],
    private_tx: &[u8; 32],
    external_data_hash: &[u8; 32],
    public_sol_amount: &[u8; 32],
    payer_pubkey_hash: &[u8; 32],
    solana_owner_pk_hashes: &[[u8; 32]],
) -> [u8; 32] {
    let zero = [0u8; 32];
    let chain = [
        hash_chain(nullifiers).expect("nullifier chain"),
        hash_chain(output_hashes).expect("output chain"),
        hash_chain(utxo_roots).expect("utxo root chain"),
        hash_chain(nullifier_tree_roots).expect("nullifier root chain"),
        *private_tx,
        hash_field(&zero).expect("p256 message field"),
        *external_data_hash,
        *public_sol_amount,
        zero, // public_spl_amount
        zero, // public_spl_asset_pubkey
        zero, // program_id_hashchain
        *payer_pubkey_hash,
        zero, // data_hash
        zero, // zone_data_hash
        hash_chain(solana_owner_pk_hashes).expect("owner chain"),
    ];
    hash_chain(&chain).expect("public input hash")
}

/// One circuit-dummy input carrying a chosen nullifier plus the real tree roots
/// and payer owner hash.
fn dummy_input(
    nullifier: &[u8; 32],
    roots: ([u8; 32], [u8; 32]),
    owner_hash: &[u8; 32],
) -> TransferInput {
    let (utxo_root, nullifier_root) = roots;
    let zero = [0u8; 32];
    TransferInput {
        utxo: UtxoInputs::new_dummy(),
        is_dummy: be(&fe(1)),
        state_path_elements: vec![be(&zero); STATE_TREE_HEIGHT],
        state_path_index: be(&zero),
        nullifier_low_value: be(&zero),
        nullifier_next_value: be(&zero),
        nullifier_low_path_elements: vec![be(&zero); NULLIFIER_TREE_HEIGHT],
        nullifier_low_path_index: be(&zero),
        utxo_tree_root: be(&utxo_root),
        nullifier_tree_root: be(&nullifier_root),
        nullifier: be(nullifier),
        solana_owner_pk_hash: be(owner_hash),
        nullifier_secret: be(&zero),
    }
}

struct TransactEnv {
    rpc: ZolanaProgramTest,
    tree: Keypair,
}

impl TransactEnv {
    fn boot() -> Option<Self> {
        let mut rpc = common::program_test()?;
        start_prover();
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
fn shield_then_withdraw_sol() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };

    let tree = env.tree.pubkey();
    let payer = env.rpc.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    // The shielded UTXO is owned by the payer's Ed25519 key (eddsa rail). Fixed
    // blinding / nullifier secret keep the run deterministic.
    let blinding: [u8; 31] = [7u8; 31];
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo = Utxo {
        owner: PublicKey::from_ed25519(&payer_bytes),
        asset: SOL_MINT,
        amount: AMOUNT,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let owner_pk_hash = utxo.owner.hash().expect("owner pk hash");
    let owner_field = owner_hash(&utxo.owner, &nullifier_pk).expect("owner field");

    // Shield: deposit AMOUNT into the UTXO. The vault (cpi_authority) is funded.
    let owner_utxo_h = utxo
        .owner_utxo_hash(&nullifier_pk)
        .expect("owner utxo hash");
    let event = env
        .rpc
        .proofless_shield_sol(&tree, &payer, AMOUNT, owner_utxo_h)
        .expect("proofless shield");

    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
    assert_eq!(
        utxo_hash, event.utxo_hash,
        "client utxo hash must match on-chain"
    );

    // The UTXO is leaf 0; its inclusion proof is against the root AFTER the
    // shield append (history index 1).
    let (utxo_root, nullifier_root) = on_chain_roots(&env.rpc, &tree, 1);

    // State inclusion proof (height 26) for leaf 0.
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&utxo_hash).expect("append state leaf");
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("state proof")
        .to_vec();

    // Nullifier non-inclusion proof (height 40). The reference tree is seeded
    // with the BN254 p-1 sentinel, matching the on-chain NULLIFIER_TREE_INIT_ROOT.
    let modulus_minus_one =
        BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10).expect("modulus") - 1u32;
    let nf_tree = IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(
        NULLIFIER_TREE_HEIGHT,
        0,
        modulus_minus_one,
    )
    .expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &blinding)
        .expect("nullifier");
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
        .expect("non inclusion proof");

    let roots = (utxo_root, nullifier_root);
    let dummy_nullifier = fe(2);

    // The real input spending the shielded UTXO (is_dummy = 0).
    let real_input = TransferInput {
        utxo: UtxoInputs::new(&owner_field, &utxo.asset, utxo.amount, &utxo.blinding)
            .expect("utxo inputs"),
        is_dummy: be(&fe(0)),
        state_path_elements: state_path.iter().map(be).collect(),
        state_path_index: be(&fe(0)),
        nullifier_low_value: be(&non_inclusion.leaf_lower_range_value),
        nullifier_next_value: be(&non_inclusion.leaf_higher_range_value),
        nullifier_low_path_elements: non_inclusion.merkle_proof.iter().map(be).collect(),
        nullifier_low_path_index: be(&fe(non_inclusion.leaf_index as u64)),
        utxo_tree_root: be(&utxo_root),
        nullifier_tree_root: be(&nullifier_root),
        nullifier: be(&nullifier),
        solana_owner_pk_hash: be(&owner_pk_hash),
        nullifier_secret: be(&right_align_slice(nullifier_key.secret()).expect("secret")),
    };

    // Withdrawal: spend AMOUNT, no change. Recipient is an external SOL account.
    let recipient = Keypair::new().pubkey();
    env.rpc
        .airdrop(&recipient, 1_000_000)
        .expect("airdrop recipient");
    let recipient_before = env
        .rpc
        .svm
        .get_balance(&recipient)
        .expect("recipient balance");
    // SOL is custodied in the `sol_interface` PDA (funded by the deposit, drained
    // on withdrawal) — shared with the proofless-shield deposit path.
    let vault = pda::sol_interface();
    // Draining the full amount closes the vault (a system account at 0 lamports
    // is reaped), so read balances with `unwrap_or(0)`.
    let vault_before = env.rpc.svm.get_balance(&vault).unwrap_or(0);

    let dummy_output = || OutputUtxo {
        view_tag: zero,
        utxo_hash: zero,
        data: Vec::new(),
    };

    let mut ix_data = TransactIxData {
        proof: [0u8; 192],
        expiry_unix_ts: u64::MAX,
        relayer_fee: 0,
        private_tx_hash: zero,
        inputs: vec![
            InputUtxo {
                nullifier_hash: nullifier,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 1,
                tree_index: 0,
                eddsa_signer_index: 0,
            },
            InputUtxo {
                nullifier_hash: dummy_nullifier,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 1,
                tree_index: 0,
                eddsa_signer_index: 0,
            },
        ],
        public_sol_amount: Some(-(AMOUNT as i64)),
        public_spl_amount: None,
        cpi_signer: None,
        tx_viewing_pk: [0u8; 33],
        sender_utxo_data: dummy_output(),
        recipient_utxo_data: vec![dummy_output(), dummy_output()],
    };

    let external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: tag::TRANSACT,
        expiry_unix_ts: ix_data.expiry_unix_ts,
        relayer_fee: ix_data.relayer_fee,
        public_sol_amount: ix_data.public_sol_amount,
        public_spl_amount: ix_data.public_spl_amount,
        user_sol_account: &recipient.to_bytes(),
        user_spl_token_account: &zero,
        spl_token_interface: &zero,
        cpi_signer: ix_data.cpi_signer,
        sender_utxo_data: &ix_data.sender_utxo_data,
        recipient_utxo_data: &ix_data.recipient_utxo_data,
    }
    .hash()
    .expect("external data hash");

    // private_tx_hash uses the real input's utxo hash; the dummy input and all
    // outputs contribute zero.
    let private_tx = private_tx_hash(&[utxo_hash, zero], &[zero, zero, zero], &external_data_hash)
        .expect("private tx hash");
    let public_sol_field = signed_to_field(-(AMOUNT as i128));
    let payer_pubkey_hash = Sha256BE::hash(&payer_bytes).expect("payer hash");

    let public_input_hash = transact_public_input_hash(
        &[nullifier, dummy_nullifier],
        &[zero, zero, zero],
        &[utxo_root, utxo_root],
        &[nullifier_root, nullifier_root],
        &private_tx,
        &external_data_hash,
        &public_sol_field,
        &payer_pubkey_hash,
        &[owner_pk_hash, owner_pk_hash],
    );

    let witness = TransferInputs {
        inputs: vec![
            real_input,
            dummy_input(&dummy_nullifier, roots, &owner_pk_hash),
        ],
        outputs: vec![
            TransferOutput::new_dummy(),
            TransferOutput::new_dummy(),
            TransferOutput::new_dummy(),
        ],
        external_data_hash: be(&external_data_hash),
        private_tx_hash: be(&private_tx),
        public_sol_amount: be(&public_sol_field),
        public_spl_amount: be(&zero),
        public_spl_asset_pubkey: be(&zero),
        program_id_hashchain: be(&zero),
        payer_pubkey_hash: be(&payer_pubkey_hash),
        data_hash: be(&zero),
        zone_data_hash: be(&zero),
        public_input_hash: be(&public_input_hash),
    };

    let proof = ProverClient::local()
        .prove_transfer(&witness)
        .expect("prove transact");

    let public_inputs = [public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        &transfer_2_3::VERIFYINGKEY,
    )
    .expect("construct verifier");
    verifier.verify().expect("groth16 proof verifies");

    ix_data.proof = pack_proof(&proof);
    ix_data.private_tx_hash = private_tx;

    // SOL withdrawal account layout: payer (signer/owner), tree, sol_interface
    // (the SOL-custody PDA), recipient, then the system program (settle_sol
    // Transfer CPI) and the program (emit_event self-CPI).
    let bytes = ix_data.serialize().expect("serialize transact ix data");
    let mut instruction_data = vec![tag::TRANSACT];
    instruction_data.extend_from_slice(&bytes);
    let ix = Instruction {
        program_id: env.rpc.program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(tree, false),
            AccountMeta::new(vault, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(env.rpc.program_id, false),
        ],
        data: instruction_data,
    };

    let result = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[]);
    assert!(result.is_ok(), "transact withdrawal failed: {result:?}");

    let recipient_after = env.rpc.svm.get_balance(&recipient).unwrap_or(0);
    let vault_after = env.rpc.svm.get_balance(&vault).unwrap_or(0);
    assert_eq!(
        recipient_after,
        recipient_before + AMOUNT,
        "recipient credited"
    );
    assert_eq!(vault_after, vault_before - AMOUNT, "vault debited");
}
