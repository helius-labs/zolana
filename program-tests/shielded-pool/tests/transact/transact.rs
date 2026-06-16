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
//! Requires `cargo build-sbf -p shielded-pool-program` to have produced the
//! `.so` binary; the test skips (does not fail) when it is missing.

#[path = "../common/mod.rs"]
#[allow(dead_code)] // shared helpers; this target uses only a subset
mod common;

use groth16_solana::groth16::Groth16Verifier;
use light_hasher::{sha256::Sha256BE, Hasher};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::private_transaction::field::{be, hash_chain};
use zolana_client::{
    spawn_prover, Proof, ProofCompressed, ProverClient, TransferInput, TransferInputs,
    TransferOutput, UtxoInputs, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_interface::instruction::instruction_data::transact::{
    ExternalDataHash, InputUtxo, OutputUtxo, TransactIxData,
};
use zolana_interface::instruction::tag;
use zolana_interface::verifying_keys::transfer_2_3;
use zolana_keypair::hash::hash_field;
use zolana_program_test::ZolanaProgramTest;
use zolana_transaction::transaction::private_tx_hash;
use zolana_tree::TreeAccount;

/// Start a prover server (once), pointed at the in-repo proving keys, so
/// `transact` scenarios can request real Groth16 proofs.
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

/// The (utxo, nullifier) tree roots at history index 0, exactly as the program
/// reads them during `apply_tree`.
fn tree_roots(rpc: &ZolanaProgramTest, tree: &Pubkey) -> ([u8; 32], [u8; 32]) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.get_utxo_tree_root(0).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
}

/// Pack an uncompressed proof into the 192-byte on-chain layout the `transact`
/// verifier expects: compressed `a` (32) || compressed `b` (64) || compressed
/// `c` (32) || commitment (32) || commitment_pok (32). The eddsa rail has no
/// commitment, so the trailing 64 bytes stay zero.
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
/// rail (no public amounts, no program/zone authorization).
#[allow(clippy::too_many_arguments)]
fn transact_public_input_hash(
    nullifiers: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
    utxo_roots: &[[u8; 32]],
    nullifier_tree_roots: &[[u8; 32]],
    private_tx: &[u8; 32],
    external_data_hash: &[u8; 32],
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
        zero, // public_sol_amount
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
/// and payer owner hash. `is_dummy = 1` waives the merkle/nullifier proofs, so
/// the path elements are zero, but the nullifier, roots, and owner hash are the
/// values the program reconstructs and the public-input hash binds.
fn dummy_input(nullifier: &[u8; 32], roots: ([u8; 32], [u8; 32]), owner_hash: &[u8; 32]) -> TransferInput {
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

/// Boot a program-test environment with a protocol config and one pool tree,
/// the shared precondition for every `transact` scenario.
struct TransactEnv {
    rpc: ZolanaProgramTest,
    tree: Keypair,
}

impl TransactEnv {
    /// Returns `None` when the program `.so` is missing so callers can skip.
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
fn transact_sends_valid_proof() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };

    let payer = env.rpc.payer.pubkey();
    let payer_bytes = payer.to_bytes();
    let roots = tree_roots(&env.rpc, &env.tree.pubkey());
    let (utxo_root, nullifier_root) = roots;
    let zero = [0u8; 32];

    // Two circuit-dummy inputs with distinct non-zero nullifiers (the program
    // inserts both into the nullifier tree; zeros or duplicates are rejected).
    let nullifiers = [fe(1), fe(2)];
    let dummy_output = || OutputUtxo {
        view_tag: zero,
        utxo_hash: zero,
        data: Vec::new(),
    };

    // Instruction data; `proof` and `private_tx_hash` are filled in once the
    // external-data hash (which excludes both) is known.
    let mut ix_data = TransactIxData {
        proof: [0u8; 192],
        expiry_unix_ts: u64::MAX,
        relayer_fee: 0,
        private_tx_hash: zero,
        inputs: nullifiers
            .iter()
            .map(|nullifier| InputUtxo {
                nullifier_hash: *nullifier,
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 0,
                tree_index: 0,
                eddsa_signer_index: 0,
            })
            .collect(),
        public_sol_amount: None,
        public_spl_amount: None,
        cpi_signer: None,
        tx_viewing_pk: [0u8; 33],
        sender_utxo_data: dummy_output(),
        recipient_utxo_data: vec![dummy_output(), dummy_output()],
    };

    // external_data_hash via the shared interface struct: the program computes
    // the identical value on-chain. No settlement, so the account fields are 0.
    let external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: tag::TRANSACT,
        expiry_unix_ts: ix_data.expiry_unix_ts,
        relayer_fee: ix_data.relayer_fee,
        public_sol_amount: ix_data.public_sol_amount,
        public_spl_amount: ix_data.public_spl_amount,
        user_sol_account: &zero,
        user_spl_token_account: &zero,
        spl_token_interface: &zero,
        cpi_signer: ix_data.cpi_signer,
        sender_utxo_data: &ix_data.sender_utxo_data,
        recipient_utxo_data: &ix_data.recipient_utxo_data,
    }
    .hash()
    .expect("external data hash");

    // Dummy inputs/outputs contribute zero hashes to private_tx_hash.
    let private_tx = private_tx_hash(
        &[zero, zero],
        &[zero, zero, zero],
        &external_data_hash,
    )
    .expect("private tx hash");

    // Values the program reconstructs from accounts[0] (the payer).
    let owner_hash = hash_field(&payer_bytes).expect("owner hash");
    let payer_pubkey_hash = Sha256BE::hash(&payer_bytes).expect("payer hash");

    let public_input_hash = transact_public_input_hash(
        &nullifiers,
        &[zero, zero, zero],
        &[utxo_root, utxo_root],
        &[nullifier_root, nullifier_root],
        &private_tx,
        &external_data_hash,
        &payer_pubkey_hash,
        &[owner_hash, owner_hash],
    );

    let witness = TransferInputs {
        inputs: vec![
            dummy_input(&nullifiers[0], roots, &owner_hash),
            dummy_input(&nullifiers[1], roots, &owner_hash),
        ],
        outputs: vec![
            TransferOutput::new_dummy(),
            TransferOutput::new_dummy(),
            TransferOutput::new_dummy(),
        ],
        external_data_hash: be(&external_data_hash),
        private_tx_hash: be(&private_tx),
        public_sol_amount: be(&zero),
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

    // Sanity: the proof verifies off-chain against the committed verifying key.
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

    // Accounts: `[payer (signer), tree (writable)]`. Index 0 is the fee payer
    // and the eddsa signer the inputs reference (`eddsa_signer_index = 0`).
    let bytes = ix_data.serialize().expect("serialize transact ix data");
    let mut instruction_data = vec![tag::TRANSACT];
    instruction_data.extend_from_slice(&bytes);
    let ix = Instruction {
        program_id: env.rpc.program_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(env.tree.pubkey(), false),
            // Self-CPI target for `emit_event`; the program account must be
            // loadable in the transaction.
            AccountMeta::new_readonly(env.rpc.program_id, false),
        ],
        data: instruction_data,
    };

    let result = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[]);
    assert!(result.is_ok(), "transact failed: {result:?}");
}
