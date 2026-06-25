//! Shared test helpers for shielded-pool `transact` proof wiring.

use anyhow::{anyhow, Result};
use groth16_solana::groth16::Groth16Verifier;
use zolana_client::{
    private_transaction::field::{be, hash_chain},
    spawn_prover, Proof, ProofCompressed, ProverClient, TransferInput, TransferInputs,
    TransferOutput, UtxoInputs, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_interface::{
    instruction::{
        instruction_data::{
            transact as transact_ix,
            transact::{ExternalDataHash, InputUtxo, TransactIxData},
        },
        tag,
    },
    verifying_keys::transfer_2_3,
};
use zolana_keypair::hash::hash_field;
use zolana_transaction::OutputUtxo;

pub fn start_prover() -> Result<()> {
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
    spawn_prover()?;
    Ok(())
}

/// A field element holding `value` in its low 8 bytes (big-endian).
pub fn fe(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

pub fn pack_proof(proof: &Proof) -> Result<[u8; 192]> {
    Ok(ProofCompressed::try_from(*proof)?.to_transact_proof_bytes())
}

/// Mirror of the eddsa-only `TransactProof::public_input_hash`.
#[allow(clippy::too_many_arguments)]
pub fn public_input_hash(
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
/// and signer owner hash.
pub fn dummy_input(
    nullifier: &[u8; 32],
    roots: ([u8; 32], [u8; 32]),
    owner_hash: &[u8; 32],
) -> TransferInput {
    let (utxo_root, nullifier_root) = roots;
    let zero = [0u8; 32];
    TransferInput {
        // A circuit-dummy input carries a chosen `nullifier`; the circuit skips its
        // ownership/inclusion/nullifier-derivation checks, so the utxo blinding is
        // unused here.
        utxo: UtxoInputs::new_dummy(be(&zero)),
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

pub fn eddsa_input_utxo(nullifier_hash: [u8; 32], utxo_tree_root_index: u16) -> InputUtxo {
    InputUtxo {
        nullifier_hash,
        nullifier_tree_root_index: 0,
        utxo_tree_root_index,
        tree_index: 0,
        eddsa_signer_index: 0,
    }
}

pub fn new_transact_ix_data(
    inputs: Vec<InputUtxo>,
    public_sol_amount: Option<i64>,
    output_utxo_hashes: Vec<[u8; 32]>,
    output_ciphertexts: Vec<transact_ix::OutputCiphertext>,
) -> TransactIxData {
    TransactIxData {
        proof: [0u8; 192],
        expiry_unix_ts: u64::MAX,
        relayer_fee: 0,
        private_tx_hash: [0u8; 32],
        inputs,
        public_sol_amount,
        public_spl_amount: None,
        cpi_signer: None,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        output_utxo_hashes,
        output_ciphertexts,
    }
}

pub fn external_data_hash(
    transact_ix_data: &TransactIxData,
    user_sol_account: &[u8; 32],
) -> Result<[u8; 32]> {
    let zero = [0u8; 32];
    Ok(ExternalDataHash {
        spp_instruction_discriminator: tag::TRANSACT,
        expiry_unix_ts: transact_ix_data.expiry_unix_ts,
        relayer_fee: transact_ix_data.relayer_fee,
        public_sol_amount: transact_ix_data.public_sol_amount,
        public_spl_amount: transact_ix_data.public_spl_amount,
        user_sol_account,
        user_spl_token_account: &zero,
        spl_token_interface: &zero,
        cpi_signer: transact_ix_data.cpi_signer,
        output_utxo_hashes: &transact_ix_data.output_utxo_hashes,
        output_ciphertexts: &transact_ix_data.output_ciphertexts,
    }
    .hash()?)
}

pub fn ix_output_ciphertext(view_tag: [u8; 32]) -> transact_ix::OutputCiphertext {
    transact_ix::OutputCiphertext {
        view_tag,
        data: Vec::new(),
    }
}

/// A dummy output (`owner_hash = 0`) over a chosen `blinding`, assembled exactly as
/// the production prover does (`assemble_outputs`): it gets a real `utxo_hash` that
/// the program appends to the tree and the proof commits via the public output
/// chain, while contributing `0` to `private_tx_hash`. Returns the witness output
/// and that hash so callers can wire both consistently.
pub fn dummy_transfer_output(blinding: &[u8; 31]) -> Result<(TransferOutput, [u8; 32])> {
    let output = OutputUtxo {
        owner_hash: [0u8; 32],
        blinding: *blinding,
        ..Default::default()
    };
    let hash = output
        .hash()
        .map_err(|e| anyhow!("dummy output hash: {e:?}"))?;
    let utxo = UtxoInputs::from_output(&output).map_err(|e| anyhow!("dummy output utxo: {e:?}"))?;
    Ok((
        TransferOutput {
            utxo,
            is_dummy: be(&fe(1)),
            hash: be(&hash),
        },
        hash,
    ))
}

pub struct TransferProverInputsArgs {
    pub inputs: Vec<TransferInput>,
    pub outputs: Vec<TransferOutput>,
    pub external_data_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub public_sol_amount: [u8; 32],
    pub payer_pubkey_hash: [u8; 32],
    pub public_input_hash: [u8; 32],
}

pub fn build_transfer_prover_inputs(args: TransferProverInputsArgs) -> TransferInputs {
    let zero = [0u8; 32];
    TransferInputs {
        inputs: args.inputs,
        outputs: args.outputs,
        external_data_hash: be(&args.external_data_hash),
        private_tx_hash: be(&args.private_tx_hash),
        public_sol_amount: be(&args.public_sol_amount),
        public_spl_amount: be(&zero),
        public_spl_asset_pubkey: be(&zero),
        program_id_hashchain: be(&zero),
        payer_pubkey_hash: be(&args.payer_pubkey_hash),
        data_hash: be(&zero),
        zone_data_hash: be(&zero),
        public_input_hash: be(&args.public_input_hash),
    }
}

pub fn prove_and_verify_transfer(
    prover_inputs: &TransferInputs,
    public_input_hash: [u8; 32],
    label: &str,
) -> Result<[u8; 192]> {
    let proof = ProverClient::local().prove_transfer(prover_inputs)?;
    let public_inputs = [public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        &transfer_2_3::VERIFYINGKEY,
    )
    .map_err(|err| anyhow!("construct {label} verifier: {err:?}"))?;
    verifier
        .verify()
        .map_err(|err| anyhow!("verify {label} proof: {err:?}"))?;
    pack_proof(&proof)
}
