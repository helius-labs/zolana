//! Shared test helpers for shielded-pool `transact` proof wiring.

use anyhow::{anyhow, Result};
use groth16_solana::groth16::Groth16Verifier;
use zolana_client::private_transaction::field::{be, hash_chain};
use zolana_client::{
    spawn_prover, Proof, ProofCompressed, ProverClient, TransferInput, TransferInputs,
    TransferOutput, UtxoInputs, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
};
use zolana_interface::instruction::instruction_data::transact::{
    ExternalDataHash, InputUtxo, TransactIxData,
};
use zolana_interface::instruction::{instruction_data::transact as transact_ix, tag};
use zolana_interface::verifying_keys::transfer_2_3;
use zolana_keypair::hash::hash_field;

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
    let compressed = ProofCompressed::try_from(*proof)?;
    let mut out = [0u8; 192];
    out[0..32].copy_from_slice(&compressed.a);
    out[32..96].copy_from_slice(&compressed.b);
    out[96..128].copy_from_slice(&compressed.c);
    if let Some(commitment) = compressed.commitment {
        out[128..160].copy_from_slice(&commitment.commitment);
        out[160..192].copy_from_slice(&commitment.commitment_pok);
    }
    Ok(out)
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
    sender_utxo_data: transact_ix::OutputUtxo,
    recipient_utxo_data: Vec<transact_ix::OutputUtxo>,
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
        sender_utxo_data,
        recipient_utxo_data,
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
        sender_utxo_data: &transact_ix_data.sender_utxo_data,
        recipient_utxo_data: &transact_ix_data.recipient_utxo_data,
    }
    .hash()?)
}

pub fn ix_output(view_tag: [u8; 32], utxo_hash: [u8; 32]) -> transact_ix::OutputUtxo {
    transact_ix::OutputUtxo {
        view_tag,
        utxo_hash,
        data: Vec::new(),
    }
}

pub fn dummy_ix_output() -> transact_ix::OutputUtxo {
    ix_output([0u8; 32], [0u8; 32])
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
