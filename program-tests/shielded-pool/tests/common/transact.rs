#[path = "transact_core.rs"]
mod transact_core;

// The shared helper module is `#[path]`-included into several test binaries;
// not every binary uses every re-export (e.g. only the photon e2e uses
// `pack_proof`), so suppress unused-import noise here rather than per binary.
#[allow(unused_imports)]
pub use transact_core::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo,
    external_data_hash, fe, ix_output_ciphertext, new_transact_ix_data, pack_proof,
    prove_and_verify_transfer, public_input_hash, start_prover, TransferProverInputsArgs,
};

use anyhow::{Context, Result};
use num_bigint::BigUint;
use zolana_client::private_transaction::field::{
    be, hash_chain, right_align_slice, signed_to_field, BN254_MODULUS_DEC,
};
use zolana_client::{
    TransferInput, TransferInputs, TransferOutput, UtxoInputs, NULLIFIER_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_interface::instruction::{
    instruction_data::transact::{ExternalDataHash, TransactIxData},
    tag,
};
use zolana_keypair::hash::hash_field;
use zolana_keypair::NullifierKey;
use zolana_merkle_tree::indexed::{IndexedMerkleTree, NonInclusionProof};
use zolana_transaction::{OutputUtxo, Utxo};

/// Mirror of `public_input_hash` for the SPL rail: the `public_spl_amount`
/// (chain index 8) and `public_spl_asset_pubkey` (`hash_field(mint)`, index 9)
/// fields carry real values instead of zero.
#[allow(dead_code, clippy::too_many_arguments)]
pub fn public_input_hash_spl(
    nullifiers: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
    utxo_roots: &[[u8; 32]],
    nullifier_tree_roots: &[[u8; 32]],
    private_tx: &[u8; 32],
    external_data_hash: &[u8; 32],
    public_spl_amount: &[u8; 32],
    mint: &[u8; 32],
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
        *public_spl_amount,
        hash_field(mint).expect("public spl asset pubkey"),
        zero, // program_id_hashchain
        *payer_pubkey_hash,
        zero, // data_hash
        zero, // zone_data_hash
        hash_chain(solana_owner_pk_hashes).expect("owner chain"),
    ];
    hash_chain(&chain).expect("public input hash spl")
}

/// Mirror of `build_transfer_prover_inputs` for the SPL rail: the witness carries
/// the real `public_spl_amount` and `public_spl_asset_pubkey` (the mint).
#[allow(dead_code)]
pub fn build_transfer_prover_inputs_spl(
    args: TransferProverInputsArgs,
    public_spl_amount: [u8; 32],
    mint: [u8; 32],
) -> TransferInputs {
    let zero = [0u8; 32];
    TransferInputs {
        inputs: args.inputs,
        outputs: args.outputs,
        external_data_hash: be(&args.external_data_hash),
        private_tx_hash: be(&args.private_tx_hash),
        public_sol_amount: be(&zero),
        public_spl_amount: be(&public_spl_amount),
        public_spl_asset_pubkey: be(&hash_field(&mint).expect("spl asset field")),
        program_id_hashchain: be(&zero),
        payer_pubkey_hash: be(&args.payer_pubkey_hash),
        data_hash: be(&zero),
        zone_data_hash: be(&zero),
        public_input_hash: be(&args.public_input_hash),
    }
}

/// `external_data_hash` for an SPL settlement: zeroes `user_sol_account` and
/// binds the user's SPL token account and the pool's SPL interface vault, exactly
/// as the program's `settlement_accounts` does for the SPL rail.
#[allow(dead_code)]
pub fn external_data_hash_spl(
    transact_ix_data: &TransactIxData,
    user_spl_token_account: &[u8; 32],
    spl_token_interface: &[u8; 32],
) -> Result<[u8; 32]> {
    let zero = [0u8; 32];
    Ok(ExternalDataHash {
        spp_instruction_discriminator: tag::TRANSACT,
        expiry_unix_ts: transact_ix_data.expiry_unix_ts,
        relayer_fee: transact_ix_data.relayer_fee,
        public_sol_amount: transact_ix_data.public_sol_amount,
        public_spl_amount: transact_ix_data.public_spl_amount,
        user_sol_account: &zero,
        user_spl_token_account,
        spl_token_interface,
        cpi_signer: transact_ix_data.cpi_signer,
        output_utxo_hashes: &transact_ix_data.output_utxo_hashes,
        output_ciphertexts: &transact_ix_data.output_ciphertexts,
    }
    .hash()?)
}

pub fn nullifier_tree() -> Result<IndexedMerkleTree<Poseidon, usize>> {
    let modulus_minus_one = BigUint::parse_bytes(BN254_MODULUS_DEC.as_bytes(), 10)
        .context("parse bn254 modulus")?
        - 1u32;
    Ok(IndexedMerkleTree::<Poseidon, usize>::new_with_next_value(
        NULLIFIER_TREE_HEIGHT,
        0,
        modulus_minus_one,
    )?)
}

pub struct SpendInputArgs<'a> {
    pub utxo: &'a Utxo,
    pub owner_field: &'a [u8; 32],
    pub state_path: &'a [[u8; 32]],
    pub state_path_index: u64,
    pub non_inclusion: &'a NonInclusionProof,
    pub roots: ([u8; 32], [u8; 32]),
    pub nullifier: &'a [u8; 32],
    pub owner_pk_hash: &'a [u8; 32],
    pub nullifier_key: &'a NullifierKey,
}

pub fn spend_input(args: SpendInputArgs<'_>) -> Result<TransferInput> {
    let (utxo_root, nullifier_root) = args.roots;
    Ok(TransferInput {
        utxo: UtxoInputs::new(
            args.owner_field,
            &args.utxo.asset,
            args.utxo.amount,
            &args.utxo.blinding,
        )?,
        is_dummy: be(&fe(0)),
        state_path_elements: args.state_path.iter().map(be).collect(),
        state_path_index: be(&fe(args.state_path_index)),
        nullifier_low_value: be(&args.non_inclusion.leaf_lower_range_value),
        nullifier_next_value: be(&args.non_inclusion.leaf_higher_range_value),
        nullifier_low_path_elements: args.non_inclusion.merkle_proof.iter().map(be).collect(),
        nullifier_low_path_index: be(&fe(args.non_inclusion.leaf_index as u64)),
        utxo_tree_root: be(&utxo_root),
        nullifier_tree_root: be(&nullifier_root),
        nullifier: be(args.nullifier),
        solana_owner_pk_hash: be(args.owner_pk_hash),
        nullifier_secret: be(&right_align_slice(args.nullifier_key.secret())?),
    })
}

#[allow(dead_code)]
pub fn transfer_output(output: &OutputUtxo) -> Result<TransferOutput> {
    let hash = output.hash()?;
    Ok(TransferOutput {
        utxo: UtxoInputs::from_output(output)?,
        is_dummy: be(&fe(0)),
        hash: be(&hash),
    })
}

pub fn public_sol_field(amount: Option<i64>) -> [u8; 32] {
    amount
        .map(|amount| signed_to_field(amount as i128))
        .unwrap_or_default()
}
