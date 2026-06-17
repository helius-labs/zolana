#[path = "transact_core.rs"]
mod transact_core;

pub use transact_core::{
    build_transfer_prover_inputs, dummy_input, dummy_ix_output, eddsa_input_utxo,
    external_data_hash, fe, ix_output, new_transact_ix_data, prove_and_verify_transfer,
    public_input_hash, start_prover, TransferProverInputsArgs,
};

use anyhow::{Context, Result};
use light_hasher::Poseidon;
use light_merkle_tree_reference::indexed::{IndexedMerkleTree, NonInclusionProof};
use num_bigint::BigUint;
use zolana_client::private_transaction::field::{
    be, right_align_slice, signed_to_field, BN254_MODULUS_DEC,
};
use zolana_client::{TransferInput, TransferOutput, UtxoInputs, NULLIFIER_TREE_HEIGHT};
use zolana_keypair::NullifierKey;
use zolana_transaction::{OutputUtxo, Utxo};

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
