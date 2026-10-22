use dynamic_swap_program::instructions::{
    deposit_liquidity::PoolDepositPublicInput,
    shared::u64_right_align,
    verifier::{verify_groth16, CompressedGroth16Proof},
};
use dynamic_swap_prover::PoolDepositProofInputs;
use dynamic_swap_sdk::{
    instructions::deposit_liquidity::DepositProofInputParams,
    shared::{pad_spp_outputs, transaction_blindings},
    state::{pool_authority_address, PoolUtxo},
};
use solana_pubkey::Pubkey;
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_transaction::{
    instructions::transact::{asset_field, ExternalData, PrivateTxHash, SppProofInputs},
    utxo::SppProofInputUtxo,
    Address, Data, Mint, Utxo,
};

const INPUT_TREE_ID: u16 = 3;
const OUTPUT_TREE_ID: u16 = 7;
const AMOUNT: u64 = 1_000;
const BLINDING_SEED: [u8; 32] = [6; 32];

fn destination() -> Mint {
    Mint::new(Address::new_from_array([2; 32]), 3)
}

fn source_in(asset: Mint, amount: u64) -> SppProofInputUtxo {
    let depositor = ShieldedKeypair::new_ed25519().unwrap();
    zolana_test_utils::utxo::wallet(
        Utxo {
            owner: depositor.signing_pubkey(),
            asset,
            amount,
            blinding: [4; 32],
            ring_program_id: None,
            data: Data::default(),
        },
        &depositor.nullifier_key,
        INPUT_TREE_ID,
        0,
        None,
        None,
    )
    .unwrap()
    .into()
}

fn sample() -> DepositProofInputParams {
    let pair = Pubkey::new_from_array([9; 32]);
    let pool_authority = pool_authority_address(&pair, ViewingKey::new().pubkey());
    let source_in = source_in(destination(), AMOUNT);
    let (private_tx_blinding, blindings) =
        transaction_blindings(&source_in.nullifier, &BLINDING_SEED, 1).unwrap();
    DepositProofInputParams {
        source_in,
        pool_out: PoolUtxo {
            asset: destination(),
            amount: AMOUNT,
            booked: AMOUNT,
            blinding: *blindings.first().unwrap(),
        },
        pool_authority,
        amount: AMOUNT,
        destination_asset: asset_field(&destination().asset).unwrap(),
        private_tx_blinding,
        tree_id: OUTPUT_TREE_ID,
    }
}

fn public_hash(inputs: &PoolDepositProofInputs) -> [u8; 32] {
    PoolDepositPublicInput {
        private_tx_hash: &inputs.private_tx_hash,
        pool_authority_owner_hash: &inputs.pool_authority_owner_hash,
        destination_asset: &inputs.destination_asset,
        amount: inputs.amount,
    }
    .hash()
    .unwrap()
}

// Keep transcript hashes consistent so attacks reach the circuit's own checks.
fn refresh_hashes(inputs: &mut PoolDepositProofInputs) {
    inputs.private_tx_hash = PrivateTxHash::new(
        &[inputs.source_in.hash().unwrap()],
        &[inputs.pool_out.hash().unwrap()],
        &inputs.private_tx_blinding,
    )
    .hash()
    .unwrap();
    inputs.public_input_hash = public_hash(inputs);
}

#[test]
fn deposit_proves_and_verifies() {
    let inputs = sample().to_proof_inputs().unwrap();
    let proof = inputs.prove().expect("prove deposit");
    assert!(verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        public_hash(&inputs),
        &dynamic_swap_program::verifying_keys::pool_deposit::VERIFYINGKEY,
    )
    .is_ok());
}

/// SPP proves the deposit at IN1_OUT2 with a compact second output. It enters
/// SPP's private transaction hash as 0, so that hash equals the one the deposit
/// circuit commits to over the source and the pool note.
#[test]
fn spp_padding_leaves_the_private_tx_hash_unchanged() {
    let params = sample();
    let inputs = params.to_proof_inputs().unwrap();
    let padded = pad_spp_outputs(SppProofInputs {
        input_utxos: vec![params.source_in.clone()],
        output_utxos: vec![params.pool_out.output_utxo(&params.pool_authority).unwrap()],
        blinding_seed: BLINDING_SEED,
        output_tree_id: OUTPUT_TREE_ID,
        external_data: ExternalData::new([0; 33], [0; 16], vec![], vec![], vec![]),
        payer: Address::new_from_array([8; 32]),
        cache_accounts: Default::default(),
    })
    .unwrap();
    assert_eq!(padded.output_utxos.len(), 2);
    assert_eq!(
        padded.private_tx_blinding().unwrap(),
        params.private_tx_blinding
    );
    let output_hashes: Vec<[u8; 32]> = padded
        .output_utxos
        .iter()
        .map(|output| {
            if output.is_dummy() {
                [0; 32]
            } else {
                output.hash(OUTPUT_TREE_ID).unwrap()
            }
        })
        .collect();
    let spp_hash = PrivateTxHash::new(
        &[params.source_in.hash()],
        &output_hashes,
        &params.private_tx_blinding,
    )
    .hash()
    .unwrap();
    assert_eq!(spp_hash, inputs.private_tx_hash);
}

#[test]
fn deposit_rejects_unbacked_or_misbooked_pool_notes() {
    let good = sample().to_proof_inputs().unwrap();
    for attack in 0..7 {
        let mut inputs = good.clone();
        match attack {
            // Re-depositing a pool note would book the same tokens twice.
            0 => inputs.source_in.owner_hash = inputs.pool_authority_owner_hash,
            // A source smaller than the booked deposit.
            1 => inputs.source_in.amount = u64_right_align(AMOUNT - 1),
            // A source in another asset.
            2 => inputs.source_in.asset = [1; 32],
            // Books less than it holds, or holds less than it books.
            3 => inputs.pool_out.data_hash = u64_right_align(AMOUNT - 1),
            4 => inputs.pool_out.amount = u64_right_align(AMOUNT - 1),
            // A note outside the pool.
            5 => inputs.pool_out.owner_hash = [1; 32],
            // Claims more liquidity than the note carries.
            _ => inputs.amount = AMOUNT + 1,
        }
        refresh_hashes(&mut inputs);
        assert!(inputs.prove().is_err(), "accepted deposit attack {attack}");
    }
}

#[test]
fn sdk_rejects_invalid_deposits() {
    let mut params = sample();
    params.pool_out.booked = AMOUNT - 1;
    assert!(params
        .to_proof_inputs()
        .unwrap_err()
        .to_string()
        .contains("book the full deposited amount"));

    let mut params = sample();
    params.source_in = source_in(destination(), AMOUNT + 1);
    assert!(params
        .to_proof_inputs()
        .unwrap_err()
        .to_string()
        .contains("source_in amount"));
}
