use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::Groth16Verifier,
};
use solana_address::Address;
use swap_program::verifying_keys::{cancel, create, fill_verifiable_encryption};
use swap_sdk::{
    instructions::{
        cancel::CancelSharedInputs, create_swap::CreateSharedInputs,
        fill_verifiable_encryption::FillVerifiableEncryptionSharedInputs,
    },
    order::{BlindingField, OrderTerms, SOL_ASSET_ID},
};
use zolana_keypair::ShieldedKeypair;

const SOL_MINT: Address = Address::new_from_array([0u8; 32]);

fn destination_mint() -> Address {
    Address::new_from_array([7u8; 32])
}

fn sample_terms() -> OrderTerms {
    let mut maker_owner_hash = [0u8; 32];
    maker_owner_hash[31] = 99;
    let mut maker_viewing_pk = [0u8; 33];
    maker_viewing_pk[0] = 2;
    let mut taker_pk_fe = [0u8; 32];
    taker_pk_fe[31] = 123;
    OrderTerms {
        source_asset_id: SOL_ASSET_ID,
        source_amount: 1_000,
        destination_asset_id: 2,
        destination_mint: destination_mint(),
        destination_amount: 250,
        maker_owner_hash,
        maker_viewing_pk,
        expiry: 1_700_000_000,
        taker_pk_fe,
        fill_mode: swap_prover::FILL_MODE_VERIFIABLE,
    }
}

fn fe(byte: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = byte;
    out
}

fn verify_standard_groth16(
    vk: &groth16_solana::groth16::Groth16Verifyingkey,
    proof_a: &[u8; 32],
    proof_b: &[u8; 64],
    proof_c: &[u8; 32],
    public_input: [u8; 32],
) -> bool {
    let a = match decompress_g1(proof_a) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let b = match decompress_g2(proof_b) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let c = match decompress_g1(proof_c) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let public_inputs = [public_input];
    let mut verifier = match Groth16Verifier::new(&a, &b, &c, &public_inputs, vk) {
        Ok(v) => v,
        Err(_) => return false,
    };
    verifier.verify().is_ok()
}

fn verify_with_commitment(
    vk: &groth16_solana::groth16::Groth16Verifyingkey,
    proof_a: &[u8; 32],
    proof_b: &[u8; 64],
    proof_c: &[u8; 32],
    commitment: &[u8; 32],
    commitment_pok: &[u8; 32],
    public_input: [u8; 32],
) -> bool {
    let a = match decompress_g1(proof_a) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let b = match decompress_g2(proof_b) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let c = match decompress_g1(proof_c) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let commitment = match decompress_g1(commitment) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let commitment_pok = match decompress_g1(commitment_pok) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let public_inputs = [public_input];
    let mut verifier = match Groth16Verifier::new_with_commitment(
        &a,
        &b,
        &c,
        &commitment,
        &commitment_pok,
        &public_inputs,
        vk,
    ) {
        Ok(v) => v,
        Err(_) => return false,
    };
    verifier.verify().is_ok()
}

#[test]
fn create_two_proof_private_tx_hash_matches() {
    let taker = ShieldedKeypair::from_seed_ed25519(&fe(0x4d)).expect("taker keypair");
    let taker_address = taker.shielded_address().expect("taker address");

    let create_inputs = CreateSharedInputs {
        terms: sample_terms(),
        escrow_blinding: blinding_from_byte(7),
        taker_address,
        source_input_hash: fe(5),
        change_amount: 750,
        change_blinding: fe(6),
        external_data_hash: fe(8),
    };

    let sdk_private_tx_hash = create_inputs
        .sdk_private_tx_hash(SOL_MINT)
        .expect("sdk private_tx_hash");
    let escrow_output_hash = create_inputs
        .escrow_output(SOL_MINT)
        .expect("escrow output")
        .hash()
        .expect("escrow hash");

    let create_proof_output = create_inputs
        .create_proof_inputs(SOL_MINT)
        .expect("create proof inputs")
        .prove()
        .expect("swap create prove");

    assert_eq!(
        escrow_output_hash, create_proof_output.escrow_hash,
        "SDK escrow output hash must equal the swap create circuit's escrow hash"
    );
    assert_eq!(
        sdk_private_tx_hash, create_proof_output.private_tx_hash,
        "SDK private_tx_hash must equal the swap create circuit's private_tx_hash"
    );

    assert!(
        verify_standard_groth16(
            &create::VERIFYINGKEY,
            &create_proof_output.proof.proof_a,
            &create_proof_output.proof.proof_b,
            &create_proof_output.proof.proof_c,
            create_proof_output.public_input_hash,
        ),
        "swap create proof must verify against the create verifying key"
    );
}

#[test]
fn fill_two_proof_private_tx_hash_matches() {
    let maker = ShieldedKeypair::from_seed_ed25519(&fe(0x51)).expect("maker keypair");
    let maker_recipient = maker.shielded_address().expect("maker address");
    let taker = ShieldedKeypair::from_seed_ed25519(&fe(0x4d)).expect("taker keypair");
    let taker_recipient = taker.shielded_address().expect("taker address");
    let taker_address = taker.owner_hash().expect("taker owner hash");

    let mut terms = sample_terms();
    terms.taker_pk_fe = taker
        .signing_pubkey()
        .owner_pk_field()
        .expect("taker pk_fe");
    terms.maker_owner_hash = maker.owner_hash().expect("maker owner hash");
    terms.maker_viewing_pk = *maker.viewing_pubkey().as_bytes();

    let fill_inputs = FillVerifiableEncryptionSharedInputs {
        terms,
        escrow_blinding: blinding_from_byte(7),
        taker_in_blinding: blinding_from_byte(13),
        destination_output_blinding: blinding_from_byte(21),
        source_output_blinding: blinding_from_byte(31),
        external_data_hash: fe(8),
        maker_recipient,
        taker_recipient,
    };

    let sdk_private_tx_hash = fill_inputs
        .sdk_private_tx_hash(SOL_MINT, destination_mint())
        .expect("sdk private_tx_hash");

    assert_eq!(
        fill_inputs
            .destination_output(destination_mint())
            .owner_hash()
            .expect("owner hash"),
        fill_inputs.terms.maker_owner_hash,
        "fill destination_output recipient owner_hash must equal the committed maker address"
    );
    assert_eq!(
        fill_inputs
            .source_output(SOL_MINT)
            .owner_hash()
            .expect("owner hash"),
        taker_address,
        "fill source_output recipient owner_hash must equal the taker's owner hash"
    );

    let inputs = fill_inputs
        .fill_proof_inputs(SOL_MINT, destination_mint())
        .expect("fill proof inputs");
    let fill_proof_output = inputs.prove().expect("swap fill prove");

    assert_eq!(
        fill_inputs
            .escrow_output(SOL_MINT)
            .expect("escrow")
            .hash()
            .expect("h"),
        fill_proof_output.escrow_hash,
        "escrow hash"
    );
    assert_eq!(
        fill_inputs
            .taker_utxo(destination_mint())
            .hash()
            .expect("h"),
        fill_proof_output.taker_utxo_hash,
        "taker utxo hash"
    );
    assert_eq!(
        fill_inputs
            .destination_output(destination_mint())
            .hash()
            .expect("h"),
        fill_proof_output.destination_output_hash,
        "destination output hash"
    );
    assert_eq!(
        fill_inputs.source_output(SOL_MINT).hash().expect("h"),
        fill_proof_output.source_output_hash,
        "source output hash"
    );

    assert_eq!(
        sdk_private_tx_hash, fill_proof_output.private_tx_hash,
        "SDK private_tx_hash must equal the swap fill circuit's private_tx_hash"
    );

    assert_eq!(
        zolana_keypair::merge::merge_ciphertext_hash(&fill_proof_output.ciphertext)
            .expect("ct hash"),
        fill_proof_output.ct_hash,
        "recomputed ciphertext hash must match the fill proof's committed ct_hash"
    );

    let (commitment, commitment_pok) = fill_proof_output
        .proof
        .commitment
        .expect("fill proof carries a BSB22 commitment");
    assert!(
        verify_with_commitment(
            &fill_verifiable_encryption::VERIFYINGKEY,
            &fill_proof_output.proof.proof_a,
            &fill_proof_output.proof.proof_b,
            &fill_proof_output.proof.proof_c,
            &commitment,
            &commitment_pok,
            fill_proof_output.public_input_hash,
        ),
        "swap fill proof must verify (with commitment) against the fill verifying key"
    );

    let (asset, amount) = inputs
        .decrypt_destination(&fill_proof_output.ciphertext)
        .expect("maker decrypts destination ciphertext");
    let expected_asset = swap_prover::asset_field(fill_inputs.terms.destination_mint.as_array())
        .expect("destination asset field");
    assert_eq!(
        (asset, amount),
        (expected_asset, fill_inputs.terms.destination_amount),
        "maker must recover (destination_asset, destination_amount) from the verifiable encryption"
    );
}

#[test]
fn cancel_two_proof_private_tx_hash_matches() {
    let maker = ShieldedKeypair::from_seed_ed25519(&fe(0x51)).expect("maker keypair");
    let maker_recipient = maker.shielded_address().expect("maker address");
    let taker = ShieldedKeypair::from_seed_ed25519(&fe(0x4d)).expect("taker keypair");
    let taker_viewing_pk = taker
        .shielded_address()
        .expect("taker address")
        .viewing_pubkey;
    let mut terms = sample_terms();
    terms.maker_owner_hash = maker.owner_hash().expect("maker owner hash");
    terms.maker_viewing_pk = *maker.viewing_pubkey().as_bytes();

    let cancel_inputs = CancelSharedInputs {
        terms,
        escrow_blinding: blinding_from_byte(7),
        taker_viewing_pk,
        source_output_blinding: blinding_from_byte(19),
        external_data_hash: fe(8),
        maker_recipient,
    };

    assert_eq!(
        cancel_inputs
            .source_output(SOL_MINT)
            .owner_hash()
            .expect("owner hash"),
        cancel_inputs.terms.maker_owner_hash,
        "cancel source_output recipient owner_hash must equal the committed maker address"
    );

    let sdk_private_tx_hash = cancel_inputs
        .sdk_private_tx_hash(SOL_MINT)
        .expect("sdk private_tx_hash");

    let cancel_proof_output = cancel_inputs
        .cancel_proof_inputs(SOL_MINT)
        .expect("cancel proof inputs")
        .prove()
        .expect("swap cancel prove");

    assert_eq!(
        sdk_private_tx_hash, cancel_proof_output.private_tx_hash,
        "SDK private_tx_hash must equal the swap cancel circuit's private_tx_hash"
    );

    assert!(
        verify_standard_groth16(
            &cancel::VERIFYINGKEY,
            &cancel_proof_output.proof.proof_a,
            &cancel_proof_output.proof.proof_b,
            &cancel_proof_output.proof.proof_c,
            cancel_proof_output.public_input_hash,
        ),
        "swap cancel proof must verify against the cancel verifying key"
    );
}

fn blinding_from_byte(byte: u8) -> zolana_transaction::Blinding {
    let mut blinding = [0u8; 31];
    if let Some(last) = blinding.last_mut() {
        *last = byte;
    }
    debug_assert_eq!(blinding.to_field(), fe(byte));
    blinding
}
