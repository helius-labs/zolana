use timelock_escrow_program::{
    instructions::{
        verifier::{verify_groth16, CompressedGroth16Proof},
        withdraw::{WithdrawProof, WithdrawPublicInput},
    },
    verifying_keys::withdraw::VERIFYINGKEY,
};
use timelock_escrow_prover::{CircuitId, WithdrawProofInputs};
use timelock_escrow_sdk::instructions::withdraw::{WithdrawProofInputParams, WithdrawTransaction};
use zolana_client::ProofInputUtxo;
use zolana_transaction::{
    instructions::transact::PrivateTxHash,
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    },
};

mod shared;
use shared::{creator, ensure_keys, escrow, funding, generated_vk, verifies, FUNDING, TREE_ID};

fn withdraw() -> WithdrawTransaction {
    let creator = creator();
    let escrow_utxo = escrow(&creator, funding(&creator, FUNDING), 250)
        .escrow_utxo()
        .clone();
    WithdrawProofInputParams {
        escrow_utxo,
        escrow_leaf_index: 1,
        payer: creator
            .shielded_address()
            .expect("creator address")
            .solana_address()
            .expect("creator solana address"),
        expiry_unix_ts: 2_000_000_000,
        output_tree_id: TREE_ID,
    }
    .build(&creator)
    .expect("withdraw transaction")
}

#[test]
fn program_vk_has_no_commitment() {
    assert_eq!(
        (
            VERIFYINGKEY.nr_pubinputs,
            VERIFYINGKEY.vk_commitment.is_none(),
            VERIFYINGKEY.vk_ic.len()
        ),
        (1, true, 2)
    );
}

#[test]
fn withdraw_prove_verify() {
    ensure_keys(CircuitId::Withdraw);
    let inputs = withdraw().to_proof_inputs().expect("withdraw proof inputs");
    let proof = inputs.prove().expect("prove failed");
    let program_proof: WithdrawProof = proof.into();

    assert_eq!(
        (
            verifies(
                &generated_vk(CircuitId::Withdraw),
                &proof,
                inputs.public.public_input_hash
            ),
            verify_groth16(
                CompressedGroth16Proof {
                    a: &program_proof.proof_a,
                    b: &program_proof.proof_b,
                    c: &program_proof.proof_c,
                    commitment: None,
                },
                inputs.public.public_input_hash,
                &VERIFYINGKEY,
            )
            .is_ok(),
        ),
        (true, true),
        "the withdraw proof must verify under the generated and the committed key; run `just ensure-escrow-keys`"
    );
}

#[test]
fn withdraw_rejects_tampered_public_input() {
    ensure_keys(CircuitId::Withdraw);
    let inputs = withdraw().to_proof_inputs().expect("withdraw proof inputs");
    let proof = inputs.prove().expect("prove failed");
    let mut tampered = inputs.public.public_input_hash;
    tampered[31] ^= 0x01;

    assert!(!verifies(
        &generated_vk(CircuitId::Withdraw),
        &proof,
        tampered
    ));
}

#[test]
fn withdraw_that_pays_another_owner_does_not_prove() {
    ensure_keys(CircuitId::Withdraw);
    let transaction = withdraw();
    let mut inputs: WithdrawProofInputs = transaction
        .to_proof_inputs()
        .expect("withdraw proof inputs");
    let escrow_utxo = transaction.escrow_utxo();
    let first_nullifier = inputs.tx.first_nullifier;
    let output_blinding = derive_transact_output_blinding(
        &first_nullifier,
        &derive_output_blinding_seed(&first_nullifier, &inputs.tx.blinding_seed)
            .expect("output blinding seed"),
        0,
    )
    .expect("output blinding");
    let payment_to_another_owner = ProofInputUtxo::new(
        [9u8; 32],
        &escrow_utxo.asset().asset,
        escrow_utxo.amount(),
        &output_blinding,
        TREE_ID,
    )
    .expect("payment to another owner");
    inputs.public.private_tx_hash = PrivateTxHash::new(
        &[inputs.escrow_utxo.utxo.hash().expect("escrow utxo hash")],
        &[payment_to_another_owner.hash().expect("payment hash")],
        &inputs.tx.external_data_hash,
        &derive_private_tx_blinding(&first_nullifier, &inputs.tx.blinding_seed)
            .expect("private tx blinding"),
    )
    .hash()
    .expect("private tx hash");
    inputs.public.public_input_hash = WithdrawPublicInput {
        private_tx_hash: &inputs.public.private_tx_hash,
        unlock: inputs.escrow_utxo.state.unlock,
        owner_pk_field: &inputs.owner_pk_field,
    }
    .hash()
    .expect("public input hash");

    assert!(inputs.prove().is_err());
}

fn with_public_input(
    mut inputs: WithdrawProofInputs,
    unlock: u64,
    owner_pk_field: [u8; 32],
) -> WithdrawProofInputs {
    inputs.owner_pk_field = owner_pk_field;
    inputs.public.public_input_hash = WithdrawPublicInput {
        private_tx_hash: &inputs.public.private_tx_hash,
        unlock,
        owner_pk_field: &owner_pk_field,
    }
    .hash()
    .expect("public input hash");
    inputs
}

#[test]
fn withdraw_rejects_another_unlock_or_signer() {
    ensure_keys(CircuitId::Withdraw);
    let inputs = withdraw().to_proof_inputs().expect("withdraw proof inputs");
    let unlock = inputs.escrow_utxo.state.unlock;
    let owner_pk_field = inputs.owner_pk_field;

    assert_eq!(
        (
            with_public_input(inputs.clone(), unlock, owner_pk_field)
                .prove()
                .is_ok(),
            with_public_input(inputs.clone(), unlock + 1, owner_pk_field)
                .prove()
                .is_err(),
            with_public_input(inputs, unlock, [9u8; 32])
                .prove()
                .is_err(),
        ),
        (true, true, true)
    );
}
