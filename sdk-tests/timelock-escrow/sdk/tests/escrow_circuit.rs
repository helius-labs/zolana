use timelock_escrow_program::{
    instructions::{
        escrow::{slot, EscrowProof, EscrowPublicInput},
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    verifying_keys::escrow::VERIFYINGKEY,
};
use timelock_escrow_prover::{CircuitId, EscrowProofInputs, ProofInputUtxo};
use timelock_escrow_sdk::{
    instructions::escrow::EscrowTransaction,
    state::EscrowTerms,
    zk_program::{NewProgramUtxo, ProgramState},
};
use zolana_transaction::{
    instructions::transact::PrivateTxHash, utxo::derive_private_tx_blinding, Mint,
};

mod shared;
use shared::{
    creator, ensure_keys, escrow, escrow_params, generated_vk, keypair, source, verifies, FUNDING,
    TREE_ID, UNLOCK,
};

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
fn escrow_prove_verify() {
    ensure_keys(CircuitId::Escrow);
    let creator = creator();
    let inputs = escrow(&creator, source(&creator, FUNDING), 250)
        .to_proof_inputs()
        .expect("escrow proof inputs");
    let proof = inputs.prove().expect("prove failed");
    let program_proof: EscrowProof = proof.into();

    assert_eq!(
        (
            verifies(
                &generated_vk(CircuitId::Escrow),
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
        "the escrow proof must verify under the generated and the committed key; run `just ensure-escrow-keys`"
    );
}

#[test]
fn escrow_rejects_tampered_public_input() {
    ensure_keys(CircuitId::Escrow);
    let creator = creator();
    let inputs = escrow(&creator, source(&creator, FUNDING), 250)
        .to_proof_inputs()
        .expect("escrow proof inputs");
    let proof = inputs.prove().expect("prove failed");
    let mut tampered = inputs.public.public_input_hash;
    tampered[31] ^= 0x01;

    assert!(!verifies(
        &generated_vk(CircuitId::Escrow),
        &proof,
        tampered
    ));
}

#[test]
fn escrow_rejects_zero_amount() {
    ensure_keys(CircuitId::Escrow);
    let creator = creator();

    assert!(escrow(&creator, source(&creator, FUNDING), 0)
        .to_proof_inputs()
        .expect("escrow proof inputs")
        .prove()
        .is_err());
}

#[test]
fn escrow_zero_change_proves() {
    ensure_keys(CircuitId::Escrow);
    let creator = creator();
    let inputs = escrow(&creator, source(&creator, FUNDING), FUNDING)
        .to_proof_inputs()
        .expect("escrow proof inputs");
    let proof = inputs.prove().expect("prove failed");

    assert!(verifies(
        &generated_vk(CircuitId::Escrow),
        &proof,
        inputs.public.public_input_hash
    ));
}

#[test]
fn escrow_outputs_are_derived_from_the_transaction_blinding_seed() {
    ensure_keys(CircuitId::Escrow);
    let creator = creator();
    let mut inputs = escrow(&creator, source(&creator, FUNDING), 250)
        .to_proof_inputs()
        .expect("escrow proof inputs");
    inputs.tx.blinding_seed[31] ^= 0x01;

    assert!(inputs.prove().is_err());
}

fn with_source(transaction: &EscrowTransaction, source: ProofInputUtxo) -> EscrowProofInputs {
    let mut inputs = transaction.to_proof_inputs().expect("escrow proof inputs");
    let built = transaction.transaction();
    inputs.source = source;
    inputs.public.private_tx_hash = PrivateTxHash::new(
        &[inputs.source.hash().expect("source hash"), [0u8; 32]],
        &[
            *built.output_hash(slot::CHANGE).expect("change hash"),
            *built.output_hash(slot::ESCROW).expect("escrow hash"),
        ],
        &inputs.tx.external_data_hash,
        &derive_private_tx_blinding(&inputs.tx.first_nullifier, &inputs.tx.blinding_seed)
            .expect("private tx blinding"),
    )
    .hash()
    .expect("private tx hash");
    inputs.public.public_input_hash = EscrowPublicInput {
        private_tx_hash: &inputs.public.private_tx_hash,
        escrow_owner_hash: &inputs.public.escrow_owner_hash,
    }
    .hash()
    .expect("public input hash");
    inputs
}

#[test]
fn escrow_spends_only_the_creator_s_source() {
    ensure_keys(CircuitId::Escrow);
    let creator = creator();
    let transaction = escrow(&creator, source(&creator, FUNDING), 250);
    let own_source =
        ProofInputUtxo::try_from(transaction.source().expect("source")).expect("source inputs");
    let locked_escrow = transaction
        .escrow_utxo()
        .proof_inputs()
        .expect("escrow inputs")
        .utxo;
    let other_source =
        ProofInputUtxo::try_from(&source(&keypair(6), FUNDING)).expect("other source inputs");

    assert_eq!(
        (
            with_source(&transaction, own_source).prove().is_ok(),
            with_source(&transaction, locked_escrow).prove().is_err(),
            with_source(&transaction, other_source).prove().is_err(),
            escrow_params(&creator, source(&keypair(6), FUNDING), 250)
                .build(&creator)
                .err()
                .map(|e| e.to_string()),
        ),
        (
            true,
            true,
            true,
            Some("the source belongs to another owner than the creator".to_string())
        )
    );
}

#[test]
fn the_escrow_utxo_carries_its_terms_and_rebuilds_from_them() {
    let creator = creator();
    let transaction = escrow(&creator, source(&creator, FUNDING), 250);
    let escrow_utxo = transaction.escrow_utxo();
    let stored = transaction
        .transaction()
        .output(slot::ESCROW)
        .expect("escrow output")
        .data
        .utxo_data()
        .expect("escrow utxo data")
        .to_vec();
    let creator_address = creator.shielded_address().expect("creator address");
    let terms = EscrowTerms::from_utxo_data(creator_address, &stored).expect("escrow terms");
    let rebuilt = NewProgramUtxo::new(
        *escrow_utxo.owner(),
        terms.clone(),
        Mint::SOL,
        250,
        creator_address.viewing_pubkey,
    )
    .created(*escrow_utxo.blinding(), TREE_ID);

    assert_eq!(
        (terms.unlock_timestamp, terms.utxo_data(), &rebuilt),
        (UNLOCK, stored, escrow_utxo)
    );
}
