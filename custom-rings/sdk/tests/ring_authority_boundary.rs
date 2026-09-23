#[path = "../../../sdk-libs/client/tests/prover_bootstrap.rs"]
mod prover_bootstrap;
#[path = "../../../sdk-libs/client/tests/test_indexer.rs"]
mod test_indexer;

use custom_ring_sdk::{RingAuthorityProofInputs, RingAuthorityProofs};
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use solana_address::Address;
use test_indexer::TestIndexer;
use zolana_client::{
    Proof, ProofAuthority, ProverClient, PublicTransfers, RingAuthorityProver, Rpc,
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{OwnerTag, TransactOutput},
        tag::RING_AUTHORITY_TRANSACT,
    },
    verifying_keys::transfer_ring_authority_2_2,
};
use zolana_keypair::{random_blinding, ShieldedKeypair};
use zolana_transaction::{
    instructions::transact::shape::Shape,
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, SppProofInputUtxo},
    Data, ExternalData, Mint, SppProofOutputUtxo, Utxo,
};

const TEST_TREE_ID: u16 = 0;

#[test]
fn prepared_authority_proves_and_verifies() {
    prover_bootstrap::start_prover();
    let ring = Address::new_from_array([9u8; 32]);
    let mut indexer = TestIndexer::new();
    let owner = ShieldedKeypair::new_ed25519().expect("owner keypair");
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: Mint::SOL,
        amount: 0,
        blinding: random_blinding(),
        ring_program_id: Some(ring),
        data: Data::default(),
    };
    let nullifier_pk = owner.nullifier_key.pubkey().expect("nullifier public key");
    let utxo_hash = utxo
        .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32], TEST_TREE_ID)
        .expect("UTXO hash");
    indexer.add_utxo(utxo_hash);

    let wallet =
        zolana_test_utils::utxo::wallet(utxo, &owner.nullifier_key, TEST_TREE_ID, 0, None, None)
            .expect("wallet UTXO");
    let inputs = vec![
        SppProofInputUtxo::from(wallet),
        SppProofInputUtxo::dummy(TEST_TREE_ID).expect("dummy input"),
    ];
    let mut outputs = vec![dummy_output(), dummy_output()];
    let blinding_seed = random_blinding();
    let output_seed =
        derive_output_blinding_seed(&inputs[0].nullifier(), &blinding_seed).expect("output seed");
    for (index, output) in outputs.iter_mut().enumerate() {
        output.blinding =
            derive_transact_output_blinding(&inputs[0].nullifier(), &output_seed, index as u32)
                .expect("output blinding");
    }
    let prepared = RingAuthorityProofInputs {
        inputs,
        outputs,
        blinding_seed,
        output_tree_id: TEST_TREE_ID,
        public_transfers: PublicTransfers::default(),
        external_data: ring_external_data(),
        payer: Address::default(),
        ring_program_id: Some(ring),
        shape: Shape::IN2_OUT2,
    };
    let proofs = indexer
        .get_input_merkle_proofs(
            &prepared.input_utxo_hashes().expect("input commitments"),
            None,
        )
        .expect("Merkle proofs");
    let dummy_nullifier_proofs = prepared
        .inputs
        .iter()
        .filter(|input| input.is_dummy())
        .map(|input| indexer.dummy_nullifier_proof(input.nullifier()))
        .collect();
    let mut result = RingAuthorityProver::try_from(RingAuthorityProofs {
        prepared,
        proofs,
        dummy_nullifier_proofs,
    })
    .expect("ring-authority prover")
    .build()
    .expect("ring-authority witness");
    owner
        .complete_inputs(&mut result.inputs.inputs)
        .expect("complete owner witness");

    let proof = ProverClient::local()
        .prove_ring_authority(&result.inputs)
        .expect("ring-authority proof");
    verify(proof, result.public_input_hash);
}

fn dummy_output() -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        blinding: random_blinding(),
        ..Default::default()
    }
}

fn ring_external_data() -> ExternalData {
    ExternalData {
        instruction_discriminator: RING_AUTHORITY_TRANSACT,
        expiry_unix_ts: 0,
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        outputs: (0..2)
            .map(|_| TransactOutput {
                utxo_hash: [0u8; 32],
                owner_tag: OwnerTag::Inline([0u8; 32]),
                data: None,
            })
            .collect(),
        resolved_owner_tags: vec![[0u8; 32]; 2],
        messages: Vec::new(),
    }
}

fn verify(proof: Proof, public_input_hash: [u8; 32]) {
    let public_inputs = [public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        ring_authority_vk(),
    )
    .expect("verifier");
    verifier.verify().expect("proof verifies");
}

fn ring_authority_vk() -> &'static Groth16Verifyingkey<'static> {
    &transfer_ring_authority_2_2::VERIFYINGKEY
}
