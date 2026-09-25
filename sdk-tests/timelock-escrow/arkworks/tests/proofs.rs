use circuit_lib::{
    rand::{rngs::StdRng, SeedableRng},
    ArkworksCircuit, Groth16Keys, SolanaProof,
};
use timelock_escrow_arkworks::client::{self, EscrowTerms};
use timelock_escrow_program::instructions::{
    escrow::slot,
    verifier::{verify_groth16, CompressedGroth16Proof},
};
use timelock_escrow_sdk::escrow_authority;
use zolana_transaction::instructions::transact::SppProofInputs;

mod shared;
use shared::{escrow_utxo, keypair, token_input, TREE_ID};

fn rng() -> StdRng {
    StdRng::seed_from_u64(7)
}

fn verify_groth16_accepts(proof: &SolanaProof, public_hash: [u8; 32], keys: &Groth16Keys) -> bool {
    let compressed = proof.compress().expect("compressed proof");
    verify_groth16(
        CompressedGroth16Proof {
            a: &compressed.a,
            b: &compressed.b,
            c: &compressed.c,
            commitment: None,
        },
        public_hash,
        &keys.verifying_key().groth16_verifyingkey(),
    )
    .is_ok()
}

fn spp_hashes(spp: &SppProofInputs) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    (
        spp.input_utxos
            .iter()
            .map(|input| {
                if input.is_dummy() {
                    [0u8; 32]
                } else {
                    input.utxo_hash
                }
            })
            .collect(),
        spp.output_utxos
            .iter()
            .map(|output| {
                if output.is_dummy() {
                    [0u8; 32]
                } else {
                    output.hash(TREE_ID).expect("output hash")
                }
            })
            .collect(),
    )
}

#[test]
fn escrow_proves_from_the_rust_circuit_with_matching_spp_proof_inputs() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let transaction = client::Escrow {
        creator: address,
        token_utxos_asset_a: [token_input(&creator, 600, 0), token_input(&creator, 400, 1)],
        amount: 250,
        unlock: 1_700_000_000,
        payer: address.solana_address().expect("payer"),
        output_tree_id: TREE_ID,
    }
    .build(&creator)
    .expect("escrow transaction");

    let circuit = ArkworksCircuit::new(transaction.proof_inputs.clone())
        .expect("the circuit computes the client's public hash");
    let keys = circuit.setup(&mut rng()).expect("escrow setup");
    let proof = circuit.prove(&keys, &mut rng()).expect("escrow proof");
    let built = &transaction.transaction;
    let spp = &built.spp_proof_inputs;
    let escrow_output = spp.output_utxos.get(slot::ESCROW).expect("escrow output");
    let mut tampered = built.public_hash;
    tampered[31] ^= 1;

    assert_eq!(
        (
            circuit.public_hash_bytes(),
            verify_groth16_accepts(&proof, built.public_hash, &keys),
            verify_groth16_accepts(&proof, tampered, &keys),
            spp_hashes(spp),
            spp.output_utxos
                .iter()
                .map(|output| output.amount)
                .collect::<Vec<_>>(),
            escrow_output.owner_hash().expect("escrow owner hash"),
            escrow_output.data.utxo_data().map(<[u8]>::to_vec),
        ),
        (
            built.public_hash,
            true,
            false,
            (built.input_hashes.to_vec(), built.output_hashes.to_vec()),
            vec![750, 250],
            escrow_authority().owner_hash().expect("escrow authority"),
            Some(1_700_000_000u64.to_le_bytes().to_vec()),
        )
    );
}

#[test]
fn withdraw_proves_from_the_rust_circuit_with_matching_spp_proof_inputs() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let transaction = client::Withdraw {
        creator: address,
        escrow: escrow_utxo(&creator, 250, 1_700_000_000),
        terms: EscrowTerms {
            creator: address.owner_hash().expect("creator owner hash"),
            unlock: 1_700_000_000,
        },
        payer: address.solana_address().expect("payer"),
        output_tree_id: TREE_ID,
    }
    .build(&creator)
    .expect("withdraw transaction");

    let circuit = ArkworksCircuit::new(transaction.proof_inputs.clone())
        .expect("the circuit computes the client's public hash");
    let keys = circuit.setup(&mut rng()).expect("withdraw setup");
    let proof = circuit.prove(&keys, &mut rng()).expect("withdraw proof");
    let built = &transaction.transaction;
    let spp = &built.spp_proof_inputs;
    let payout = spp.output_utxos.first().expect("payout");

    assert_eq!(
        (
            circuit.public_hash_bytes(),
            verify_groth16_accepts(&proof, built.public_hash, &keys),
            spp_hashes(spp),
            (payout.amount, payout.owner_hash().expect("payout owner")),
            spp.input_utxos.first().map(|input| input.utxo.amount),
        ),
        (
            built.public_hash,
            true,
            (built.input_hashes.to_vec(), built.output_hashes.to_vec()),
            (250, address.owner_hash().expect("creator owner hash")),
            Some(250),
        )
    );
}
