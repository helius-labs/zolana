use borsh::BorshDeserialize;
use timelock_escrow_arkworks::{
    escrow_input, Escrow, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms, Withdraw,
    WithdrawPrivateInputs, WithdrawPublicInputs,
};
use timelock_escrow_program::instructions::{
    escrow::slot,
    verifier::{verify_groth16, CompressedGroth16Proof},
};
use timelock_escrow_sdk::escrow_authority;
use zk_program_sdk::{
    rand::{rngs::StdRng, SeedableRng},
    ArkworksCircuit, CompressedProof, Groth16Keys, SolanaProof, TxContext, ZkProgram,
};
use zolana_hasher::primitives::solana_owner_identity;

#[allow(dead_code)]
mod shared;
use shared::{keypair, token_input, token_inputs, TREE_ID};

fn verify_on_program(proof: &SolanaProof, public_hash: [u8; 32], keys: &Groth16Keys) {
    let compressed = CompressedProof::try_from(proof).expect("compressed proof");
    verify_groth16(
        CompressedGroth16Proof {
            a: &compressed.a,
            b: &compressed.b,
            c: &compressed.c,
            commitment: None,
        },
        public_hash,
        &keys.verifying_key().into(),
    )
    .expect("the program verifier accepts the proof");
}

#[test]
fn escrow_then_withdraw_prove_and_verify() {
    let mut rng = StdRng::seed_from_u64(7);
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let payer = address.solana_address().expect("payer");
    let first = token_input(&creator, 600, 0);
    let second = token_input(&creator, 400, 1);

    let (escrow, escrow_spp_proof_inputs) = Escrow {
        private: EscrowPrivateInputs {
            tx_context: TxContext::new(first.nullifier, TREE_ID, address),
            token_utxos_asset_a: token_inputs([first, second]),
            unlock: 1_700_000_000,
            amount: 250,
        },
        public: EscrowPublicInputs {
            escrow_owner: escrow_authority()
                .address(address.viewing_pubkey)
                .expect("escrow owner"),
        },
    }
    .create_proof_inputs_and_encrypt(&creator, payer, u64::MAX)
    .expect("escrow proof inputs");
    let escrow_circuit = ArkworksCircuit::new(escrow).expect("escrow circuit");
    let escrow_keys = escrow_circuit.setup(&mut rng).expect("escrow setup");
    let escrow_proof = escrow_circuit
        .prove(&escrow_keys, &mut rng)
        .expect("escrow proof");
    verify_on_program(
        &escrow_proof,
        escrow_circuit.public_hash_bytes(),
        &escrow_keys,
    );

    let escrow_output = escrow_spp_proof_inputs
        .output_utxos
        .get(slot::ESCROW)
        .expect("escrow output");
    let escrow_utxo = escrow_input(escrow_output, TREE_ID, 2).expect("escrow input");
    let terms = EscrowTerms::try_from_slice(escrow_output.data.utxo_data().expect("escrow data"))
        .expect("escrow terms");
    let unlock = terms.unlock;

    let (withdraw, _withdraw_spp_proof_inputs) = Withdraw {
        private: WithdrawPrivateInputs {
            tx_context: TxContext::new(escrow_utxo.nullifier, TREE_ID, address),
            escrow: escrow_utxo,
            terms,
        },
        public: WithdrawPublicInputs {
            unlock,
            owner_identity: solana_owner_identity(payer.as_array()).expect("owner identity"),
        },
    }
    .create_proof_inputs_and_encrypt(&creator, payer, u64::MAX)
    .expect("withdraw proof inputs");
    let withdraw_circuit = ArkworksCircuit::new(withdraw).expect("withdraw circuit");
    let withdraw_keys = withdraw_circuit.setup(&mut rng).expect("withdraw setup");
    let withdraw_proof = withdraw_circuit
        .prove(&withdraw_keys, &mut rng)
        .expect("withdraw proof");
    verify_on_program(
        &withdraw_proof,
        withdraw_circuit.public_hash_bytes(),
        &withdraw_keys,
    );
}
