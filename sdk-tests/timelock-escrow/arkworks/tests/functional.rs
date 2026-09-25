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
    CompressedProof, Groth16Keys, Groth16Prover, SolanaProof, TxContext, ZkProgram,
};
use zolana_hasher::primitives::solana_owner_identity;

#[allow(dead_code)]
mod shared;
use shared::{keypair, token_input, token_inputs};

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
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let payer = address.solana_address().expect("payer");
    let first = token_input(&creator, 600, 0);
    let second = token_input(&creator, 400, 1);

    let escrow = Escrow {
        private: EscrowPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: token_inputs([first, second]),
            unlock: 1_700_000_000,
            amount: 250,
        },
        public: EscrowPublicInputs {
            escrow_owner: escrow_authority()
                .address(address.viewing_pubkey)
                .expect("escrow owner"),
        },
    };
    let escrow_spp_proof_inputs = escrow
        .create_proof_inputs_and_encrypt(&creator, payer, u64::MAX)
        .expect("escrow proof inputs");
    let escrow_prover = Groth16Prover::<Escrow>::new_with_test_setup().expect("escrow setup");
    let escrow_result = escrow_prover.prove(&escrow).expect("escrow proof");
    verify_on_program(
        &escrow_result.proof,
        escrow_result.public_hash,
        escrow_prover.keys(),
    );

    let escrow_output = escrow_spp_proof_inputs
        .output_utxos
        .get(slot::ESCROW)
        .expect("escrow output");
    let escrow_utxo = escrow_input(escrow_output, escrow_spp_proof_inputs.output_tree_id, 2)
        .expect("escrow input");
    let terms = EscrowTerms::try_from_slice(escrow_output.data.utxo_data().expect("escrow data"))
        .expect("escrow terms");
    let unlock = terms.unlock;

    let withdraw = Withdraw {
        private: WithdrawPrivateInputs {
            tx_context: TxContext::new(),
            escrow: escrow_utxo,
            terms,
        },
        public: WithdrawPublicInputs {
            unlock,
            owner_identity: solana_owner_identity(payer.as_array()).expect("owner identity"),
        },
    };
    withdraw
        .create_proof_inputs_and_encrypt(&creator, payer, u64::MAX)
        .expect("withdraw proof inputs");
    let withdraw_prover = Groth16Prover::<Withdraw>::new_with_test_setup().expect("withdraw setup");
    let withdraw_result = withdraw_prover.prove(&withdraw).expect("withdraw proof");
    verify_on_program(
        &withdraw_result.proof,
        withdraw_result.public_hash,
        withdraw_prover.keys(),
    );
}
