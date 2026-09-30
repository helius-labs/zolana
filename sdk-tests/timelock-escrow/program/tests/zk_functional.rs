use borsh::BorshDeserialize;
use timelock_escrow_program::circuits::escrow_authority;
use timelock_escrow_program::circuits::{
    Escrow, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms, Withdraw, WithdrawPrivateInputs,
    WithdrawPublicInputs,
};
use timelock_escrow_program::{
    instructions::escrow::slot,
    zk::{escrow, withdraw, Groth16Proof},
};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_program::{
    compression::PdaOwner, CompressedProof, Groth16Prover, SolanaProof, TxContext, ZkProgram,
};

#[allow(dead_code)]
mod shared;
use shared::{keypair, token_input};

fn compressed(proof: &SolanaProof) -> CompressedProof {
    CompressedProof::try_from(proof).expect("compressed proof")
}

fn groth16(proof: &CompressedProof) -> Groth16Proof<'_> {
    Groth16Proof {
        a: &proof.a,
        b: &proof.b,
        c: &proof.c,
    }
}

#[test]
fn escrow_then_withdraw_prove_and_verify() {
    let creator = keypair(5);
    let payer = creator
        .shielded_address()
        .and_then(|address| address.solana_address())
        .expect("payer");
    let authority = escrow_authority(&payer);
    let creator_identity = solana_owner_identity(payer.as_array()).expect("creator identity");

    let escrow = Escrow {
        private: EscrowPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: vec![token_input(&creator, 600, 0), token_input(&creator, 400, 1)],
            unlock: 1_700_000_000,
            amount: 250,
        },
        public: EscrowPublicInputs {
            escrow_owner: authority
                .address(creator.viewing_pubkey())
                .expect("escrow owner"),
            creator_identity,
        },
    };
    let escrow_spp_proof_inputs = escrow
        .create_proof_inputs_and_encrypt_with_keys(&creator, payer, u64::MAX)
        .expect("escrow proof inputs");
    let escrow_prover = Groth16Prover::<Escrow>::new_with_test_setup().expect("escrow setup");
    let escrow_result = escrow_prover.prove(&escrow).expect("escrow proof");
    escrow::verify(
        &groth16(&compressed(&escrow_result.proof)),
        &escrow::PublicInputs {
            escrow_owner: *PdaOwner::new(authority.pda())
                .expect("escrow owner")
                .owner_hash(),
            creator_identity,
        },
        &escrow_spp_proof_inputs
            .padding_independent_private_tx_hash()
            .expect("escrow private tx hash"),
    )
    .expect("the program verifier accepts the escrow proof");

    let escrow_output = escrow_spp_proof_inputs
        .output_utxos
        .get(slot::ESCROW)
        .expect("escrow output");
    let escrow_utxo = authority
        .input(escrow_output, escrow_spp_proof_inputs.output_tree_id, 2)
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
            creator_identity,
        },
    };
    let withdraw_spp_proof_inputs = withdraw
        .create_proof_inputs_and_encrypt_with_keys(&creator, payer, u64::MAX)
        .expect("withdraw proof inputs");
    let withdraw_prover = Groth16Prover::<Withdraw>::new_with_test_setup().expect("withdraw setup");
    let withdraw_result = withdraw_prover.prove(&withdraw).expect("withdraw proof");
    withdraw::verify(
        &groth16(&compressed(&withdraw_result.proof)),
        &withdraw::PublicInputs {
            unlock,
            creator_identity,
        },
        &withdraw_spp_proof_inputs
            .padding_independent_private_tx_hash()
            .expect("withdraw private tx hash"),
    )
    .expect("the program verifier accepts the withdraw proof");
}
