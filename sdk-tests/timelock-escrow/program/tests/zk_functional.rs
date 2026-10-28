use borsh::BorshDeserialize;
use spr_hasher::primitives::solana_owner_identity;
use spr_keypair::ViewingKey;
use spr_program::verifier::VerifyError;
use spr_program::{CompressedProof, Groth16Prover, SolanaProof, TxContext, ZkProgramCircuit};
use timelock_escrow_program::circuits::escrow_authority;
use timelock_escrow_program::circuits::{
    Escrow, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms, Withdraw, WithdrawPrivateInputs,
    WithdrawPublicInputs,
};
use timelock_escrow_program::{
    instructions::escrow::slot,
    verifier::{escrow, withdraw},
};

#[allow(dead_code)]
mod shared;
use shared::{keypair, token_input, TREE_ID};

fn compressed(proof: &SolanaProof) -> CompressedProof {
    CompressedProof::try_from(proof).expect("compressed proof")
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
    escrow::Verifier {
        proof: &compressed(&escrow_result.proof),
        public_inputs: escrow::PublicInputs {
            escrow_owner: escrow
                .public
                .escrow_owner
                .address_hash()
                .expect("address hash"),
            creator_identity,
        },
        private_tx_hash: &escrow_spp_proof_inputs
            .padding_independent_private_tx_hash()
            .expect("escrow private tx hash"),
        transfers: &[],
    }
    .verify()
    .expect("the program verifier accepts the escrow proof");

    // The same proof cannot authorize a different SPP transaction or transfer.
    let proof = compressed(&escrow_result.proof);
    let private_tx_hash = escrow_spp_proof_inputs
        .padding_independent_private_tx_hash()
        .expect("escrow private tx hash");
    let mut verifier = escrow::Verifier {
        proof: &proof,
        public_inputs: escrow::PublicInputs {
            escrow_owner: escrow.public.escrow_owner.address_hash().unwrap(),
            creator_identity,
        },
        private_tx_hash: &private_tx_hash,
        transfers: &[],
    };
    let mut other_private_tx_hash = private_tx_hash;
    other_private_tx_hash[31] ^= 1;
    verifier.private_tx_hash = &other_private_tx_hash;
    assert_eq!(verifier.verify(), Err(VerifyError::Proof));

    let transfers = [spr_program::PublicTransfer {
        mint: solana_address::Address::default(),
        is_deposit: true,
        amount: 1,
        account: payer,
    }];
    verifier.private_tx_hash = &private_tx_hash;
    verifier.transfers = &transfers;
    assert_eq!(verifier.verify(), Err(VerifyError::Proof));

    let other_viewer = ViewingKey::from_bytes(&[9u8; 32]);
    let wrong_address_hash = spr_program::verifier::address_hash(
        &escrow.public.escrow_owner.owner_hash().unwrap(),
        other_viewer.pubkey().as_bytes(),
    )
    .unwrap();
    assert_eq!(
        escrow::Verifier {
            proof: &compressed(&escrow_result.proof),
            public_inputs: escrow::PublicInputs {
                escrow_owner: wrong_address_hash,
                creator_identity,
            },
            private_tx_hash: &escrow_spp_proof_inputs
                .padding_independent_private_tx_hash()
                .unwrap(),
            transfers: &[],
        }
        .verify(),
        Err(VerifyError::Proof)
    );

    let escrow_output = escrow_spp_proof_inputs
        .output_utxos
        .get(slot::ESCROW)
        .expect("escrow output");
    let mut escrow_utxo = authority
        .input(escrow_output, escrow_spp_proof_inputs.output_tree_id, 2)
        .expect("escrow input");
    escrow_utxo.latest_tree_id = Some(TREE_ID);
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
    withdraw::Verifier {
        proof: &compressed(&withdraw_result.proof),
        public_inputs: withdraw::PublicInputs {
            unlock,
            creator_identity,
        },
        private_tx_hash: &withdraw_spp_proof_inputs
            .padding_independent_private_tx_hash()
            .expect("withdraw private tx hash"),
        transfers: &[],
    }
    .verify()
    .expect("the program verifier accepts the withdraw proof");
}
