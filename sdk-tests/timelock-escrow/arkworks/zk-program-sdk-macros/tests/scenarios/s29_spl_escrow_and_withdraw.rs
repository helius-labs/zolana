use borsh::BorshDeserialize;
use zk_program_sdk::{Groth16Prover, TxContext, ZkProgram};
use zolana_hasher::primitives::solana_owner_identity;

use crate::{
    benchmark::prove,
    s27_escrow::{
        escrow_authority, Escrow, EscrowPrivateInputs, EscrowPublicInputs, EscrowTerms, ESCROW_SLOT,
    },
    s28_escrow_withdraw::{Withdraw, WithdrawPrivateInputs, WithdrawPublicInputs},
    shared::{keypair, token_input, USDC},
};

#[test]
fn spl_escrow_then_withdraw_prove_and_verify() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let payer = address.solana_address().expect("payer");
    let escrow_owner = escrow_authority().address(&address);
    let first = token_input(&creator, USDC, 600, 0);
    let second = token_input(&creator, USDC, 400, 1);

    let escrow = Escrow {
        private: EscrowPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, second],
            unlock: 1_700_000_000,
            amount: 250,
        },
        public: EscrowPublicInputs { escrow_owner },
    };
    let escrow_spp_proof_inputs = escrow
        .create_proof_inputs_and_encrypt(&creator, payer, u64::MAX)
        .expect("escrow proof inputs");
    let escrow_prover = Groth16Prover::<Escrow>::new_with_test_setup().expect("escrow setup");
    let escrow_result = prove(&escrow_prover, &escrow, "escrow proof");
    escrow_prover
        .verify(&escrow_result)
        .expect("the compressed proof verifies");

    let escrow_output = escrow_spp_proof_inputs
        .output_utxos
        .get(ESCROW_SLOT)
        .expect("escrow output");
    let escrow_utxo =
        escrow_authority().input(escrow_output, escrow_spp_proof_inputs.output_tree_id, 2);
    let terms = EscrowTerms::try_from_slice(escrow_output.data.utxo_data().expect("escrow data"))
        .expect("escrow terms");

    let withdraw = Withdraw {
        private: WithdrawPrivateInputs {
            tx_context: TxContext::new(),
            escrow: escrow_utxo,
            terms: terms.clone(),
        },
        public: WithdrawPublicInputs {
            unlock: terms.unlock,
            owner_identity: solana_owner_identity(payer.as_array()).expect("owner identity"),
        },
    };
    let withdraw_spp_proof_inputs = withdraw
        .create_proof_inputs_and_encrypt(&creator, payer, u64::MAX)
        .expect("withdraw proof inputs");
    let withdraw_prover = Groth16Prover::<Withdraw>::new_with_test_setup().expect("withdraw setup");
    let withdraw_result = prove(&withdraw_prover, &withdraw, "withdraw proof");
    withdraw_prover
        .verify(&withdraw_result)
        .expect("the compressed proof verifies");

    assert_eq!(
        (
            escrow_spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.asset, output.amount))
                .collect::<Vec<_>>(),
            withdraw_spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.asset, output.amount))
                .collect::<Vec<_>>(),
        ),
        (
            vec![(Some(address), USDC, 750), (Some(escrow_owner), USDC, 250)],
            vec![(Some(address), USDC, 250)],
        )
    );
}
