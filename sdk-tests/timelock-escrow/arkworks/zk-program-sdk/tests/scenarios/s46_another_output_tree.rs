use zk_program_sdk::{Groth16Prover, TxContext, ZkProgram};
use zolana_transaction::Mint;

use crate::{
    s01_sol_payment::{Payment, PaymentPrivateInputs, PaymentPublicInputs},
    shared::{keypair, token_input, TREE_ID},
};

const OUTPUT_TREE_ID: u16 = 5;

#[test]
fn another_output_tree_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let first = token_input(&sender, Mint::SOL, 300, 0);
    let second = token_input(&sender, Mint::SOL, 200, 1);

    let payment = Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new().with_output_tree_id(Some(OUTPUT_TREE_ID)),
            token_utxos_asset_a: [first, second],
            amount: 400,
        },
        public: PaymentPublicInputs { recipient },
    };
    let spp_proof_inputs = payment
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("payment proof inputs");
    assert_eq!(
        (
            spp_proof_inputs
                .input_utxos
                .iter()
                .map(|input| input.tree_id)
                .collect::<Vec<_>>(),
            spp_proof_inputs.output_tree_id,
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| output.hash(OUTPUT_TREE_ID).expect("output hash"))
                .collect::<Vec<_>>(),
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.asset, output.amount))
                .collect::<Vec<_>>(),
        ),
        (
            vec![TREE_ID, TREE_ID],
            OUTPUT_TREE_ID,
            spp_proof_inputs
                .external_data
                .outputs
                .iter()
                .map(|output| output.utxo_hash)
                .collect::<Vec<_>>(),
            vec![
                (Some(address), Mint::SOL, 100),
                (Some(recipient), Mint::SOL, 400),
            ],
        )
    );

    let prover = Groth16Prover::<Payment>::new_with_test_setup().expect("payment setup");
    let result = prover.prove(&payment).expect("payment proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
