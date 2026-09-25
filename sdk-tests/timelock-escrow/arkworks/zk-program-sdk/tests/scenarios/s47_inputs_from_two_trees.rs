use zk_program_sdk::{Groth16Prover, TxContext, ZkProgram};
use zolana_interface::shape::Shape;
use zolana_transaction::Mint;

use crate::{
    s04_payment_across_shapes::{Payment, PaymentPrivateInputs, PaymentPublicInputs},
    shared::{dummy, keypair, token_input_in, TREE_ID},
};

const SECOND_TREE_ID: u16 = 5;

#[test]
fn inputs_from_two_trees_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipients =
        [6u8, 7, 8].map(|seed| keypair(seed).shielded_address().expect("recipient address"));
    let first = token_input_in(&sender, Mint::SOL, 300, TREE_ID, 0);
    let second = token_input_in(&sender, Mint::SOL, 200, SECOND_TREE_ID, 0);

    let payment = Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, second, dummy()],
            amounts: [100, 150, 200],
        },
        public: PaymentPublicInputs { recipients },
    };
    let spp_proof_inputs = payment
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("payment proof inputs");
    let [first_recipient, second_recipient, third_recipient] = recipients;
    assert_eq!(
        (
            spp_proof_inputs.check_shape().expect("payment shape"),
            spp_proof_inputs
                .input_utxos
                .iter()
                .map(|input| (input.is_dummy(), input.tree_id))
                .collect::<Vec<_>>(),
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.amount))
                .collect::<Vec<_>>(),
        ),
        (
            Shape::IN4_OUT4,
            vec![
                (false, TREE_ID),
                (false, SECOND_TREE_ID),
                (true, SECOND_TREE_ID),
                (true, SECOND_TREE_ID),
            ],
            vec![
                (Some(address), 50),
                (Some(first_recipient), 100),
                (Some(second_recipient), 150),
                (Some(third_recipient), 200),
            ],
        )
    );

    let prover = Groth16Prover::<Payment<3, 3>>::new_with_test_setup().expect("payment setup");
    let result = prover.prove(&payment).expect("payment proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
