use zk_program_sdk::{Groth16Prover, TxContext, ZkProgram};
use zolana_program::{derive_output_blinding_seed, derive_transact_output_blinding};

use crate::{
    benchmark::prove,
    s31_order_make::order_utxo,
    s32_order_take::{Take, TakePrivateInputs, TakePublicInputs},
    shared::{keypair, token_input, USDC},
};

#[test]
fn program_chosen_blinding_seed_prove_and_verify() {
    let maker = keypair(5);
    let maker_address = maker.shielded_address().expect("maker address");
    let taker = keypair(6);
    let taker_address = taker.shielded_address().expect("taker address");
    let payer = taker_address.solana_address().expect("payer");
    let blinding_seed = [9u8; 32];
    let (order, terms) = order_utxo(&maker, 500, 60, 1_800_000_000);
    let first_nullifier = order.nullifier;

    let take = Take {
        private: TakePrivateInputs {
            tx_context: TxContext::new().with_blinding_seed(blinding_seed),
            order,
            terms,
            maker: maker_address,
            token_utxos_asset_b: [token_input(&taker, USDC, 100, 3)],
        },
        public: TakePublicInputs {
            ask_asset: USDC,
            ask_amount: 60,
        },
    };
    let spp_proof_inputs = take
        .create_proof_inputs_and_encrypt(&taker, payer, u64::MAX)
        .expect("take proof inputs");
    let output_blinding_seed =
        derive_output_blinding_seed(&first_nullifier, &blinding_seed).expect("output seed");
    assert_eq!(
        (
            spp_proof_inputs.blinding_seed,
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| output.blinding)
                .collect::<Vec<_>>(),
        ),
        (
            blinding_seed,
            (0u32..3)
                .map(|slot| {
                    derive_transact_output_blinding(&first_nullifier, &output_blinding_seed, slot)
                        .expect("output blinding")
                })
                .collect::<Vec<_>>(),
        )
    );

    let prover = Groth16Prover::<Take>::new_with_test_setup().expect("take setup");
    let result = prove(&prover, &take, "take proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
