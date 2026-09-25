use zk_program_sdk::{Groth16Prover, TxContext, ZkProgram};
use zolana_transaction::Mint;

use crate::{
    s13_counter_create::{
        Counter, CounterCreate, CounterCreatePrivateInputs, CounterCreatePublicInputs,
    },
    s14_counter_increment::{Increment, IncrementPrivateInputs, IncrementPublicInputs},
    s15_counter_decrement::{Decrement, DecrementPrivateInputs, DecrementPublicInputs},
    s16_counter_reset::{Reset, ResetPrivateInputs, ResetPublicInputs},
    s17_counter_close::{Close, ClosePrivateInputs, ClosePublicInputs},
    shared::{decrypt_data_output, keypair, token_input},
};

#[test]
fn counter_lifecycle_prove_and_verify() {
    let owner = keypair(5);
    let address = owner.shielded_address().expect("owner address");
    let payer = address.solana_address().expect("payer");
    let funding = token_input(&owner, Mint::SOL, 300, 0);

    let create = CounterCreate {
        private: CounterCreatePrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [funding],
        },
        public: CounterCreatePublicInputs { owner: address },
    };
    let create_spp_proof_inputs = create
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("create proof inputs");
    let create_prover =
        Groth16Prover::<CounterCreate>::new_with_test_setup().expect("create setup");
    let create_result = create_prover.prove(&create).expect("create proof");
    create_prover
        .verify(&create_result)
        .expect("the create proof verifies");
    let (counter, created) =
        decrypt_data_output::<Counter>(&owner, &create_spp_proof_inputs, 1, 10);

    let increment_prover =
        Groth16Prover::<Increment>::new_with_test_setup().expect("increment setup");
    let increment = Increment {
        private: IncrementPrivateInputs {
            tx_context: TxContext::new(),
            counter,
            state: created.clone(),
        },
        public: IncrementPublicInputs { step: 3 },
    };
    let increment_spp_proof_inputs = increment
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("increment proof inputs");
    let increment_result = increment_prover.prove(&increment).expect("increment proof");
    increment_prover
        .verify(&increment_result)
        .expect("the increment proof verifies");
    let (counter, incremented) =
        decrypt_data_output::<Counter>(&owner, &increment_spp_proof_inputs, 0, 12);

    let increment = Increment {
        private: IncrementPrivateInputs {
            tx_context: TxContext::new(),
            counter,
            state: incremented.clone(),
        },
        public: IncrementPublicInputs { step: 4 },
    };
    let increment_spp_proof_inputs = increment
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("second increment proof inputs");
    let increment_result = increment_prover
        .prove(&increment)
        .expect("second increment proof");
    increment_prover
        .verify(&increment_result)
        .expect("the second increment proof verifies");
    let (counter, incremented_again) =
        decrypt_data_output::<Counter>(&owner, &increment_spp_proof_inputs, 0, 13);

    let decrement = Decrement {
        private: DecrementPrivateInputs {
            tx_context: TxContext::new(),
            counter,
            state: incremented_again.clone(),
        },
        public: DecrementPublicInputs { step: 2 },
    };
    let decrement_spp_proof_inputs = decrement
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("decrement proof inputs");
    let decrement_prover =
        Groth16Prover::<Decrement>::new_with_test_setup().expect("decrement setup");
    let decrement_result = decrement_prover.prove(&decrement).expect("decrement proof");
    decrement_prover
        .verify(&decrement_result)
        .expect("the decrement proof verifies");
    let (counter, decremented) =
        decrypt_data_output::<Counter>(&owner, &decrement_spp_proof_inputs, 0, 14);

    let reset = Reset {
        private: ResetPrivateInputs {
            tx_context: TxContext::new(),
            counter,
            state: decremented.clone(),
        },
        public: ResetPublicInputs { owner: address },
    };
    let reset_spp_proof_inputs = reset
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("reset proof inputs");
    let reset_prover = Groth16Prover::<Reset>::new_with_test_setup().expect("reset setup");
    let reset_result = reset_prover.prove(&reset).expect("reset proof");
    reset_prover
        .verify(&reset_result)
        .expect("the reset proof verifies");
    let (counter, reset_state) =
        decrypt_data_output::<Counter>(&owner, &reset_spp_proof_inputs, 0, 15);

    let close = Close {
        private: ClosePrivateInputs {
            tx_context: TxContext::new(),
            counter,
            state: reset_state.clone(),
        },
        public: ClosePublicInputs { owner: address },
    };
    let close_spp_proof_inputs = close
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("close proof inputs");
    let close_prover = Groth16Prover::<Close>::new_with_test_setup().expect("close setup");
    let close_result = close_prover.prove(&close).expect("close proof");
    close_prover
        .verify(&close_result)
        .expect("the close proof verifies");

    assert_eq!(
        (
            [
                created,
                incremented,
                incremented_again,
                decremented,
                reset_state
            ],
            close_spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.amount))
                .collect::<Vec<_>>(),
        ),
        (
            [0, 3, 7, 5, 0].map(|count| Counter { count }),
            vec![(None, 0)],
        )
    );
}
