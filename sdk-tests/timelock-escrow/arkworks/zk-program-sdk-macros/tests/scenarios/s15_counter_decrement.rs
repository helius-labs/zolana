use zk_program_sdk::{
    circuit,
    circuit::{Bits, CheckedTransaction, Circuit, ConfidentialTransaction, DataUtxo, PublicInputs},
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s13_counter_create::Counter,
    shared::{data_input, keypair},
};

#[derive(Clone, ProofInput)]
pub(crate) struct Decrement {
    pub(crate) private: DecrementPrivateInputs,
    pub(crate) public: DecrementPublicInputs,
}

#[derive(Clone, ProofInput)]
pub(crate) struct DecrementPrivateInputs {
    pub(crate) tx_context: TxContext,
    pub(crate) counter: WalletUtxo,
    pub(crate) state: Counter,
}

#[derive(Clone, ProofInput, PublicInputs)]
pub(crate) struct DecrementPublicInputs {
    pub(crate) step: u64,
}

#[circuit]
impl Circuit for Decrement {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let mut counter = DataUtxo::new_mut(&private.counter, &private.state)?;
        counter.count = counter.count.clone() - &self.public.step;
        counter.count.check_bits(64)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_data_utxo(counter)
            .check()
    }
}

#[test]
fn counter_decrement_prove_and_verify() {
    let owner = keypair(5);
    let address = owner.shielded_address().expect("owner address");
    let payer = address.solana_address().expect("payer");
    let state = Counter { count: 5 };
    let counter = data_input(&owner, 0, &state, 0);

    let decrement = Decrement {
        private: DecrementPrivateInputs {
            tx_context: TxContext::new(),
            counter,
            state,
        },
        public: DecrementPublicInputs { step: 2 },
    };
    let spp_proof_inputs = decrement
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("decrement proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (
                output.owner_address,
                output.asset,
                output.amount,
                output.data.utxo_data().map(<[u8]>::to_vec),
            ))
            .collect::<Vec<_>>(),
        vec![(
            Some(address),
            Mint::SOL,
            0,
            Some(borsh::to_vec(&Counter { count: 3 }).expect("counter bytes")),
        )]
    );

    let prover = Groth16Prover::<Decrement>::new_with_test_setup().expect("decrement setup");
    let result = prove(&prover, &decrement, "decrement proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
