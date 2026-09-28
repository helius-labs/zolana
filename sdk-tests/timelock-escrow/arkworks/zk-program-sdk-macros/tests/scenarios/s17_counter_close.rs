use zk_program_sdk::{
    circuit::{
        Assert, Balance, CheckedTransaction, Circuit, ConfidentialTransaction, DataUtxo,
        PublicInputs,
    },
    conversion::ProofInput,
    CircuitError, Groth16Prover, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::WalletUtxo;

use crate::{
    benchmark::prove,
    s13_counter_create::Counter,
    shared::{data_input, keypair},
};

#[derive(Clone, ProofInput)]
pub struct Close {
    pub(crate) private: ClosePrivateInputs,
    pub(crate) public: ClosePublicInputs,
}

#[derive(Clone, ProofInput)]
pub(crate) struct ClosePrivateInputs {
    pub(crate) tx_context: TxContext,
    pub(crate) counter: WalletUtxo,
    pub(crate) state: Counter,
}

#[derive(Clone, ProofInput, PublicInputs)]
pub(crate) struct ClosePublicInputs {
    pub(crate) owner: ShieldedAddress,
}

#[deny(clippy::disallowed_types)]
impl Circuit for <Close as ProofInput>::Circuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        let counter = DataUtxo::new_burn(&private.counter, &private.state)?;
        counter
            .owner()
            .hash()?
            .assert_equal(&self.public.owner.hash()?, "the counter has another owner")?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_data_utxo(counter)
            .check()
    }
}

#[test]
fn counter_close_prove_and_verify() {
    let owner = keypair(5);
    let address = owner.shielded_address().expect("owner address");
    let payer = address.solana_address().expect("payer");
    let state = Counter { count: 5 };
    let counter = data_input(&owner, 0, &state, 0);

    let close = Close {
        private: ClosePrivateInputs {
            tx_context: TxContext::new(),
            counter,
            state,
        },
        public: ClosePublicInputs { owner: address },
    };
    let spp_proof_inputs = close
        .create_proof_inputs_and_encrypt_with_keys(&owner, payer, u64::MAX)
        .expect("close proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.amount))
            .collect::<Vec<_>>(),
        vec![(None, 0)]
    );

    let prover = Groth16Prover::<Close>::new_with_test_setup().expect("close setup");
    let result = prove(&prover, &close, "close proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
