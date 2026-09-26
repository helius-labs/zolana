use zk_program_sdk::{
    circuit,
    circuit::{
        zero, Assert, Balance, CheckedTransaction, Circuit, ConfidentialTransaction, DataUtxo,
        PublicInputs,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s13_counter_create::Counter,
    shared::{data_input, keypair},
};

#[derive(Clone, ProofInput)]
pub(crate) struct Reset {
    pub(crate) private: ResetPrivateInputs,
    pub(crate) public: ResetPublicInputs,
}

#[derive(Clone, ProofInput)]
pub(crate) struct ResetPrivateInputs {
    pub(crate) tx_context: TxContext,
    pub(crate) counter: WalletUtxo,
    pub(crate) state: Counter,
}

#[derive(Clone, ProofInput, PublicInputs)]
pub(crate) struct ResetPublicInputs {
    pub(crate) owner: ShieldedAddress,
}

#[circuit]
impl Circuit for Reset {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let mut counter = DataUtxo::new_mut(&private.counter, &private.state)?;
        counter
            .owner()
            .hash()?
            .assert_equal(&self.public.owner.hash()?, "the counter has another owner")?;
        counter.count = zero();

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_data_utxo(counter)
            .check()
    }
}

#[test]
fn counter_reset_prove_and_verify() {
    let owner = keypair(5);
    let address = owner.shielded_address().expect("owner address");
    let payer = address.solana_address().expect("payer");
    let state = Counter { count: 5 };
    let counter = data_input(&owner, 0, &state, 0);

    let reset = Reset {
        private: ResetPrivateInputs {
            tx_context: TxContext::new(),
            counter,
            state,
        },
        public: ResetPublicInputs { owner: address },
    };
    let spp_proof_inputs = reset
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("reset proof inputs");
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
            Some(borsh::to_vec(&Counter { count: 0 }).expect("counter bytes")),
        )]
    );

    let prover = Groth16Prover::<Reset>::new_with_test_setup().expect("reset setup");
    let result = prove(&prover, &reset, "reset proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
