use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    circuit,
    circuit::{
        Asset, CheckedTransaction, Circuit, CircuitType, ConfidentialTransaction, DataUtxo,
        PublicInputs, TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input},
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct Counter {
    pub count: u64,
}

#[derive(Clone, ProofInput)]
pub(crate) struct CounterCreate {
    pub(crate) private: CounterCreatePrivateInputs,
    pub(crate) public: CounterCreatePublicInputs,
}

#[derive(Clone, ProofInput)]
pub(crate) struct CounterCreatePrivateInputs {
    pub(crate) tx_context: TxContext,
    pub(crate) token_utxos_asset_a: [WalletUtxo; 1],
}

#[derive(Clone, ProofInput, PublicInputs)]
pub(crate) struct CounterCreatePublicInputs {
    pub(crate) owner: ShieldedAddress,
}

#[circuit]
impl Circuit for CounterCreate {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let counter = DataUtxo::<CounterCircuit>::new_init(&self.public.owner, &Asset::sol());

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(counter)
            .check()
    }
}

#[test]
fn counter_create_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let input = token_input(&sender, Mint::SOL, 300, 0);

    let create = CounterCreate {
        private: CounterCreatePrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
        },
        public: CounterCreatePublicInputs { owner: address },
    };
    let spp_proof_inputs = create
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("counter create proof inputs");
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
        vec![
            (Some(address), Mint::SOL, 300, None),
            (
                Some(address),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&Counter { count: 0 }).expect("counter bytes")),
            ),
        ]
    );

    let prover =
        Groth16Prover::<CounterCreate>::new_with_test_setup().expect("counter create setup");
    let result = prove(&prover, &create, "counter create proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
