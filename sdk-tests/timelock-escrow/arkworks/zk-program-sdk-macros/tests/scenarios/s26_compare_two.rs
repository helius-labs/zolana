use zk_program_sdk::{
    circuit,
    circuit::{
        Assert, CheckedTransaction, Circuit, ConfidentialTransaction, DataUtxo, PublicInputs,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s25_read_with_threshold::Account,
    shared::{data_input, keypair},
};

#[derive(Clone, ProofInput)]
struct CompareTwo {
    private: CompareTwoPrivateInputs,
    public: CompareTwoPublicInputs,
}

#[derive(Clone, ProofInput)]
struct CompareTwoPrivateInputs {
    tx_context: TxContext,
    first_utxo: WalletUtxo,
    first: Account,
    second_utxo: WalletUtxo,
    second: Account,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct CompareTwoPublicInputs {
    total: u64,
}

#[circuit]
impl Circuit for CompareTwo {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let first = DataUtxo::new_mut(&private.first_utxo, &private.first)?;
        let second = DataUtxo::new_mut(&private.second_utxo, &private.second)?;
        (first.balance.clone() + &second.balance)
            .assert_equal(&self.public.total, "the balances do not sum to the total")?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_data_utxo(first)
            .with_data_utxo(second)
            .check()
    }
}

#[test]
fn compare_two_prove_and_verify() {
    let owner = keypair(5);
    let address = owner.shielded_address().expect("owner address");
    let payer = address.solana_address().expect("payer");
    let first = Account { balance: 700 };
    let second = Account { balance: 300 };
    let first_utxo = data_input(&owner, 0, &first, 0);
    let second_utxo = data_input(&owner, 0, &second, 1);

    let compare = CompareTwo {
        private: CompareTwoPrivateInputs {
            tx_context: TxContext::new(),
            first_utxo,
            first: first.clone(),
            second_utxo,
            second: second.clone(),
        },
        public: CompareTwoPublicInputs { total: 1_000 },
    };
    let spp_proof_inputs = compare
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("compare proof inputs");
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
            (
                Some(address),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&first).expect("first bytes")),
            ),
            (
                Some(address),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&second).expect("second bytes")),
            ),
        ]
    );

    let prover = Groth16Prover::<CompareTwo>::new_with_test_setup().expect("compare setup");
    let result = prove(&prover, &compare, "compare proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
