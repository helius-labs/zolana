use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s25_read_with_threshold::Account,
    shared::{data_input, keypair},
};

#[derive(Clone)]
struct CompareTwo {
    private: CompareTwoPrivateInputs,
    public: CompareTwoPublicInputs,
}

#[derive(Clone)]
struct CompareTwoPrivateInputs {
    tx_context: TxContext,
    first_utxo: WalletUtxo,
    first: Account,
    second_utxo: WalletUtxo,
    second: Account,
}

#[derive(Clone)]
struct CompareTwoPublicInputs {
    total: u64,
}

impl ProofInput for CompareTwo {
    type Circuit = circuit::CompareTwo;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::CompareTwo, RelationError> {
        let private = &self.private;
        Ok(circuit::CompareTwo {
            private: circuit::CompareTwoPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                first_utxo: private.first_utxo.instantiate(allocator)?,
                first: private.first.instantiate(allocator)?,
                second_utxo: private.second_utxo.instantiate(allocator)?,
                second: private.second.instantiate(allocator)?,
            },
            public: circuit::CompareTwoPublicInputs {
                total: self.public.total.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for CompareTwo {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: CompareTwoPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                first_utxo: Placeholder::placeholder()?,
                first: Placeholder::placeholder()?,
                second_utxo: Placeholder::placeholder()?,
                second: Placeholder::placeholder()?,
            },
            public: CompareTwoPublicInputs {
                total: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, Assert, CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction,
            DataUtxo, PublicInputs, TxContext, Utxo,
        },
        RelationError,
    };

    use crate::s25_read_with_threshold::circuit::Account;

    pub struct CompareTwo {
        pub private: CompareTwoPrivateInputs,
        pub public: CompareTwoPublicInputs,
    }

    pub struct CompareTwoPrivateInputs {
        pub tx_context: TxContext,
        pub first_utxo: Utxo,
        pub first: Account,
        pub second_utxo: Utxo,
        pub second: Account,
    }

    pub struct CompareTwoPublicInputs {
        pub total: CircuitVar,
    }

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

    impl PublicInputs for CompareTwoPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.total.clone(), transaction_hash.clone()])
        }
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
