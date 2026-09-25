use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    conversion::{Allocator, FromCircuit, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{data_input, keypair},
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Account {
    pub balance: u64,
}

impl ProofInput for Account {
    type Circuit = circuit::Account;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Account, RelationError> {
        Ok(circuit::Account {
            balance: self.balance.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Account {
    fn from_circuit(circuit: &circuit::Account) -> Result<Self, RelationError> {
        Ok(Self {
            balance: u64::from_circuit(&circuit.balance)?,
        })
    }
}

impl Placeholder for Account {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            balance: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone)]
struct ReadThreshold {
    private: ReadThresholdPrivateInputs,
    public: ReadThresholdPublicInputs,
}

#[derive(Clone)]
struct ReadThresholdPrivateInputs {
    tx_context: TxContext,
    account_utxo: WalletUtxo,
    account: Account,
}

#[derive(Clone)]
struct ReadThresholdPublicInputs {
    threshold: u64,
}

impl ProofInput for ReadThreshold {
    type Circuit = circuit::ReadThreshold;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::ReadThreshold, RelationError> {
        let private = &self.private;
        Ok(circuit::ReadThreshold {
            private: circuit::ReadThresholdPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                account_utxo: private.account_utxo.instantiate(allocator)?,
                account: private.account.instantiate(allocator)?,
            },
            public: circuit::ReadThresholdPublicInputs {
                threshold: self.public.threshold.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for ReadThreshold {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: ReadThresholdPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                account_utxo: Placeholder::placeholder()?,
                account: Placeholder::placeholder()?,
            },
            public: ReadThresholdPublicInputs {
                threshold: Placeholder::placeholder()?,
            },
        })
    }
}

pub(crate) mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, zero, Assert, CheckedTransaction, Circuit, CircuitVar,
            ConfidentialTransaction, DataHash, DataUtxo, PublicInputs, TxContext, Utxo, UtxoData,
        },
        RelationError,
    };

    #[derive(Clone, Debug)]
    pub struct Account {
        pub balance: CircuitVar,
    }

    impl Default for Account {
        fn default() -> Self {
            Self { balance: zero() }
        }
    }

    impl DataHash for Account {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(std::slice::from_ref(&self.balance))
        }
    }

    impl UtxoData for Account {
        type Client = super::Account;
    }

    pub struct ReadThreshold {
        pub private: ReadThresholdPrivateInputs,
        pub public: ReadThresholdPublicInputs,
    }

    pub struct ReadThresholdPrivateInputs {
        pub tx_context: TxContext,
        pub account_utxo: Utxo,
        pub account: Account,
    }

    pub struct ReadThresholdPublicInputs {
        pub threshold: CircuitVar,
    }

    impl Circuit for ReadThreshold {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let account = DataUtxo::new_mut(&private.account_utxo, &private.account)?;
            (account.balance.clone() - &self.public.threshold).check_bits(64)?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_data_utxo(account)
                .check()
        }
    }

    impl PublicInputs for ReadThresholdPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.threshold.clone(), transaction_hash.clone()])
        }
    }
}

#[test]
fn read_with_threshold_prove_and_verify() {
    let owner = keypair(5);
    let address = owner.shielded_address().expect("owner address");
    let payer = address.solana_address().expect("payer");
    let account = Account { balance: 700 };
    let account_utxo = data_input(&owner, 0, &account, 0);

    let read = ReadThreshold {
        private: ReadThresholdPrivateInputs {
            tx_context: TxContext::new(),
            account_utxo,
            account: account.clone(),
        },
        public: ReadThresholdPublicInputs { threshold: 500 },
    };
    let spp_proof_inputs = read
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("read proof inputs");
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
            Some(borsh::to_vec(&account).expect("account bytes")),
        )]
    );

    let prover = Groth16Prover::<ReadThreshold>::new_with_test_setup().expect("read setup");
    let result = prove(&prover, &read, "read proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
