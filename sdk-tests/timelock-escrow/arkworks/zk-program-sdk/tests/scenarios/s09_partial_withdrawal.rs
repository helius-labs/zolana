use solana_address::Address;
use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_transaction::{instructions::transact::SettlementTransfer, Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input},
};

#[derive(Clone)]
struct Withdrawal {
    private: WithdrawalPrivateInputs,
    public: WithdrawalPublicInputs,
}

#[derive(Clone)]
struct WithdrawalPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    destination: Address,
}

#[derive(Clone)]
struct WithdrawalPublicInputs {
    amount: u64,
}

impl ProofInput for Withdrawal {
    type Circuit = circuit::Withdrawal;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Withdrawal, RelationError> {
        let private = &self.private;
        Ok(circuit::Withdrawal {
            private: circuit::WithdrawalPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                destination: private.destination.instantiate(allocator)?,
            },
            public: circuit::WithdrawalPublicInputs {
                amount: self.public.amount.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for Withdrawal {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: WithdrawalPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                destination: Placeholder::placeholder()?,
            },
            public: WithdrawalPublicInputs {
                amount: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, Balance, Bytes, CheckedTransaction, Circuit, CircuitVar,
            ConfidentialTransaction, PublicInputs, TokenUtxo, TxContext, Utxo,
        },
        RelationError,
    };

    pub struct Withdrawal {
        pub private: WithdrawalPrivateInputs,
        pub public: WithdrawalPublicInputs,
    }

    pub struct WithdrawalPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 1],
        pub destination: Bytes<32>,
    }

    pub struct WithdrawalPublicInputs {
        pub amount: CircuitVar,
    }

    impl Circuit for Withdrawal {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            tokens.withdraw(&self.public.amount, &private.destination)?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .check()
        }
    }

    impl PublicInputs for WithdrawalPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.amount.clone(), transaction_hash.clone()])
        }
    }
}

#[test]
fn partial_withdrawal_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let destination = Address::new_from_array([8u8; 32]);
    let input = token_input(&sender, Mint::SOL, 300, 0);

    let withdrawal = Withdrawal {
        private: WithdrawalPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            destination,
        },
        public: WithdrawalPublicInputs { amount: 120 },
    };
    let spp_proof_inputs = withdrawal
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("withdrawal proof inputs");
    assert_eq!(
        (
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.asset, output.amount))
                .collect::<Vec<_>>(),
            spp_proof_inputs.external_data.interface_transfers.clone(),
        ),
        (
            vec![(Some(address), Mint::SOL, 180)],
            vec![SettlementTransfer::Sol {
                is_deposit: false,
                amount: 120,
                user_sol_account: destination,
            }],
        )
    );

    let prover = Groth16Prover::<Withdrawal>::new_with_test_setup().expect("withdrawal setup");
    let result = prove(&prover, &withdrawal, "withdrawal proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
