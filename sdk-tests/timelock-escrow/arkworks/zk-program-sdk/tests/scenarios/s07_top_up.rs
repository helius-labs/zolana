use solana_address::Address;
use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_transaction::{instructions::transact::SettlementTransfer, Mint, WalletUtxo};

use crate::shared::{keypair, token_input};

#[derive(Clone)]
struct TopUp {
    private: TopUpPrivateInputs,
    public: TopUpPublicInputs,
}

#[derive(Clone)]
struct TopUpPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    source: Address,
}

#[derive(Clone)]
struct TopUpPublicInputs {
    amount: u64,
}

impl ProofInput for TopUp {
    type Circuit = circuit::TopUp;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::TopUp, RelationError> {
        let private = &self.private;
        Ok(circuit::TopUp {
            private: circuit::TopUpPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                source: private.source.instantiate(allocator)?,
            },
            public: circuit::TopUpPublicInputs {
                amount: self.public.amount.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for TopUp {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: TopUpPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                source: Placeholder::placeholder()?,
            },
            public: TopUpPublicInputs {
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

    pub struct TopUp {
        pub private: TopUpPrivateInputs,
        pub public: TopUpPublicInputs,
    }

    pub struct TopUpPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 1],
        pub source: Bytes<32>,
    }

    pub struct TopUpPublicInputs {
        pub amount: CircuitVar,
    }

    impl Circuit for TopUp {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            tokens.deposit(&self.public.amount, &private.source)?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .check()
        }
    }

    impl PublicInputs for TopUpPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.amount.clone(), transaction_hash.clone()])
        }
    }
}

#[test]
fn top_up_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let input = token_input(&sender, Mint::SOL, 300, 0);

    let top_up = TopUp {
        private: TopUpPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            source: payer,
        },
        public: TopUpPublicInputs { amount: 50 },
    };
    let spp_proof_inputs = top_up
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("top-up proof inputs");
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
            vec![(Some(address), Mint::SOL, 350)],
            vec![SettlementTransfer::Sol {
                is_deposit: true,
                amount: 50,
                user_sol_account: payer,
            }],
        )
    );

    let prover = Groth16Prover::<TopUp>::new_with_test_setup().expect("top-up setup");
    let result = prover.prove(&top_up).expect("top-up proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
