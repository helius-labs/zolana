use solana_address::Address;
use spr_interface::instruction::instruction_data::transact::OwnerTag;
use spr_program::{
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError, Groth16Prover, TxContext, ZkProgramCircuit,
};
use spr_transaction::{instructions::transact::SettlementTransfer, Mint, WalletUtxo};

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

impl spr_program::circuit::CircuitType for circuit::Withdrawal {}

impl ProofInput for Withdrawal {
    type Circuit = circuit::Withdrawal;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Withdrawal, CircuitError> {
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
    fn placeholder() -> Result<Self, CircuitError> {
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
    use spr_program::{
        circuit::{
            poseidon, Assert, CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction,
            PublicInputs, SolanaAddress, TokenUtxos, TxContext, Uint, Utxo, UtxoTrait,
        },
        CircuitError,
    };

    pub struct Withdrawal {
        pub private: WithdrawalPrivateInputs,
        pub public: WithdrawalPublicInputs,
    }

    pub struct WithdrawalPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 1],
        pub destination: SolanaAddress,
    }

    pub struct WithdrawalPublicInputs {
        pub amount: Uint<64>,
    }

    impl Circuit for Withdrawal {
        type Output = CheckedTransaction;

        fn circuit(&self) -> Result<Self::Output, CircuitError> {
            let private = &self.private;
            let mut tokens = TokenUtxos::new_mut(&private.token_utxos_asset_a)?.close();
            let withdrawn = tokens.withdraw_all(&private.destination)?;
            self.public
                .amount
                .assert_equal(&withdrawn, "the withdrawal is not the public amount")?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with(tokens)
                .check()
        }
    }

    impl PublicInputs for WithdrawalPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, CircuitError> {
            poseidon(&[self.amount.clone().into(), transaction_hash.clone()])
        }
    }
}

#[test]
fn full_withdrawal_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    // Compact padding publishes no owner tags for the empty outputs.
    let payer = sender
        .shielded_address()
        .and_then(|address| address.solana_address())
        .expect("payer");
    let destination = Address::new_from_array([8u8; 32]);
    let input = token_input(&sender, Mint::SOL, 300, 0);

    let withdrawal = Withdrawal {
        private: WithdrawalPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            destination,
        },
        public: WithdrawalPublicInputs { amount: 300 },
    };
    let spp_proof_inputs = withdrawal
        .create_proof_inputs_and_encrypt(&address, payer)
        .expect("withdrawal proof inputs");
    assert_eq!(
        (
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.amount))
                .collect::<Vec<_>>(),
            spp_proof_inputs
                .external_data
                .outputs
                .iter()
                .map(|output| output.owner_tag)
                .collect::<Vec<_>>(),
            spp_proof_inputs.external_data.resolved_owner_tags.clone(),
            spp_proof_inputs.external_data.interface_transfers.clone(),
        ),
        (
            vec![(None, 0), (None, 0)],
            Vec::<OwnerTag>::new(),
            Vec::<[u8; 32]>::new(),
            vec![SettlementTransfer::Sol {
                is_deposit: false,
                amount: 300,
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
