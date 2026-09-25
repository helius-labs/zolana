use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input},
};

const RECIPIENTS: usize = 7;

#[derive(Clone)]
struct FanOut {
    private: FanOutPrivateInputs,
    public: FanOutPublicInputs,
}

#[derive(Clone)]
struct FanOutPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    recipients: [ShieldedAddress; RECIPIENTS],
    amounts: [u64; RECIPIENTS],
}

#[derive(Clone)]
struct FanOutPublicInputs {
    total: u64,
}

impl ProofInput for FanOut {
    type Circuit = circuit::FanOut;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::FanOut, RelationError> {
        let private = &self.private;
        Ok(circuit::FanOut {
            private: circuit::FanOutPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                recipients: private.recipients.instantiate(allocator)?,
                amounts: private.amounts.instantiate(allocator)?,
            },
            public: circuit::FanOutPublicInputs {
                total: self.public.total.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for FanOut {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: FanOutPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                recipients: Placeholder::placeholder()?,
                amounts: Placeholder::placeholder()?,
            },
            public: FanOutPublicInputs {
                total: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, zero, Assert, Balance, CheckedTransaction, Circuit, CircuitVar,
            ConfidentialTransaction, Owner, PublicInputs, TokenUtxo, TxContext, Utxo,
        },
        RelationError,
    };

    use super::RECIPIENTS;

    pub struct FanOut {
        pub private: FanOutPrivateInputs,
        pub public: FanOutPublicInputs,
    }

    pub struct FanOutPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 1],
        pub recipients: [Owner; RECIPIENTS],
        pub amounts: [CircuitVar; RECIPIENTS],
    }

    pub struct FanOutPublicInputs {
        pub total: CircuitVar,
    }

    impl Circuit for FanOut {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            private
                .amounts
                .iter()
                .fold(zero(), |sum, amount| sum + amount)
                .assert_equal(&self.public.total, "the payments do not sum to the total")?;
            let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let payments: Vec<_> = private
                .recipients
                .iter()
                .zip(&private.amounts)
                .map(|(recipient, amount)| tokens.transfer(recipient, amount))
                .collect::<Result<_, _>>()?;

            payments
                .into_iter()
                .fold(
                    ConfidentialTransaction::new(&private.tx_context, &self.public)
                        .with_token_utxos(tokens),
                    ConfidentialTransaction::with_output_token_utxo,
                )
                .check()
        }
    }

    impl PublicInputs for FanOutPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.total.clone(), transaction_hash.clone()])
        }
    }
}

#[test]
fn fan_out_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipients: [ShieldedAddress; RECIPIENTS] = std::array::from_fn(|index| {
        keypair(6 + u8::try_from(index).expect("recipient seed"))
            .shielded_address()
            .expect("recipient address")
    });
    let amounts = [10, 20, 30, 40, 50, 60, 70];
    let input = token_input(&sender, Mint::SOL, 1_000, 0);

    let fan_out = FanOut {
        private: FanOutPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            recipients,
            amounts,
        },
        public: FanOutPublicInputs { total: 280 },
    };
    let spp_proof_inputs = fan_out
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("fan-out proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.amount))
            .collect::<Vec<_>>(),
        core::iter::once((Some(address), 720))
            .chain(
                recipients
                    .iter()
                    .zip(amounts)
                    .map(|(recipient, amount)| (Some(*recipient), amount))
            )
            .collect::<Vec<_>>()
    );

    let prover = Groth16Prover::<FanOut>::new_with_test_setup().expect("fan-out setup");
    let result = prove(&prover, &fan_out, "fan-out proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
