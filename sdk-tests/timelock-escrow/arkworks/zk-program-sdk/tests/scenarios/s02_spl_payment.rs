use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError, Groth16Prover, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input, USDC},
};

#[derive(Clone)]
struct SplPayment {
    private: SplPaymentPrivateInputs,
    public: SplPaymentPublicInputs,
}

#[derive(Clone)]
struct SplPaymentPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    amount: u64,
}

#[derive(Clone)]
struct SplPaymentPublicInputs {
    recipient: ShieldedAddress,
    mint: Mint,
}

impl zk_program_sdk::circuit::CircuitType for circuit::SplPayment {}

impl ProofInput for SplPayment {
    type Circuit = circuit::SplPayment;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::SplPayment, CircuitError> {
        let private = &self.private;
        Ok(circuit::SplPayment {
            private: circuit::SplPaymentPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                amount: private.amount.instantiate(allocator)?,
            },
            public: circuit::SplPaymentPublicInputs {
                recipient: self.public.recipient.instantiate(allocator)?,
                mint: self.public.mint.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for SplPayment {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self {
            private: SplPaymentPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                amount: Placeholder::placeholder()?,
            },
            public: SplPaymentPublicInputs {
                recipient: Placeholder::placeholder()?,
                mint: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, Asset, CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction,
            Owner, PublicInputs, TokenUtxos, TxContext, Uint, Utxo, UtxoTrait,
        },
        CircuitError,
    };

    pub struct SplPayment {
        pub private: SplPaymentPrivateInputs,
        pub public: SplPaymentPublicInputs,
    }

    pub struct SplPaymentPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 1],
        pub amount: Uint<64>,
    }

    pub struct SplPaymentPublicInputs {
        pub recipient: Owner,
        pub mint: Asset,
    }

    impl Circuit for SplPayment {
        fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
            let private = &self.private;
            let mut tokens = TokenUtxos::new_mut(&private.token_utxos_asset_a)?;
            let mut payment = TokenUtxos::new_init(&self.public.recipient, &self.public.mint);
            tokens.transfer(&mut payment, &private.amount)?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_token_utxos(payment)
                .check()
        }
    }

    impl PublicInputs for SplPaymentPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, CircuitError> {
            poseidon(&[
                self.recipient.hash()?,
                self.mint.hash()?,
                transaction_hash.clone(),
            ])
        }
    }
}

#[test]
fn spl_payment_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let input = token_input(&sender, USDC, 500, 0);

    let payment = SplPayment {
        private: SplPaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            amount: 400,
        },
        public: SplPaymentPublicInputs {
            recipient,
            mint: USDC,
        },
    };
    let spp_proof_inputs = payment
        .create_proof_inputs_and_encrypt(&address, payer)
        .expect("spl payment proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect::<Vec<_>>(),
        vec![(Some(address), USDC, 100), (Some(recipient), USDC, 400)]
    );

    let prover = Groth16Prover::<SplPayment>::new_with_test_setup().expect("spl payment setup");
    let result = prove(&prover, &payment, "spl payment proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}

#[test]
fn spl_payment_encrypts_with_the_synced_key_of_its_first_input() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let synced_key = keypair(7).viewing_key;
    let mut input = token_input(&sender, USDC, 500, 0);
    input.tx_viewing_key = Some(*synced_key.secret_bytes());

    let payment = SplPayment {
        private: SplPaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            amount: 400,
        },
        public: SplPaymentPublicInputs {
            recipient,
            mint: USDC,
        },
    };
    let spp_proof_inputs = payment
        .create_proof_inputs_and_encrypt(&address, payer)
        .expect("spl payment proof inputs");

    assert_eq!(
        spp_proof_inputs.external_data.tx_viewing_pk,
        *synced_key.pubkey().as_bytes()
    );
}
