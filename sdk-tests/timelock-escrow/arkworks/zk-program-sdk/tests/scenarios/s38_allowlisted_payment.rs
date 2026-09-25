use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::shared::{keypair, token_input, MerklePath, MerkleTree};

#[derive(Clone)]
struct AllowlistedPayment {
    private: AllowlistedPaymentPrivateInputs,
    public: AllowlistedPaymentPublicInputs,
}

#[derive(Clone)]
struct AllowlistedPaymentPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
    amount: u64,
    path: MerklePath,
}

#[derive(Clone)]
struct AllowlistedPaymentPublicInputs {
    root: [u8; 32],
    recipient: ShieldedAddress,
}

impl ProofInput for AllowlistedPayment {
    type Circuit = circuit::AllowlistedPayment;

    fn instantiate(
        &self,
        allocator: &Allocator,
    ) -> Result<circuit::AllowlistedPayment, RelationError> {
        let private = &self.private;
        Ok(circuit::AllowlistedPayment {
            private: circuit::AllowlistedPaymentPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                amount: private.amount.instantiate(allocator)?,
                path: private.path.instantiate(allocator)?,
            },
            public: circuit::AllowlistedPaymentPublicInputs {
                root: self.public.root.instantiate(allocator)?,
                recipient: self.public.recipient.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for AllowlistedPayment {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: AllowlistedPaymentPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                amount: Placeholder::placeholder()?,
                path: Placeholder::placeholder()?,
            },
            public: AllowlistedPaymentPublicInputs {
                root: Placeholder::placeholder()?,
                recipient: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, Assert, Balance, CheckedTransaction, Circuit, CircuitVar,
            ConfidentialTransaction, Owner, PublicInputs, TokenUtxo, TxContext, Utxo,
        },
        RelationError,
    };

    use crate::shared::CircuitMerklePath;

    pub struct AllowlistedPayment {
        pub private: AllowlistedPaymentPrivateInputs,
        pub public: AllowlistedPaymentPublicInputs,
    }

    pub struct AllowlistedPaymentPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 2],
        pub amount: CircuitVar,
        pub path: CircuitMerklePath,
    }

    pub struct AllowlistedPaymentPublicInputs {
        pub root: CircuitVar,
        pub recipient: Owner,
    }

    impl Circuit for AllowlistedPayment {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let public = &self.public;
            private
                .path
                .root(&public.recipient.hash()?)?
                .assert_equal(&public.root, "the recipient is not on the allowlist")?;
            let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let payment = tokens.transfer(&public.recipient, &private.amount)?;

            ConfidentialTransaction::new(&private.tx_context, public)
                .with_token_utxos(tokens)
                .with_output_token_utxo(payment)
                .check()
        }
    }

    impl PublicInputs for AllowlistedPaymentPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.root.clone(),
                self.recipient.hash()?,
                transaction_hash.clone(),
            ])
        }
    }
}

#[test]
fn allowlisted_payment_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let allowlist = MerkleTree::new(&[7u8, 6, 8].map(|seed| {
        keypair(seed)
            .shielded_address()
            .expect("allowlisted address")
            .owner_hash()
            .expect("allowlisted owner hash")
    }));
    let first = token_input(&sender, Mint::SOL, 300, 0);
    let second = token_input(&sender, Mint::SOL, 200, 1);

    let payment = AllowlistedPayment {
        private: AllowlistedPaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, second],
            amount: 400,
            path: allowlist.path(1),
        },
        public: AllowlistedPaymentPublicInputs {
            root: allowlist.root(),
            recipient,
        },
    };
    let spp_proof_inputs = payment
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("allowlisted payment proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect::<Vec<_>>(),
        vec![
            (Some(address), Mint::SOL, 100),
            (Some(recipient), Mint::SOL, 400),
        ]
    );

    let prover = Groth16Prover::<AllowlistedPayment>::new_with_test_setup()
        .expect("allowlisted payment setup");
    let result = prover.prove(&payment).expect("allowlisted payment proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
