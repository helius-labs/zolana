use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s31_order_make::{order_utxo, OrderTerms},
    shared::keypair,
};

#[derive(Clone)]
struct Cancel {
    private: CancelPrivateInputs,
    public: CancelPublicInputs,
}

#[derive(Clone)]
struct CancelPrivateInputs {
    tx_context: TxContext,
    order: WalletUtxo,
    terms: OrderTerms,
    maker: ShieldedAddress,
}

#[derive(Clone)]
struct CancelPublicInputs {
    expiry: u64,
    maker_identity: [u8; 32],
}

impl zk_program_sdk::circuit::CircuitType for circuit::Cancel {}

impl ProofInput for Cancel {
    type Circuit = circuit::Cancel;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Cancel, RelationError> {
        let private = &self.private;
        Ok(circuit::Cancel {
            private: circuit::CancelPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                order: private.order.instantiate(allocator)?,
                terms: private.terms.instantiate(allocator)?,
                maker: private.maker.instantiate(allocator)?,
            },
            public: circuit::CancelPublicInputs {
                expiry: self.public.expiry.instantiate(allocator)?,
                maker_identity: self.public.maker_identity.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for Cancel {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: CancelPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                order: Placeholder::placeholder()?,
                terms: Placeholder::placeholder()?,
                maker: Placeholder::placeholder()?,
            },
            public: CancelPublicInputs {
                expiry: Placeholder::placeholder()?,
                maker_identity: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, Assert, Balance, CheckedTransaction, Circuit, CircuitMarker, CircuitVar,
            ConfidentialTransaction, DataUtxo, Owner, PublicInputs, TokenUtxo, TxContext, Utxo,
        },
        RelationError,
    };

    use crate::s31_order_make::circuit::OrderTerms;

    pub struct Cancel {
        pub private: CancelPrivateInputs,
        pub public: CancelPublicInputs,
    }

    pub struct CancelPrivateInputs {
        pub tx_context: TxContext,
        pub order: Utxo,
        pub terms: OrderTerms,
        pub maker: Owner,
    }

    pub struct CancelPublicInputs {
        pub expiry: CircuitVar,
        pub maker_identity: CircuitVar,
    }

    impl Circuit for Cancel {
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let public = &self.public;
            let mut order = DataUtxo::new_burn(&private.order, &private.terms)?;
            private
                .maker
                .hash()?
                .assert_equal(&order.maker_hash, "the maker is not the order's")?;
            private.maker.key().identity()?.assert_equal(
                &public.maker_identity,
                "the signer is not the order's maker",
            )?;
            public
                .expiry
                .assert_equal(&order.expiry, "the expiry is not the order's")?;
            let mut refund = TokenUtxo::new_init(&private.maker, &order.asset());
            order.transfer_all(&mut refund)?;

            ConfidentialTransaction::new(&private.tx_context, public)
                .with_data_utxo(order)
                .with_token_utxos(refund)
                .check()
        }
    }

    impl PublicInputs for CancelPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.expiry.clone(),
                self.maker_identity.clone(),
                transaction_hash.clone(),
            ])
        }
    }
}

#[test]
fn order_cancel_prove_and_verify() {
    let maker = keypair(5);
    let address = maker.shielded_address().expect("maker address");
    let payer = address.solana_address().expect("payer");
    let (order, terms) = order_utxo(&maker, 500, 60, 1_800_000_000);

    let cancel = Cancel {
        private: CancelPrivateInputs {
            tx_context: TxContext::new(),
            order,
            terms,
            maker: address,
        },
        public: CancelPublicInputs {
            expiry: 1_800_000_000,
            maker_identity: solana_owner_identity(payer.as_array()).expect("maker identity"),
        },
    };
    let spp_proof_inputs = cancel
        .create_proof_inputs_and_encrypt(&maker, payer, u64::MAX)
        .expect("cancel proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect::<Vec<_>>(),
        vec![(Some(address), Mint::SOL, 500)]
    );

    let prover = Groth16Prover::<Cancel>::new_with_test_setup().expect("cancel setup");
    let result = prove(&prover, &cancel, "cancel proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
