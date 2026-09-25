use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s27_escrow::{escrow_utxo, EscrowTerms},
    shared::keypair,
};

#[derive(Clone)]
pub(crate) struct Withdraw {
    pub(crate) private: WithdrawPrivateInputs,
    pub(crate) public: WithdrawPublicInputs,
}

#[derive(Clone)]
pub(crate) struct WithdrawPrivateInputs {
    pub(crate) tx_context: TxContext,
    pub(crate) escrow: WalletUtxo,
    pub(crate) terms: EscrowTerms,
}

#[derive(Clone)]
pub(crate) struct WithdrawPublicInputs {
    pub(crate) unlock: u64,
    pub(crate) owner_identity: [u8; 32],
}

impl ProofInput for Withdraw {
    type Circuit = circuit::Withdraw;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Withdraw, RelationError> {
        let private = &self.private;
        Ok(circuit::Withdraw {
            private: circuit::WithdrawPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                escrow: private.escrow.instantiate(allocator)?,
                terms: private.terms.instantiate(allocator)?,
            },
            public: circuit::WithdrawPublicInputs {
                unlock: self.public.unlock.instantiate(allocator)?,
                owner_identity: self.public.owner_identity.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for Withdraw {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: WithdrawPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                escrow: Placeholder::placeholder()?,
                terms: Placeholder::placeholder()?,
            },
            public: WithdrawPublicInputs {
                unlock: Placeholder::placeholder()?,
                owner_identity: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, zero, Assert, Balance, CheckedTransaction, Circuit, CircuitVar,
            ConfidentialTransaction, DataUtxo, PublicInputs, TxContext, Utxo,
        },
        RelationError,
    };

    use crate::s27_escrow::circuit::EscrowTerms;

    pub struct Withdraw {
        pub private: WithdrawPrivateInputs,
        pub public: WithdrawPublicInputs,
    }

    pub struct WithdrawPrivateInputs {
        pub tx_context: TxContext,
        pub escrow: Utxo,
        pub terms: EscrowTerms,
    }

    pub struct WithdrawPublicInputs {
        pub unlock: CircuitVar,
        pub owner_identity: CircuitVar,
    }

    impl Circuit for Withdraw {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let mut escrow = DataUtxo::new_burn(&private.escrow, &private.terms)?;
            escrow
                .balance()
                .assert_not_equal(&zero(), "the escrow utxo holds nothing")?;
            escrow.creator.key().identity()?.assert_equal(
                &self.public.owner_identity,
                "the signer is not the escrow creator",
            )?;
            self.public
                .unlock
                .assert_equal(&escrow.unlock, "the unlock time is not the escrow's")?;
            let creator = escrow.creator.clone();
            let payout = escrow.transfer_all(&creator);

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_data_utxo(escrow)
                .with_output_token_utxo(payout)
                .check()
        }
    }

    impl PublicInputs for WithdrawPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.unlock.clone(),
                self.owner_identity.clone(),
                transaction_hash.clone(),
            ])
        }
    }
}

#[test]
fn escrow_withdraw_prove_and_verify() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let payer = address.solana_address().expect("payer");
    let (escrow, terms) = escrow_utxo(&creator, Mint::SOL, 250, 1_700_000_000);

    let withdraw = Withdraw {
        private: WithdrawPrivateInputs {
            tx_context: TxContext::new(),
            escrow,
            terms,
        },
        public: WithdrawPublicInputs {
            unlock: 1_700_000_000,
            owner_identity: solana_owner_identity(payer.as_array()).expect("owner identity"),
        },
    };
    let spp_proof_inputs = withdraw
        .create_proof_inputs_and_encrypt(&creator, payer, u64::MAX)
        .expect("withdraw proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect::<Vec<_>>(),
        vec![(Some(address), Mint::SOL, 250)]
    );

    let prover = Groth16Prover::<Withdraw>::new_with_test_setup().expect("withdraw setup");
    let result = prove(&prover, &withdraw, "withdraw proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
