use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    s27_escrow::{escrow_utxo, EscrowTerms},
    shared::keypair,
};

#[derive(Clone)]
struct SplitWithdraw {
    private: SplitWithdrawPrivateInputs,
    public: SplitWithdrawPublicInputs,
}

#[derive(Clone)]
struct SplitWithdrawPrivateInputs {
    tx_context: TxContext,
    escrow: WalletUtxo,
    terms: EscrowTerms,
}

#[derive(Clone)]
struct SplitWithdrawPublicInputs {
    unlock: u64,
    owner_identity: [u8; 32],
    fee_recipient: ShieldedAddress,
    fee: u64,
}

impl ProofInput for SplitWithdraw {
    type Circuit = circuit::SplitWithdraw;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::SplitWithdraw, RelationError> {
        let private = &self.private;
        let public = &self.public;
        Ok(circuit::SplitWithdraw {
            private: circuit::SplitWithdrawPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                escrow: private.escrow.instantiate(allocator)?,
                terms: private.terms.instantiate(allocator)?,
            },
            public: circuit::SplitWithdrawPublicInputs {
                unlock: public.unlock.instantiate(allocator)?,
                owner_identity: public.owner_identity.instantiate(allocator)?,
                fee_recipient: public.fee_recipient.instantiate(allocator)?,
                fee: public.fee.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for SplitWithdraw {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: SplitWithdrawPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                escrow: Placeholder::placeholder()?,
                terms: Placeholder::placeholder()?,
            },
            public: SplitWithdrawPublicInputs {
                unlock: Placeholder::placeholder()?,
                owner_identity: Placeholder::placeholder()?,
                fee_recipient: Placeholder::placeholder()?,
                fee: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, zero, Assert, Balance, CheckedTransaction, Circuit, CircuitVar,
            ConfidentialTransaction, DataUtxo, Owner, PublicInputs, TxContext, Utxo,
        },
        RelationError,
    };

    use crate::s27_escrow::circuit::EscrowTerms;

    pub struct SplitWithdraw {
        pub private: SplitWithdrawPrivateInputs,
        pub public: SplitWithdrawPublicInputs,
    }

    pub struct SplitWithdrawPrivateInputs {
        pub tx_context: TxContext,
        pub escrow: Utxo,
        pub terms: EscrowTerms,
    }

    pub struct SplitWithdrawPublicInputs {
        pub unlock: CircuitVar,
        pub owner_identity: CircuitVar,
        pub fee_recipient: Owner,
        pub fee: CircuitVar,
    }

    impl Circuit for SplitWithdraw {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let public = &self.public;
            let mut escrow = DataUtxo::new_burn(&private.escrow, &private.terms)?;
            escrow
                .balance()
                .assert_not_equal(&zero(), "the escrow utxo holds nothing")?;
            escrow.creator.key().identity()?.assert_equal(
                &public.owner_identity,
                "the signer is not the escrow creator",
            )?;
            public
                .unlock
                .assert_equal(&escrow.unlock, "the unlock time is not the escrow's")?;
            let fee = escrow.transfer(&public.fee_recipient, &public.fee)?;
            let creator = escrow.creator.clone();
            let payout = escrow.transfer_all(&creator);
            payout.amount().check_bits(64)?;

            ConfidentialTransaction::new(&private.tx_context, public)
                .with_data_utxo(escrow)
                .with_output_token_utxo(payout)
                .with_output_token_utxo(fee)
                .check()
        }
    }

    impl PublicInputs for SplitWithdrawPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.unlock.clone(),
                self.owner_identity.clone(),
                self.fee_recipient.hash()?,
                self.fee.clone(),
                transaction_hash.clone(),
            ])
        }
    }
}

#[test]
fn split_withdrawal_prove_and_verify() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let payer = address.solana_address().expect("payer");
    let fee_recipient = keypair(6)
        .shielded_address()
        .expect("fee recipient address");
    let (escrow, terms) = escrow_utxo(&creator, Mint::SOL, 250, 1_700_000_000);

    let withdraw = SplitWithdraw {
        private: SplitWithdrawPrivateInputs {
            tx_context: TxContext::new(),
            escrow,
            terms,
        },
        public: SplitWithdrawPublicInputs {
            unlock: 1_700_000_000,
            owner_identity: solana_owner_identity(payer.as_array()).expect("owner identity"),
            fee_recipient,
            fee: 10,
        },
    };
    let spp_proof_inputs = withdraw
        .create_proof_inputs_and_encrypt(&creator, payer, u64::MAX)
        .expect("split withdraw proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect::<Vec<_>>(),
        vec![
            (Some(address), Mint::SOL, 240),
            (Some(fee_recipient), Mint::SOL, 10),
        ]
    );

    let prover =
        Groth16Prover::<SplitWithdraw>::new_with_test_setup().expect("split withdraw setup");
    let result = prover.prove(&withdraw).expect("split withdraw proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
