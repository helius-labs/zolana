use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s44_mixer_deposit::{commitment_utxo, MixerCommitment, DENOMINATION},
    shared::{keypair, poseidon_bytes},
};

#[derive(Clone)]
struct MixerWithdrawal {
    private: MixerWithdrawalPrivateInputs,
    public: MixerWithdrawalPublicInputs,
}

#[derive(Clone)]
struct MixerWithdrawalPrivateInputs {
    tx_context: TxContext,
    note: WalletUtxo,
    commitment: MixerCommitment,
    nullifier_secret: [u8; 32],
    secret: [u8; 32],
}

#[derive(Clone)]
struct MixerWithdrawalPublicInputs {
    recipient: ShieldedAddress,
    nullifier_hash: [u8; 32],
}

impl zk_program_sdk::circuit::CircuitType for circuit::MixerWithdrawal {}

impl ProofInput for MixerWithdrawal {
    type Circuit = circuit::MixerWithdrawal;

    fn instantiate(
        &self,
        allocator: &Allocator,
    ) -> Result<circuit::MixerWithdrawal, RelationError> {
        let private = &self.private;
        Ok(circuit::MixerWithdrawal {
            private: circuit::MixerWithdrawalPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                note: private.note.instantiate(allocator)?,
                commitment: private.commitment.instantiate(allocator)?,
                nullifier_secret: private.nullifier_secret.instantiate(allocator)?,
                secret: private.secret.instantiate(allocator)?,
            },
            public: circuit::MixerWithdrawalPublicInputs {
                recipient: self.public.recipient.instantiate(allocator)?,
                nullifier_hash: self.public.nullifier_hash.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for MixerWithdrawal {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: MixerWithdrawalPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                note: Placeholder::placeholder()?,
                commitment: Placeholder::placeholder()?,
                nullifier_secret: Placeholder::placeholder()?,
                secret: Placeholder::placeholder()?,
            },
            public: MixerWithdrawalPublicInputs {
                recipient: Placeholder::placeholder()?,
                nullifier_hash: Placeholder::placeholder()?,
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

    use crate::s44_mixer_deposit::circuit::MixerCommitment;

    pub struct MixerWithdrawal {
        pub private: MixerWithdrawalPrivateInputs,
        pub public: MixerWithdrawalPublicInputs,
    }

    pub struct MixerWithdrawalPrivateInputs {
        pub tx_context: TxContext,
        pub note: Utxo,
        pub commitment: MixerCommitment,
        pub nullifier_secret: CircuitVar,
        pub secret: CircuitVar,
    }

    pub struct MixerWithdrawalPublicInputs {
        pub recipient: Owner,
        pub nullifier_hash: CircuitVar,
    }

    impl Circuit for MixerWithdrawal {
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let public = &self.public;
            let mut note = DataUtxo::new_burn(&private.note, &private.commitment)?;
            poseidon(&[private.nullifier_secret.clone(), private.secret.clone()])?
                .assert_equal(&note.commitment, "the secrets do not open the commitment")?;
            poseidon(std::slice::from_ref(&private.nullifier_secret))?.assert_equal(
                &public.nullifier_hash,
                "the nullifier hash is not the commitment's",
            )?;
            let mut payout = TokenUtxo::new_init(&public.recipient, &note.asset());
            note.transfer_all(&mut payout)?;

            ConfidentialTransaction::new(&private.tx_context, public)
                .with_data_utxo(note)
                .with_token_utxos(payout)
                .check()
        }
    }

    impl PublicInputs for MixerWithdrawalPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.recipient.hash()?,
                self.nullifier_hash.clone(),
                transaction_hash.clone(),
            ])
        }
    }
}

#[test]
fn mixer_withdrawal_prove_and_verify() {
    let depositor = keypair(5);
    let recipient = keypair(6);
    let address = recipient.shielded_address().expect("recipient address");
    let payer = address.solana_address().expect("payer");
    let (nullifier_secret, secret) = ([3u8; 32], [4u8; 32]);
    let (note, commitment) = commitment_utxo(&depositor, nullifier_secret, secret);

    let withdrawal = MixerWithdrawal {
        private: MixerWithdrawalPrivateInputs {
            tx_context: TxContext::new(),
            note,
            commitment,
            nullifier_secret,
            secret,
        },
        public: MixerWithdrawalPublicInputs {
            recipient: address,
            nullifier_hash: poseidon_bytes(&[nullifier_secret]),
        },
    };
    let spp_proof_inputs = withdrawal
        .create_proof_inputs_and_encrypt(&recipient, payer, u64::MAX)
        .expect("mixer withdrawal proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect::<Vec<_>>(),
        vec![(Some(address), Mint::SOL, DENOMINATION)]
    );

    let prover =
        Groth16Prover::<MixerWithdrawal>::new_with_test_setup().expect("mixer withdrawal setup");
    let result = prove(&prover, &withdrawal, "mixer withdrawal proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
