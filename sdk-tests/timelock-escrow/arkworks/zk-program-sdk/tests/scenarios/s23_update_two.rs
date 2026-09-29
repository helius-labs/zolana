use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError, Groth16Prover, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s22_create_and_update::{Badge, Profile},
    shared::{data_input, keypair},
};

#[derive(Clone)]
struct UpdateTwo {
    private: UpdateTwoPrivateInputs,
    public: UpdateTwoPublicInputs,
}

#[derive(Clone)]
struct UpdateTwoPrivateInputs {
    tx_context: TxContext,
    profile_utxo: WalletUtxo,
    profile: Profile,
    badge_utxo: WalletUtxo,
    badge: Badge,
}

#[derive(Clone)]
struct UpdateTwoPublicInputs {
    owner: ShieldedAddress,
}

impl zk_program_sdk::circuit::CircuitType for circuit::UpdateTwo {}

impl ProofInput for UpdateTwo {
    type Circuit = circuit::UpdateTwo;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::UpdateTwo, CircuitError> {
        let private = &self.private;
        Ok(circuit::UpdateTwo {
            private: circuit::UpdateTwoPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                profile_utxo: private.profile_utxo.instantiate(allocator)?,
                profile: private.profile.instantiate(allocator)?,
                badge_utxo: private.badge_utxo.instantiate(allocator)?,
                badge: private.badge.instantiate(allocator)?,
            },
            public: circuit::UpdateTwoPublicInputs {
                owner: self.public.owner.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for UpdateTwo {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self {
            private: UpdateTwoPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                profile_utxo: Placeholder::placeholder()?,
                profile: Placeholder::placeholder()?,
                badge_utxo: Placeholder::placeholder()?,
                badge: Placeholder::placeholder()?,
            },
            public: UpdateTwoPublicInputs {
                owner: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, Assert, CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction,
            DataUtxo, Owner, PublicInputs, TxContext, Uint, Utxo, UtxoTrait,
        },
        CircuitError,
    };

    use crate::s22_create_and_update::circuit::{Badge, Profile};

    pub struct UpdateTwo {
        pub private: UpdateTwoPrivateInputs,
        pub public: UpdateTwoPublicInputs,
    }

    pub struct UpdateTwoPrivateInputs {
        pub tx_context: TxContext,
        pub profile_utxo: Utxo,
        pub profile: Profile,
        pub badge_utxo: Utxo,
        pub badge: Badge,
    }

    pub struct UpdateTwoPublicInputs {
        pub owner: Owner,
    }

    impl Circuit for UpdateTwo {
        fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
            let private = &self.private;
            let owner = self.public.owner.hash()?;
            let mut profile = DataUtxo::new_mut(&private.profile_utxo, &private.profile)?;
            profile
                .owner()
                .hash()?
                .assert_equal(&owner, "the profile has another owner")?;
            profile.score = profile
                .score
                .checked_add(&Uint::<64>::constant(10)?, "the score overflows")?;
            let mut badge = DataUtxo::new_mut(&private.badge_utxo, &private.badge)?;
            badge
                .owner()
                .hash()?
                .assert_equal(&owner, "the badge has another owner")?;
            badge.level = badge
                .level
                .checked_add(&Uint::<16>::constant(1)?, "the level overflows")?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_data_utxo(profile)
                .with_data_utxo(badge)
                .check()
        }
    }

    impl PublicInputs for UpdateTwoPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, CircuitError> {
            poseidon(&[self.owner.hash()?, transaction_hash.clone()])
        }
    }
}

#[test]
fn update_two_prove_and_verify() {
    let owner = keypair(5);
    let address = owner.shielded_address().expect("owner address");
    let payer = address.solana_address().expect("payer");
    let profile = Profile { score: 41 };
    let badge = Badge { level: 2 };
    let profile_utxo = data_input(&owner, 0, &profile, 0);
    let badge_utxo = data_input(&owner, 0, &badge, 1);

    let update_two = UpdateTwo {
        private: UpdateTwoPrivateInputs {
            tx_context: TxContext::new(),
            profile_utxo,
            profile,
            badge_utxo,
            badge,
        },
        public: UpdateTwoPublicInputs { owner: address },
    };
    let spp_proof_inputs = update_two
        .create_proof_inputs_and_encrypt(&address, payer)
        .expect("update two proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (
                output.owner_address,
                output.asset,
                output.amount,
                output.data.utxo_data().map(<[u8]>::to_vec),
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                Some(address),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&Profile { score: 51 }).expect("profile bytes")),
            ),
            (
                Some(address),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&Badge { level: 3 }).expect("badge bytes")),
            ),
        ]
    );

    let prover = Groth16Prover::<UpdateTwo>::new_with_test_setup().expect("update two setup");
    let result = prove(&prover, &update_two, "update two proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
