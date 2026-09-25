use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    conversion::{Allocator, FromCircuit, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, ProgramOwner},
};

fn vesting_authority() -> ProgramOwner {
    ProgramOwner::new(43)
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Vesting {
    pub beneficiary_hash: [u8; 32],
    pub total: u64,
    pub claimed: u64,
    pub start: u64,
    pub end: u64,
}

impl zk_program_sdk::circuit::CircuitType for circuit::Vesting {}

impl ProofInput for Vesting {
    type Circuit = circuit::Vesting;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Vesting, RelationError> {
        Ok(circuit::Vesting {
            beneficiary_hash: self.beneficiary_hash.instantiate(allocator)?,
            total: self.total.instantiate(allocator)?,
            claimed: self.claimed.instantiate(allocator)?,
            start: self.start.instantiate(allocator)?,
            end: self.end.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Vesting {
    fn from_circuit(circuit: &circuit::Vesting) -> Result<Self, RelationError> {
        Ok(Self {
            beneficiary_hash: <[u8; 32]>::from_circuit(&circuit.beneficiary_hash)?,
            total: u64::from_circuit(&circuit.total)?,
            claimed: u64::from_circuit(&circuit.claimed)?,
            start: u64::from_circuit(&circuit.start)?,
            end: u64::from_circuit(&circuit.end)?,
        })
    }
}

impl Placeholder for Vesting {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            beneficiary_hash: Placeholder::placeholder()?,
            total: Placeholder::placeholder()?,
            claimed: Placeholder::placeholder()?,
            start: Placeholder::placeholder()?,
            end: Placeholder::placeholder()?,
        })
    }
}

#[derive(Clone)]
struct VestingClaim {
    private: VestingClaimPrivateInputs,
    public: VestingClaimPublicInputs,
}

#[derive(Clone)]
struct VestingClaimPrivateInputs {
    tx_context: TxContext,
    vesting: WalletUtxo,
    state: Vesting,
    beneficiary: ShieldedAddress,
    vesting_owner: ShieldedAddress,
    unlocked: u64,
    remainder: u64,
}

#[derive(Clone)]
struct VestingClaimPublicInputs {
    now: u64,
    start: u64,
    end: u64,
}

impl zk_program_sdk::circuit::CircuitType for circuit::VestingClaim {}

impl ProofInput for VestingClaim {
    type Circuit = circuit::VestingClaim;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::VestingClaim, RelationError> {
        let private = &self.private;
        let public = &self.public;
        Ok(circuit::VestingClaim {
            private: circuit::VestingClaimPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                vesting: private.vesting.instantiate(allocator)?,
                state: private.state.instantiate(allocator)?,
                beneficiary: private.beneficiary.instantiate(allocator)?,
                vesting_owner: private.vesting_owner.instantiate(allocator)?,
                unlocked: private.unlocked.instantiate(allocator)?,
                remainder: private.remainder.instantiate(allocator)?,
            },
            public: circuit::VestingClaimPublicInputs {
                now: public.now.instantiate(allocator)?,
                start: public.start.instantiate(allocator)?,
                end: public.end.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for VestingClaim {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: VestingClaimPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                vesting: Placeholder::placeholder()?,
                state: Placeholder::placeholder()?,
                beneficiary: Placeholder::placeholder()?,
                vesting_owner: Placeholder::placeholder()?,
                unlocked: Placeholder::placeholder()?,
                remainder: Placeholder::placeholder()?,
            },
            public: VestingClaimPublicInputs {
                now: Placeholder::placeholder()?,
                start: Placeholder::placeholder()?,
                end: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            constant, poseidon, zero, Assert, Balance, CheckedTransaction, Circuit, CircuitMarker,
            CircuitVar, ConfidentialTransaction, DataHash, DataUtxo, Owner, PublicInputs,
            TokenUtxo, TxContext, Utxo, UtxoData,
        },
        RelationError,
    };

    #[derive(Clone, Debug)]
    pub struct Vesting {
        pub beneficiary_hash: CircuitVar,
        pub total: CircuitVar,
        pub claimed: CircuitVar,
        pub start: CircuitVar,
        pub end: CircuitVar,
    }

    impl Default for Vesting {
        fn default() -> Self {
            Self {
                beneficiary_hash: zero(),
                total: zero(),
                claimed: zero(),
                start: zero(),
                end: zero(),
            }
        }
    }

    impl DataHash for Vesting {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.beneficiary_hash.clone(),
                self.total.clone(),
                self.claimed.clone(),
                self.start.clone(),
                self.end.clone(),
            ])
        }
    }

    impl UtxoData for Vesting {
        type Client = super::Vesting;
    }

    pub struct VestingClaim {
        pub private: VestingClaimPrivateInputs,
        pub public: VestingClaimPublicInputs,
    }

    pub struct VestingClaimPrivateInputs {
        pub tx_context: TxContext,
        pub vesting: Utxo,
        pub state: Vesting,
        pub beneficiary: Owner,
        pub vesting_owner: Owner,
        pub unlocked: CircuitVar,
        pub remainder: CircuitVar,
    }

    pub struct VestingClaimPublicInputs {
        pub now: CircuitVar,
        pub start: CircuitVar,
        pub end: CircuitVar,
    }

    impl Circuit for VestingClaim {
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let public = &self.public;
            let mut vesting = DataUtxo::new_burn(&private.vesting, &private.state)?;
            private.beneficiary.hash()?.assert_equal(
                &vesting.beneficiary_hash,
                "the claimant is not the beneficiary",
            )?;
            private.vesting_owner.hash()?.assert_equal(
                &vesting.owner().hash()?,
                "the vesting owner is not the pool's",
            )?;
            public
                .start
                .assert_equal(&vesting.start, "the start is not the schedule's")?;
            public
                .end
                .assert_equal(&vesting.end, "the end is not the schedule's")?;
            let elapsed = public.now.clone() - &public.start;
            elapsed.check_bits(64)?;
            (public.end.clone() - &public.now).check_bits(64)?;
            let duration = public.end.clone() - &public.start;
            (private.unlocked.clone() * &duration + &private.remainder).assert_equal(
                &(vesting.total.clone() * &elapsed),
                "the unlocked amount is not total * elapsed / duration",
            )?;
            (duration - &private.remainder - constant(1u64)).check_bits(64)?;
            let payout = private.unlocked.clone() - &vesting.claimed;
            let mut paid = TokenUtxo::new_init(&private.beneficiary, &vesting.asset());
            vesting.transfer(&mut paid, &payout)?;
            let mut next = DataUtxo::<Vesting>::new_init(&private.vesting_owner, &vesting.asset());
            vesting.transfer_all(&mut next)?;
            next.beneficiary_hash = vesting.beneficiary_hash.clone();
            next.total = vesting.total.clone();
            next.claimed = private.unlocked.clone();
            next.start = vesting.start.clone();
            next.end = vesting.end.clone();

            ConfidentialTransaction::new(&private.tx_context, public)
                .with_data_utxo(vesting)
                .with_token_utxos(paid)
                .with_data_utxo(next)
                .check()
        }
    }

    impl PublicInputs for VestingClaimPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.now.clone(),
                self.start.clone(),
                self.end.clone(),
                transaction_hash.clone(),
            ])
        }
    }
}

#[test]
fn vesting_claim_prove_and_verify() {
    let beneficiary = keypair(5);
    let address = beneficiary.shielded_address().expect("beneficiary address");
    let payer = address.solana_address().expect("payer");
    let vesting_owner = vesting_authority().address(&address);
    let state = Vesting {
        beneficiary_hash: address.owner_hash().expect("beneficiary hash"),
        total: 1_000,
        claimed: 100,
        start: 1_000,
        end: 1_700,
    };
    let vesting = vesting_authority().data_input(&address, Mint::SOL, 900, &state, 0);

    let claim = VestingClaim {
        private: VestingClaimPrivateInputs {
            tx_context: TxContext::new(),
            vesting,
            state: state.clone(),
            beneficiary: address,
            vesting_owner,
            unlocked: 428,
            remainder: 400,
        },
        public: VestingClaimPublicInputs {
            now: 1_300,
            start: 1_000,
            end: 1_700,
        },
    };
    let spp_proof_inputs = claim
        .create_proof_inputs_and_encrypt(&beneficiary, payer, u64::MAX)
        .expect("vesting claim proof inputs");
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
            (Some(address), Mint::SOL, 328, None),
            (
                Some(vesting_owner),
                Mint::SOL,
                572,
                Some(
                    borsh::to_vec(&Vesting {
                        claimed: 428,
                        ..state
                    })
                    .expect("vesting bytes")
                ),
            ),
        ]
    );

    let prover = Groth16Prover::<VestingClaim>::new_with_test_setup().expect("vesting claim setup");
    let result = prove(&prover, &claim, "vesting claim proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
