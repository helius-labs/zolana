use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::right_align;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s39_airdrop_pool::{airdrop_authority, pool_utxo, Pool},
    shared::{keypair, poseidon_bytes, MerklePath, MerkleTree},
};

#[derive(Clone)]
struct Claim {
    private: ClaimPrivateInputs,
    public: ClaimPublicInputs,
}

#[derive(Clone)]
struct ClaimPrivateInputs {
    tx_context: TxContext,
    pool: WalletUtxo,
    state: Pool,
    pool_owner: ShieldedAddress,
    secret_key: [u8; 32],
    path: MerklePath,
}

#[derive(Clone)]
struct ClaimPublicInputs {
    root: [u8; 32],
    airdrop_id: u64,
    nullifier: [u8; 32],
    recipient: ShieldedAddress,
    amount: u64,
}

impl zk_program_sdk::circuit::CircuitType for circuit::Claim {}

impl ProofInput for Claim {
    type Circuit = circuit::Claim;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Claim, RelationError> {
        let private = &self.private;
        let public = &self.public;
        Ok(circuit::Claim {
            private: circuit::ClaimPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                pool: private.pool.instantiate(allocator)?,
                state: private.state.instantiate(allocator)?,
                pool_owner: private.pool_owner.instantiate(allocator)?,
                secret_key: private.secret_key.instantiate(allocator)?,
                path: private.path.instantiate(allocator)?,
            },
            public: circuit::ClaimPublicInputs {
                root: public.root.instantiate(allocator)?,
                airdrop_id: public.airdrop_id.instantiate(allocator)?,
                nullifier: public.nullifier.instantiate(allocator)?,
                recipient: public.recipient.instantiate(allocator)?,
                amount: public.amount.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for Claim {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: ClaimPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                pool: Placeholder::placeholder()?,
                state: Placeholder::placeholder()?,
                pool_owner: Placeholder::placeholder()?,
                secret_key: Placeholder::placeholder()?,
                path: Placeholder::placeholder()?,
            },
            public: ClaimPublicInputs {
                root: Placeholder::placeholder()?,
                airdrop_id: Placeholder::placeholder()?,
                nullifier: Placeholder::placeholder()?,
                recipient: Placeholder::placeholder()?,
                amount: Placeholder::placeholder()?,
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

    use crate::{s39_airdrop_pool::circuit::Pool, shared::CircuitMerklePath};

    pub struct Claim {
        pub private: ClaimPrivateInputs,
        pub public: ClaimPublicInputs,
    }

    pub struct ClaimPrivateInputs {
        pub tx_context: TxContext,
        pub pool: Utxo,
        pub state: Pool,
        pub pool_owner: Owner,
        pub secret_key: CircuitVar,
        pub path: CircuitMerklePath,
    }

    pub struct ClaimPublicInputs {
        pub root: CircuitVar,
        pub airdrop_id: CircuitVar,
        pub nullifier: CircuitVar,
        pub recipient: Owner,
        pub amount: CircuitVar,
    }

    impl Circuit for Claim {
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let public = &self.public;
            let mut pool = DataUtxo::new_burn(&private.pool, &private.state)?;
            private
                .pool_owner
                .hash()?
                .assert_equal(&pool.owner().hash()?, "the pool owner is not the pool's")?;
            pool.root
                .assert_equal(&public.root, "the root is not the pool's")?;
            pool.airdrop_id
                .assert_equal(&public.airdrop_id, "the airdrop is not the pool's")?;
            let leaf = poseidon(&[
                poseidon(std::slice::from_ref(&private.secret_key))?,
                public.amount.clone(),
            ])?;
            private
                .path
                .root(&leaf)?
                .assert_equal(&public.root, "the claim is not in the airdrop")?;
            poseidon(&[public.airdrop_id.clone(), private.secret_key.clone()])?
                .assert_equal(&public.nullifier, "the nullifier is not the claim's")?;
            let mut claim = TokenUtxo::new_init(&public.recipient, &pool.asset());
            pool.transfer(&mut claim, &public.amount)?;
            let mut next_pool = DataUtxo::<Pool>::new_init(&private.pool_owner, &pool.asset());
            pool.transfer_all(&mut next_pool)?;
            next_pool.root = pool.root.clone();
            next_pool.airdrop_id = pool.airdrop_id.clone();

            ConfidentialTransaction::new(&private.tx_context, public)
                .with_data_utxo(pool)
                .with_token_utxos(claim)
                .with_data_utxo(next_pool)
                .check()
        }
    }

    impl PublicInputs for ClaimPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.root.clone(),
                self.airdrop_id.clone(),
                self.nullifier.clone(),
                self.recipient.hash()?,
                self.amount.clone(),
                transaction_hash.clone(),
            ])
        }
    }
}

fn eligibility_leaf(secret_key: [u8; 32], amount: u64) -> [u8; 32] {
    poseidon_bytes(&[
        poseidon_bytes(&[secret_key]),
        right_align(&amount.to_be_bytes()),
    ])
}

#[test]
fn airdrop_claim_prove_and_verify() {
    let funder = keypair(5);
    let funder_address = funder.shielded_address().expect("funder address");
    let claimant = keypair(6);
    let address = claimant.shielded_address().expect("claimant address");
    let payer = address.solana_address().expect("payer");
    let secret_key = [4u8; 32];
    let eligibility = MerkleTree::new(&[
        eligibility_leaf([1u8; 32], 100),
        eligibility_leaf(secret_key, 250),
        eligibility_leaf([2u8; 32], 50),
    ]);
    let (pool, state) = pool_utxo(&funder, 600, eligibility.root(), 12);
    let pool_owner = airdrop_authority().address(&funder_address);

    let claim = Claim {
        private: ClaimPrivateInputs {
            tx_context: TxContext::new(),
            pool,
            state: state.clone(),
            pool_owner,
            secret_key,
            path: eligibility.path(1),
        },
        public: ClaimPublicInputs {
            root: eligibility.root(),
            airdrop_id: 12,
            nullifier: poseidon_bytes(&[right_align(&12u64.to_be_bytes()), secret_key]),
            recipient: address,
            amount: 250,
        },
    };
    let spp_proof_inputs = claim
        .create_proof_inputs_and_encrypt(&claimant, payer, u64::MAX)
        .expect("claim proof inputs");
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
            (Some(address), Mint::SOL, 250, None),
            (
                Some(pool_owner),
                Mint::SOL,
                350,
                Some(borsh::to_vec(&state).expect("pool bytes")),
            ),
        ]
    );

    let prover = Groth16Prover::<Claim>::new_with_test_setup().expect("claim setup");
    let result = prove(&prover, &claim, "claim proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
