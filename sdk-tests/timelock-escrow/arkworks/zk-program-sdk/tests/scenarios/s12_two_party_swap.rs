use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input, USDC},
};

#[derive(Clone)]
struct Swap {
    private: SwapPrivateInputs,
    public: SwapPublicInputs,
}

#[derive(Clone)]
struct SwapPrivateInputs {
    tx_context: TxContext,
    party_a: ShieldedAddress,
    party_b: ShieldedAddress,
    token_utxos_asset_a: [WalletUtxo; 1],
    token_utxos_asset_b: [WalletUtxo; 1],
}

#[derive(Clone)]
struct SwapPublicInputs {
    mint_a: Mint,
    amount_a: u64,
    mint_b: Mint,
    amount_b: u64,
}

impl ProofInput for Swap {
    type Circuit = circuit::Swap;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Swap, RelationError> {
        let private = &self.private;
        let public = &self.public;
        Ok(circuit::Swap {
            private: circuit::SwapPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                party_a: private.party_a.instantiate(allocator)?,
                party_b: private.party_b.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                token_utxos_asset_b: private.token_utxos_asset_b.instantiate(allocator)?,
            },
            public: circuit::SwapPublicInputs {
                mint_a: public.mint_a.instantiate(allocator)?,
                amount_a: public.amount_a.instantiate(allocator)?,
                mint_b: public.mint_b.instantiate(allocator)?,
                amount_b: public.amount_b.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for Swap {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: SwapPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                party_a: Placeholder::placeholder()?,
                party_b: Placeholder::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                token_utxos_asset_b: Placeholder::placeholder()?,
            },
            public: SwapPublicInputs {
                mint_a: Placeholder::placeholder()?,
                amount_a: Placeholder::placeholder()?,
                mint_b: Placeholder::placeholder()?,
                amount_b: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, Assert, Asset, Balance, CheckedTransaction, Circuit, CircuitVar,
            ConfidentialTransaction, Owner, PublicInputs, TokenUtxo, TxContext, Utxo,
        },
        RelationError,
    };

    pub struct Swap {
        pub private: SwapPrivateInputs,
        pub public: SwapPublicInputs,
    }

    pub struct SwapPrivateInputs {
        pub tx_context: TxContext,
        pub party_a: Owner,
        pub party_b: Owner,
        pub token_utxos_asset_a: [Utxo; 1],
        pub token_utxos_asset_b: [Utxo; 1],
    }

    pub struct SwapPublicInputs {
        pub mint_a: Asset,
        pub amount_a: CircuitVar,
        pub mint_b: Asset,
        pub amount_b: CircuitVar,
    }

    fn leg(inputs: &[Utxo; 1], owner: &Owner, mint: &Asset) -> Result<TokenUtxo<1>, RelationError> {
        let tokens = TokenUtxo::new_burn(inputs)?;
        tokens
            .owner()
            .hash()?
            .assert_equal(&owner.hash()?, "the leg belongs to another party")?;
        tokens
            .asset()
            .hash()?
            .assert_equal(&mint.hash()?, "the leg is in another mint")?;
        Ok(tokens)
    }

    impl Circuit for Swap {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let public = &self.public;
            let mut tokens_a = leg(
                &private.token_utxos_asset_a,
                &private.party_a,
                &public.mint_a,
            )?;
            let mut tokens_b = leg(
                &private.token_utxos_asset_b,
                &private.party_b,
                &public.mint_b,
            )?;
            let to_b = tokens_a.transfer(&private.party_b, &public.amount_a)?;
            let to_a = tokens_b.transfer(&private.party_a, &public.amount_b)?;

            ConfidentialTransaction::new(&private.tx_context, public)
                .with_token_utxos(tokens_a)
                .with_token_utxos(tokens_b)
                .with_output_token_utxo(to_b)
                .with_output_token_utxo(to_a)
                .check()
        }
    }

    impl PublicInputs for SwapPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.mint_a.hash()?,
                self.amount_a.clone(),
                self.mint_b.hash()?,
                self.amount_b.clone(),
                transaction_hash.clone(),
            ])
        }
    }
}

#[test]
fn two_party_swap_prove_and_verify() {
    let party_a = keypair(5);
    let party_b = keypair(6);
    let address_a = party_a.shielded_address().expect("party a address");
    let address_b = party_b.shielded_address().expect("party b address");
    let payer = address_a.solana_address().expect("payer");
    let leg_a = token_input(&party_a, Mint::SOL, 300, 0);
    let leg_b = token_input(&party_b, USDC, 90, 1);

    let swap = Swap {
        private: SwapPrivateInputs {
            tx_context: TxContext::new(),
            party_a: address_a,
            party_b: address_b,
            token_utxos_asset_a: [leg_a],
            token_utxos_asset_b: [leg_b],
        },
        public: SwapPublicInputs {
            mint_a: Mint::SOL,
            amount_a: 300,
            mint_b: USDC,
            amount_b: 90,
        },
    };
    let spp_proof_inputs = swap
        .create_proof_inputs_and_encrypt(&party_a, payer, u64::MAX)
        .expect("swap proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect::<Vec<_>>(),
        vec![
            (Some(address_b), Mint::SOL, 300),
            (Some(address_a), USDC, 90),
        ]
    );

    let prover = Groth16Prover::<Swap>::new_with_test_setup().expect("swap setup");
    let result = prove(&prover, &swap, "swap proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
