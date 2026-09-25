use zk_program_sdk::{
    circuit,
    circuit::{
        Assert, Balance, CheckedTransaction, Circuit, ConfidentialTransaction, Owner, PublicInputs,
        TokenUtxo, Utxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input, USDC},
};

#[derive(Clone, ProofInput)]
struct Swap {
    private: SwapPrivateInputs,
    public: SwapPublicInputs,
}

#[derive(Clone, ProofInput)]
struct SwapPrivateInputs {
    tx_context: TxContext,
    party_a: ShieldedAddress,
    party_b: ShieldedAddress,
    token_utxos_asset_a: [WalletUtxo; 1],
    token_utxos_asset_b: [WalletUtxo; 1],
}

#[derive(Clone, ProofInput, PublicInputs)]
struct SwapPublicInputs {
    mint_a: Mint,
    amount_a: u64,
    mint_b: Mint,
    amount_b: u64,
}

#[circuit]
fn leg(inputs: &[Utxo; 1], owner: &Owner) -> Result<TokenUtxo, RelationError> {
    let tokens = TokenUtxo::new_burn(inputs)?;
    tokens
        .owner()
        .hash()?
        .assert_equal(&owner.hash()?, "the leg belongs to another party")?;
    Ok(tokens)
}

#[circuit]
impl Circuit for Swap {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let public = &self.public;
        let mut tokens_a = leg(&private.token_utxos_asset_a, &private.party_a)?;
        let mut tokens_b = leg(&private.token_utxos_asset_b, &private.party_b)?;
        let mut to_b = TokenUtxo::new_init(&private.party_b, &public.mint_a);
        tokens_a.transfer(&mut to_b, &public.amount_a)?;
        let mut to_a = TokenUtxo::new_init(&private.party_a, &public.mint_b);
        tokens_b.transfer(&mut to_a, &public.amount_b)?;

        ConfidentialTransaction::new(&private.tx_context, public)
            .with_token_utxos(tokens_a)
            .with_token_utxos(tokens_b)
            .with_token_utxos(to_b)
            .with_token_utxos(to_a)
            .check()
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
