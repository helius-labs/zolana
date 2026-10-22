use zolana_interface::shape::Shape;
use zolana_keypair::ShieldedAddress;
use zolana_program::{
    circuit::{
        CheckedTransaction, Circuit, ConfidentialTransaction, DataUtxo, PublicInputs, TokenUtxos,
    },
    conversion::ProofInput,
    CircuitError, Groth16Prover, TxContext, ZkProgramCircuit,
};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s22_create_and_update::{Badge, Profile},
    shared::{dummy, keypair, token_input},
};

#[derive(Clone, ZkProgramCircuit)]
pub struct CreateTwo {
    private: CreateTwoPrivateInputs,
    public: CreateTwoPublicInputs,
}

#[derive(Clone, ProofInput)]
struct CreateTwoPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
    score: u64,
    level: u16,
}

#[derive(Clone, PublicInputs)]
struct CreateTwoPublicInputs {
    owner: ShieldedAddress,
}

use crate::s22_create_and_update::{BadgeCircuit, ProfileCircuit};

#[deny(clippy::disallowed_types)]
impl Circuit for <CreateTwo as ProofInput>::Circuit {
    type Output = CheckedTransaction;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let private = &self.private;
        let tokens = TokenUtxos::new_mut(&private.token_utxos_asset_a)?;
        let mut profile = DataUtxo::<ProfileCircuit>::new_init(&self.public.owner);
        profile.score = private.score.clone();
        let mut badge = DataUtxo::<BadgeCircuit>::new_init(&self.public.owner);
        badge.level = private.level.clone();

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with(tokens)
            .with(profile)
            .with(badge)
            .check()
    }
}

#[test]
fn create_two_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let input = token_input(&sender, Mint::SOL, 300, 0);

    let create_two = CreateTwo {
        private: CreateTwoPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input, dummy()],
            score: 5,
            level: 1,
        },
        public: CreateTwoPublicInputs { owner: address },
    };
    let spp_proof_inputs = create_two
        .create_proof_inputs_and_encrypt_with_keys(&sender, payer, u64::MAX)
        .expect("create two proof inputs");
    assert_eq!(
        (
            spp_proof_inputs.check_shape().expect("create two shape"),
            spp_proof_inputs
                .input_utxos
                .iter()
                .map(|input| input.is_dummy())
                .collect::<Vec<_>>(),
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
        ),
        (
            Shape::IN1_OUT4,
            vec![false],
            vec![
                (Some(address), Mint::SOL, 300, None),
                (
                    Some(address),
                    Mint::SOL,
                    0,
                    Some(borsh::to_vec(&Profile { score: 5 }).expect("profile bytes")),
                ),
                (
                    Some(address),
                    Mint::SOL,
                    0,
                    Some(borsh::to_vec(&Badge { level: 1 }).expect("badge bytes")),
                ),
                (None, Mint::SOL, 0, None),
            ],
        )
    );

    let prover = Groth16Prover::<CreateTwo>::new_with_test_setup().expect("create two setup");
    let result = prove(&prover, &create_two, "create two proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
