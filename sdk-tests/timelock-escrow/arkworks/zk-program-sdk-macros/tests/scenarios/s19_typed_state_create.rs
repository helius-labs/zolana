use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    circuit,
    circuit::{
        Asset, CheckedTransaction, Circuit, CircuitType, ConfidentialTransaction, DataUtxo,
        PublicInputs, TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input, USDC},
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct TypedState {
    pub amount: u64,
    pub count: u32,
    pub kind: u16,
    pub active: bool,
    pub tag: [u8; 32],
    pub owner_hash: [u8; 32],
    pub asset_hash: [u8; 32],
}

#[derive(Clone, ProofInput)]
struct TypedCreate {
    private: TypedCreatePrivateInputs,
    public: TypedCreatePublicInputs,
}

#[derive(Clone, ProofInput)]
struct TypedCreatePrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    owner: ShieldedAddress,
    mint: Mint,
    count: u32,
    kind: u16,
    active: bool,
    tag: [u8; 32],
}

#[derive(Clone, ProofInput, PublicInputs)]
struct TypedCreatePublicInputs {
    amount: u64,
}

#[circuit]
impl Circuit for TypedCreate {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut state = DataUtxo::<TypedStateCircuit>::new_init(&private.owner, &Asset::sol());
        state.amount = self.public.amount.clone();
        state.count = private.count.clone();
        state.kind = private.kind.clone();
        state.active = private.active.clone();
        state.tag = private.tag.clone();
        state.owner_hash = private.owner.hash()?;
        state.asset_hash = private.mint.hash()?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(state)
            .check()
    }
}

#[test]
fn typed_state_create_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let input = token_input(&sender, Mint::SOL, 300, 0);

    let create = TypedCreate {
        private: TypedCreatePrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            owner: address,
            mint: USDC,
            count: 7,
            kind: 2,
            active: true,
            tag: [7u8; 32],
        },
        public: TypedCreatePublicInputs { amount: 1_000 },
    };
    let spp_proof_inputs = create
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("typed create proof inputs");
    let state = TypedState {
        amount: 1_000,
        count: 7,
        kind: 2,
        active: true,
        tag: [7u8; 32],
        owner_hash: address.owner_hash().expect("owner hash"),
        asset_hash: hash_bytes(USDC.asset.as_array()).expect("asset hash"),
    };
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
            (Some(address), Mint::SOL, 300, None),
            (
                Some(address),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&state).expect("state bytes")),
            ),
        ]
    );

    let prover = Groth16Prover::<TypedCreate>::new_with_test_setup().expect("typed create setup");
    let result = prove(&prover, &create, "typed create proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
