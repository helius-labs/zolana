use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    circuit,
    circuit::{
        Balance, CheckedTransaction, Circuit, CircuitType, ConfidentialTransaction, DataUtxo,
        PublicInputs, TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input, ProgramOwner, USDC},
};

pub(crate) const ORDER_SLOT: usize = 1;

pub(crate) fn order_authority() -> ProgramOwner {
    ProgramOwner::new(41)
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct OrderTerms {
    pub maker_hash: [u8; 32],
    pub ask_asset_hash: [u8; 32],
    pub ask_amount: u64,
    pub expiry: u64,
}

#[derive(Clone, ProofInput)]
struct Make {
    private: MakePrivateInputs,
    public: MakePublicInputs,
}

#[derive(Clone, ProofInput)]
struct MakePrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
    amount: u64,
    ask_mint: Mint,
    ask_amount: u64,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct MakePublicInputs {
    order_owner: ShieldedAddress,
    expiry: u64,
}

pub(crate) fn order_utxo(
    maker: &ShieldedKeypair,
    amount: u64,
    ask_amount: u64,
    expiry: u64,
) -> (WalletUtxo, OrderTerms) {
    let address = maker.shielded_address().expect("maker address");
    let first = token_input(maker, Mint::SOL, amount, 0);
    let spp_proof_inputs = Make {
        private: MakePrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, token_input(maker, Mint::SOL, 100, 1)],
            amount,
            ask_mint: USDC,
            ask_amount,
        },
        public: MakePublicInputs {
            order_owner: order_authority().address(&address),
            expiry,
        },
    }
    .create_proof_inputs_and_encrypt(maker, address.solana_address().expect("payer"), u64::MAX)
    .expect("make proof inputs");
    let output = spp_proof_inputs
        .output_utxos
        .get(ORDER_SLOT)
        .expect("order output");
    let terms = OrderTerms::try_from_slice(output.data.utxo_data().expect("order data"))
        .expect("order terms");
    (
        order_authority().input(output, spp_proof_inputs.output_tree_id, 2),
        terms,
    )
}

#[circuit]
impl Circuit for Make {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut order =
            DataUtxo::<OrderTermsCircuit>::new_init(&self.public.order_owner, &tokens.asset());
        tokens.transfer(&mut order, &private.amount)?;
        order.maker_hash = tokens.owner().hash()?;
        order.ask_asset_hash = private.ask_mint.hash()?;
        order.ask_amount = private.ask_amount.clone();
        order.expiry = self.public.expiry.clone();

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(order)
            .check()
    }
}

#[test]
fn order_make_prove_and_verify() {
    let maker = keypair(5);
    let address = maker.shielded_address().expect("maker address");
    let payer = address.solana_address().expect("payer");
    let order_owner = order_authority().address(&address);
    let first = token_input(&maker, Mint::SOL, 600, 0);
    let second = token_input(&maker, Mint::SOL, 400, 1);

    let make = Make {
        private: MakePrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, second],
            amount: 500,
            ask_mint: USDC,
            ask_amount: 60,
        },
        public: MakePublicInputs {
            order_owner,
            expiry: 1_800_000_000,
        },
    };
    let spp_proof_inputs = make
        .create_proof_inputs_and_encrypt(&maker, payer, u64::MAX)
        .expect("make proof inputs");
    let terms = OrderTerms {
        maker_hash: address.owner_hash().expect("maker hash"),
        ask_asset_hash: hash_bytes(USDC.asset.as_array()).expect("ask asset hash"),
        ask_amount: 60,
        expiry: 1_800_000_000,
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
            (Some(address), Mint::SOL, 500, None),
            (
                Some(order_owner),
                Mint::SOL,
                500,
                Some(borsh::to_vec(&terms).expect("order terms bytes")),
            ),
        ]
    );

    let prover = Groth16Prover::<Make>::new_with_test_setup().expect("make setup");
    let result = prove(&prover, &make, "make proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
