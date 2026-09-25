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
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input},
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct Limits {
    pub daily: u64,
    pub weekly: u64,
    pub per_transfer: u64,
    pub frozen: bool,
    pub tier: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct Portfolio {
    pub owner_hash: [u8; 32],
    pub nonce: u32,
    pub limits: Limits,
    pub balances: [u64; 4],
    pub labels: [u16; 2],
}

#[derive(Clone, ProofInput)]
struct PortfolioCreate {
    private: PortfolioCreatePrivateInputs,
    public: PortfolioCreatePublicInputs,
}

#[derive(Clone, ProofInput)]
struct PortfolioCreatePrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    nonce: u32,
    limits: Limits,
    balances: [u64; 4],
    labels: [u16; 2],
}

#[derive(Clone, ProofInput, PublicInputs)]
struct PortfolioCreatePublicInputs {
    owner: ShieldedAddress,
}

#[circuit]
impl Circuit for PortfolioCreate {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut portfolio =
            DataUtxo::<PortfolioCircuit>::new_init(&self.public.owner, &Asset::sol());
        portfolio.owner_hash = self.public.owner.hash()?;
        portfolio.nonce = private.nonce.clone();
        portfolio.limits = private.limits.clone();
        portfolio.balances = private.balances.clone();
        portfolio.labels = private.labels.clone();

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(portfolio)
            .check()
    }
}

#[test]
fn nested_array_state_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let owner = keypair(6).shielded_address().expect("owner address");
    let input = token_input(&sender, Mint::SOL, 300, 0);
    let limits = Limits {
        daily: 1_000,
        weekly: 5_000,
        per_transfer: 250,
        frozen: false,
        tier: 3,
    };

    let create = PortfolioCreate {
        private: PortfolioCreatePrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            nonce: 1,
            limits: limits.clone(),
            balances: [10, 20, 30, 40],
            labels: [7, 8],
        },
        public: PortfolioCreatePublicInputs { owner },
    };
    let spp_proof_inputs = create
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("portfolio create proof inputs");
    let portfolio = Portfolio {
        owner_hash: owner.owner_hash().expect("owner hash"),
        nonce: 1,
        limits,
        balances: [10, 20, 30, 40],
        labels: [7, 8],
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
                Some(owner),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&portfolio).expect("portfolio bytes")),
            ),
        ]
    );

    let prover =
        Groth16Prover::<PortfolioCreate>::new_with_test_setup().expect("portfolio create setup");
    let result = prove(&prover, &create, "portfolio create proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
