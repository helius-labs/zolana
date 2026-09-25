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
pub struct Issuer {
    pub issuer_hash: [u8; 32],
    pub issued: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct Credential {
    pub issuer_hash: [u8; 32],
    pub attribute_commitment: [u8; 32],
}

#[derive(Clone, ProofInput)]
struct CreateIssuer {
    private: CreateIssuerPrivateInputs,
    public: CreateIssuerPublicInputs,
}

#[derive(Clone, ProofInput)]
struct CreateIssuerPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
}

#[derive(Clone, ProofInput, PublicInputs)]
struct CreateIssuerPublicInputs {
    issuer: ShieldedAddress,
}

#[circuit]
impl Circuit for CreateIssuer {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut issuer = DataUtxo::<IssuerCircuit>::new_init(&self.public.issuer, &Asset::sol());
        issuer.issuer_hash = self.public.issuer.hash()?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(issuer)
            .check()
    }
}

#[test]
fn create_issuer_prove_and_verify() {
    let issuer = keypair(5);
    let address = issuer.shielded_address().expect("issuer address");
    let payer = address.solana_address().expect("payer");
    let input = token_input(&issuer, Mint::SOL, 300, 0);

    let create = CreateIssuer {
        private: CreateIssuerPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
        },
        public: CreateIssuerPublicInputs { issuer: address },
    };
    let spp_proof_inputs = create
        .create_proof_inputs_and_encrypt(&issuer, payer, u64::MAX)
        .expect("create issuer proof inputs");
    let state = Issuer {
        issuer_hash: address.owner_hash().expect("issuer hash"),
        issued: 0,
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
                Some(borsh::to_vec(&state).expect("issuer bytes")),
            ),
        ]
    );

    let prover = Groth16Prover::<CreateIssuer>::new_with_test_setup().expect("create issuer setup");
    let result = prove(&prover, &create, "create issuer proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
