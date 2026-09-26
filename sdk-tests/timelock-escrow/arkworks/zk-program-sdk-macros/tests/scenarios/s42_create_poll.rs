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
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input, ProgramOwner},
};

pub(crate) const POLL_SLOT: usize = 1;

pub(crate) fn poll_authority() -> ProgramOwner {
    ProgramOwner::new(44)
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct Poll {
    pub poll_id: u64,
    pub root: [u8; 32],
    pub tally: [u64; 3],
}

#[derive(Clone, ProofInput)]
struct CreatePoll {
    private: CreatePollPrivateInputs,
    public: CreatePollPublicInputs,
}

#[derive(Clone, ProofInput)]
struct CreatePollPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    poll_owner: ShieldedAddress,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct CreatePollPublicInputs {
    poll_id: u64,
    root: [u8; 32],
}

pub(crate) fn poll_utxo(
    creator: &ShieldedKeypair,
    poll_id: u64,
    root: [u8; 32],
) -> (WalletUtxo, Poll) {
    let address = creator.shielded_address().expect("creator address");
    let input = token_input(creator, Mint::SOL, 300, 0);
    let spp_proof_inputs = CreatePoll {
        private: CreatePollPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            poll_owner: poll_authority().address(&address),
        },
        public: CreatePollPublicInputs { poll_id, root },
    }
    .create_proof_inputs_and_encrypt(creator, address.solana_address().expect("payer"), u64::MAX)
    .expect("create poll proof inputs");
    let output = spp_proof_inputs
        .output_utxos
        .get(POLL_SLOT)
        .expect("poll output");
    let poll =
        Poll::try_from_slice(output.data.utxo_data().expect("poll data")).expect("poll state");
    (
        poll_authority().input(output, spp_proof_inputs.output_tree_id, 2),
        poll,
    )
}

#[circuit]
impl Circuit for CreatePoll {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut poll = DataUtxo::<PollCircuit>::new_init(&private.poll_owner, &Asset::sol());
        poll.poll_id = self.public.poll_id.clone();
        poll.root = self.public.root.clone();

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(poll)
            .check()
    }
}

#[test]
fn create_poll_prove_and_verify() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let payer = address.solana_address().expect("payer");
    let poll_owner = poll_authority().address(&address);
    let input = token_input(&creator, Mint::SOL, 300, 0);
    let root = [2u8; 32];

    let create = CreatePoll {
        private: CreatePollPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            poll_owner,
        },
        public: CreatePollPublicInputs { poll_id: 3, root },
    };
    let spp_proof_inputs = create
        .create_proof_inputs_and_encrypt(&creator, payer, u64::MAX)
        .expect("create poll proof inputs");
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
                Some(poll_owner),
                Mint::SOL,
                0,
                Some(
                    borsh::to_vec(&Poll {
                        poll_id: 3,
                        root,
                        tally: [0; 3],
                    })
                    .expect("poll bytes")
                ),
            ),
        ]
    );

    let prover = Groth16Prover::<CreatePoll>::new_with_test_setup().expect("create poll setup");
    let result = prove(&prover, &create, "create poll proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
