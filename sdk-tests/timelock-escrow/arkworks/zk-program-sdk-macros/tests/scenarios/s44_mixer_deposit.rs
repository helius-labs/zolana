use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    circuit,
    circuit::{
        poseidon, Balance, CheckedTransaction, Circuit, CircuitType, ConfidentialTransaction,
        DataUtxo, PublicInputs, TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, poseidon_bytes, token_input, ProgramOwner},
};

pub(crate) const NOTE_SLOT: usize = 1;
pub(crate) const DENOMINATION: u64 = 100;

pub(crate) fn mixer_authority() -> ProgramOwner {
    ProgramOwner::new(45)
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct MixerCommitment {
    pub commitment: [u8; 32],
}

#[derive(Clone, ProofInput)]
struct MixerDeposit {
    private: MixerDepositPrivateInputs,
    public: MixerDepositPublicInputs,
}

#[derive(Clone, ProofInput)]
struct MixerDepositPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    mixer: ShieldedAddress,
    nullifier_secret: [u8; 32],
    secret: [u8; 32],
}

#[derive(Clone, ProofInput, PublicInputs)]
struct MixerDepositPublicInputs {
    denomination: u64,
}

pub(crate) fn commitment_utxo(
    depositor: &ShieldedKeypair,
    nullifier_secret: [u8; 32],
    secret: [u8; 32],
) -> (WalletUtxo, MixerCommitment) {
    let address = depositor.shielded_address().expect("depositor address");
    let input = token_input(depositor, Mint::SOL, 300, 0);
    let spp_proof_inputs = MixerDeposit {
        private: MixerDepositPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            mixer: mixer_authority().address(&address),
            nullifier_secret,
            secret,
        },
        public: MixerDepositPublicInputs {
            denomination: DENOMINATION,
        },
    }
    .create_proof_inputs_and_encrypt(
        depositor,
        address.solana_address().expect("payer"),
        u64::MAX,
    )
    .expect("mixer deposit proof inputs");
    let output = spp_proof_inputs
        .output_utxos
        .get(NOTE_SLOT)
        .expect("commitment output");
    let commitment =
        MixerCommitment::try_from_slice(output.data.utxo_data().expect("commitment data"))
            .expect("commitment state");
    (
        mixer_authority().input(output, spp_proof_inputs.output_tree_id, 2),
        commitment,
    )
}

#[circuit]
impl Circuit for MixerDeposit {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut note =
            DataUtxo::<MixerCommitmentCircuit>::new_init(&private.mixer, &tokens.asset());
        tokens.transfer(&mut note, &self.public.denomination)?;
        note.commitment = poseidon(&[private.nullifier_secret.clone(), private.secret.clone()])?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(note)
            .check()
    }
}

#[test]
fn mixer_deposit_prove_and_verify() {
    let depositor = keypair(5);
    let address = depositor.shielded_address().expect("depositor address");
    let payer = address.solana_address().expect("payer");
    let mixer = mixer_authority().address(&address);
    let input = token_input(&depositor, Mint::SOL, 300, 0);
    let (nullifier_secret, secret) = ([3u8; 32], [4u8; 32]);

    let deposit = MixerDeposit {
        private: MixerDepositPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [input],
            mixer,
            nullifier_secret,
            secret,
        },
        public: MixerDepositPublicInputs {
            denomination: DENOMINATION,
        },
    };
    let spp_proof_inputs = deposit
        .create_proof_inputs_and_encrypt(&depositor, payer, u64::MAX)
        .expect("mixer deposit proof inputs");
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
            (Some(address), Mint::SOL, 200, None),
            (
                Some(mixer),
                Mint::SOL,
                DENOMINATION,
                Some(
                    borsh::to_vec(&MixerCommitment {
                        commitment: poseidon_bytes(&[nullifier_secret, secret]),
                    })
                    .expect("commitment bytes")
                ),
            ),
        ]
    );

    let prover = Groth16Prover::<MixerDeposit>::new_with_test_setup().expect("mixer deposit setup");
    let result = prove(&prover, &deposit, "mixer deposit proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
