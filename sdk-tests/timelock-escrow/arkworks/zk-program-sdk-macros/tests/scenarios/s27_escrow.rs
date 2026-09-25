use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    circuit,
    circuit::{
        zero, Assert, Balance, CheckedTransaction, Circuit, CircuitType, ConfidentialTransaction,
        DataUtxo, PublicInputs, TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, Owner, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input, ProgramOwner},
};

pub(crate) const ESCROW_SLOT: usize = 1;

pub(crate) fn escrow_authority() -> ProgramOwner {
    ProgramOwner::new(40)
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct EscrowTerms {
    pub creator: Owner,
    pub unlock: u64,
}

#[derive(Clone, ProofInput)]
pub(crate) struct Escrow {
    pub(crate) private: EscrowPrivateInputs,
    pub(crate) public: EscrowPublicInputs,
}

#[derive(Clone, ProofInput)]
pub(crate) struct EscrowPrivateInputs {
    pub(crate) tx_context: TxContext,
    pub(crate) token_utxos_asset_a: [WalletUtxo; 2],
    pub(crate) unlock: u64,
    pub(crate) amount: u64,
}

#[derive(Clone, ProofInput, PublicInputs)]
pub(crate) struct EscrowPublicInputs {
    pub(crate) escrow_owner: ShieldedAddress,
}

pub(crate) fn escrow_utxo(
    creator: &ShieldedKeypair,
    mint: Mint,
    amount: u64,
    unlock: u64,
) -> (WalletUtxo, EscrowTerms) {
    let address = creator.shielded_address().expect("creator address");
    let first = token_input(creator, mint, amount, 0);
    let spp_proof_inputs = Escrow {
        private: EscrowPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, token_input(creator, mint, 100, 1)],
            unlock,
            amount,
        },
        public: EscrowPublicInputs {
            escrow_owner: escrow_authority().address(&address),
        },
    }
    .create_proof_inputs_and_encrypt(creator, address.solana_address().expect("payer"), u64::MAX)
    .expect("escrow proof inputs");
    let output = spp_proof_inputs
        .output_utxos
        .get(ESCROW_SLOT)
        .expect("escrow output");
    let terms = EscrowTerms::try_from_slice(output.data.utxo_data().expect("escrow data"))
        .expect("escrow terms");
    (
        escrow_authority().input(output, spp_proof_inputs.output_tree_id, 2),
        terms,
    )
}

#[circuit]
impl Circuit for Escrow {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        private
            .amount
            .assert_not_equal(&zero(), "the escrow locks nothing")?;
        let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut escrow =
            DataUtxo::<EscrowTermsCircuit>::new_init(&self.public.escrow_owner, &tokens.asset());
        tokens.transfer(&mut escrow, &private.amount)?;
        escrow.creator = tokens.owner();
        escrow.unlock = private.unlock.clone();

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(escrow)
            .check()
    }
}

#[test]
fn escrow_prove_and_verify() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let payer = address.solana_address().expect("payer");
    let escrow_owner = escrow_authority().address(&address);
    let first = token_input(&creator, Mint::SOL, 600, 0);
    let second = token_input(&creator, Mint::SOL, 400, 1);

    let escrow = Escrow {
        private: EscrowPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, second],
            unlock: 1_700_000_000,
            amount: 250,
        },
        public: EscrowPublicInputs { escrow_owner },
    };
    let spp_proof_inputs = escrow
        .create_proof_inputs_and_encrypt(&creator, payer, u64::MAX)
        .expect("escrow proof inputs");
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
            (Some(address), Mint::SOL, 750, None),
            (
                Some(escrow_owner),
                Mint::SOL,
                250,
                Some(
                    borsh::to_vec(&EscrowTerms {
                        creator: Owner::try_from(&address).expect("creator owner"),
                        unlock: 1_700_000_000,
                    })
                    .expect("escrow terms bytes")
                ),
            ),
        ]
    );

    let prover = Groth16Prover::<Escrow>::new_with_test_setup().expect("escrow setup");
    let result = prove(&prover, &escrow, "escrow proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
