use zk_program_sdk::{
    circuit,
    circuit::{
        zero, Assert, Balance, CheckedTransaction, Circuit, ConfidentialTransaction, DataUtxo,
        PublicInputs, TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s27_escrow::{escrow_utxo, EscrowTerms},
    shared::keypair,
};

#[derive(Clone, ProofInput)]
struct SplitWithdraw {
    private: SplitWithdrawPrivateInputs,
    public: SplitWithdrawPublicInputs,
}

#[derive(Clone, ProofInput)]
struct SplitWithdrawPrivateInputs {
    tx_context: TxContext,
    escrow: WalletUtxo,
    terms: EscrowTerms,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct SplitWithdrawPublicInputs {
    unlock: u64,
    owner_identity: [u8; 32],
    fee_recipient: ShieldedAddress,
    fee: u64,
}

#[circuit]
impl Circuit for SplitWithdraw {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let public = &self.public;
        let mut escrow = DataUtxo::new_burn(&private.escrow, &private.terms)?;
        escrow
            .balance()
            .assert_not_equal(&zero(), "the escrow utxo holds nothing")?;
        escrow.creator.key().identity()?.assert_equal(
            &public.owner_identity,
            "the signer is not the escrow creator",
        )?;
        public
            .unlock
            .assert_equal(&escrow.unlock, "the unlock time is not the escrow's")?;
        let mut fee = TokenUtxo::new_init(&public.fee_recipient, &escrow.asset());
        escrow.transfer(&mut fee, &public.fee)?;
        let mut payout = TokenUtxo::new_init(&escrow.creator, &escrow.asset());
        escrow.transfer_all(&mut payout)?;

        ConfidentialTransaction::new(&private.tx_context, public)
            .with_data_utxo(escrow)
            .with_token_utxos(payout)
            .with_token_utxos(fee)
            .check()
    }
}

#[test]
fn split_withdrawal_prove_and_verify() {
    let creator = keypair(5);
    let address = creator.shielded_address().expect("creator address");
    let payer = address.solana_address().expect("payer");
    let fee_recipient = keypair(6)
        .shielded_address()
        .expect("fee recipient address");
    let (escrow, terms) = escrow_utxo(&creator, Mint::SOL, 250, 1_700_000_000);

    let withdraw = SplitWithdraw {
        private: SplitWithdrawPrivateInputs {
            tx_context: TxContext::new(),
            escrow,
            terms,
        },
        public: SplitWithdrawPublicInputs {
            unlock: 1_700_000_000,
            owner_identity: solana_owner_identity(payer.as_array()).expect("owner identity"),
            fee_recipient,
            fee: 10,
        },
    };
    let spp_proof_inputs = withdraw
        .create_proof_inputs_and_encrypt(&creator, payer, u64::MAX)
        .expect("split withdraw proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect::<Vec<_>>(),
        vec![
            (Some(address), Mint::SOL, 240),
            (Some(fee_recipient), Mint::SOL, 10),
        ]
    );

    let prover =
        Groth16Prover::<SplitWithdraw>::new_with_test_setup().expect("split withdraw setup");
    let result = prove(&prover, &withdraw, "split withdraw proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
