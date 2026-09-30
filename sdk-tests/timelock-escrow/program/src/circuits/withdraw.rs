use zolana_program::{
    circuit::{
        Assert, CheckedTransaction, Circuit, ConfidentialTransaction, DataUtxo, PublicInputs,
        TokenUtxos, UtxoTrait,
    },
    conversion::ProofInput,
    CircuitError, TxContext,
};
use zolana_transaction::WalletUtxo;

use super::EscrowTerms;

#[derive(Clone, ProofInput)]
pub struct Withdraw {
    pub private: WithdrawPrivateInputs,
    pub public: WithdrawPublicInputs,
}

#[derive(Clone, ProofInput)]
pub struct WithdrawPrivateInputs {
    pub tx_context: TxContext,
    pub escrow: WalletUtxo,
    pub terms: EscrowTerms,
}

#[derive(Clone, PublicInputs)]
pub struct WithdrawPublicInputs {
    pub unlock: u64,
    pub creator_identity: [u8; 32],
}

impl Circuit for WithdrawCircuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        let mut escrow = DataUtxo::new_close(&private.escrow, &private.terms)?;
        escrow
            .amount()?
            .assert_not_zero("the escrow utxo holds nothing")?;
        escrow.creator.key().identity()?.assert_equal(
            &self.public.creator_identity,
            "the signer is not the escrow creator",
        )?;
        self.public
            .unlock
            .assert_equal(&escrow.unlock, "the unlock time is not the escrow's")?;
        let mut payout = TokenUtxos::new_init(&escrow.creator, &escrow.asset());
        escrow.transfer_all(&mut payout)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_data_utxo(escrow)
            .with_token_utxos(payout)
            .check()
    }
}
