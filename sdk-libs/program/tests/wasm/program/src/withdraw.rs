use spr_program::ZkProgramCircuit;
use spr_program::{
    circuit::{
        Assert, CheckedTransaction, Circuit, ConfidentialTransaction, DataUtxo, PublicInputs,
        TokenUtxos, UtxoTrait,
    },
    conversion::ProofInput,
    CircuitError, TxContext,
};
use spr_transaction::WalletUtxo;

use super::EscrowTerms;

#[derive(Clone, ZkProgramCircuit)]
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
    pub owner_identity: [u8; 32],
}

#[deny(clippy::disallowed_types)]
impl Circuit for WithdrawCircuit {
    type Output = CheckedTransaction;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let private = &self.private;
        let mut escrow = DataUtxo::new_mut(&private.escrow, &private.terms)?.close();
        escrow
            .amount()?
            .assert_not_zero("the escrow utxo holds nothing")?;
        escrow.creator.key().identity()?.assert_equal(
            &self.public.owner_identity,
            "the signer is not the escrow creator",
        )?;
        self.public
            .unlock
            .assert_equal(&escrow.unlock, "the unlock time is not the escrow's")?;
        let mut payout = TokenUtxos::new_init(&escrow.creator, &escrow.asset());
        escrow.transfer_all(&mut payout)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with(escrow)
            .with(payout)
            .check()
    }
}
