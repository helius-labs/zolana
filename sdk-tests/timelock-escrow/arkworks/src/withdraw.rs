use circuit_lib::{
    poseidon, zero, Allocator, Assert, Circuit, CircuitVar, ConfidentialTransaction, DataUtxo,
    ProofInput, PublicHash, PublicInputs, RelationError, TxContext, Utxo, U64,
};
use timelock_escrow_program::instructions::withdraw::{N_INPUTS, N_OUTPUTS};

use crate::EscrowTerms;

#[derive(Clone, Debug)]
pub struct Withdraw {
    pub private: WithdrawPrivateInputs,
    pub public: WithdrawPublicInputs,
    pub public_hash: PublicHash,
}

#[derive(Clone, Debug)]
pub struct WithdrawPrivateInputs {
    pub tx_context: TxContext,
    pub escrow: Utxo,
    pub terms: EscrowTerms,
    pub creator_nullifier_pk: CircuitVar,
}

#[derive(Clone, Debug)]
pub struct WithdrawPublicInputs {
    pub unlock: U64,
    pub owner_identity: CircuitVar,
}

pub struct WithdrawCircuit {
    pub private: WithdrawPrivateInputs,
    pub public: WithdrawPublicInputsCircuit,
    pub public_hash: CircuitVar,
}

pub struct WithdrawPublicInputsCircuit {
    pub unlock: CircuitVar,
    pub owner_identity: CircuitVar,
}

impl Circuit for WithdrawCircuit {
    fn circuit(&self) -> Result<CircuitVar, RelationError> {
        let private = &self.private;
        let mut escrow = DataUtxo::new_burn(&private.escrow, private.terms.clone())?;
        escrow
            .amount()
            .assert_not_equal(&zero(), "the escrow utxo holds nothing")?;
        poseidon(&[
            self.public.owner_identity.clone(),
            private.creator_nullifier_pk.clone(),
        ])?
        .assert_equal(&escrow.creator, "the signer is not the escrow creator")?;
        self.public
            .unlock
            .assert_equal(&escrow.unlock, "the unlock time is not the escrow's")?;
        let (creator, amount) = (escrow.creator.clone(), escrow.amount().clone());
        let payout = escrow.transfer(&creator, amount)?;

        ConfidentialTransaction::<_, N_INPUTS, N_OUTPUTS>::new(&private.tx_context, &self.public)
            .with_data_utxo(escrow)
            .with_output_token_utxo(payout)
            .check()
    }

    fn public_hash(&self) -> &CircuitVar {
        &self.public_hash
    }
}

impl PublicInputs for WithdrawPublicInputsCircuit {
    fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
        poseidon(&[
            self.unlock.clone(),
            self.owner_identity.clone(),
            private_tx_hash.clone(),
        ])
    }
}

impl ProofInput for Withdraw {
    type Circuit = WithdrawCircuit;

    fn instantiate(&self, allocator: &Allocator) -> Result<WithdrawCircuit, RelationError> {
        Ok(WithdrawCircuit {
            private: self.private.instantiate(allocator)?,
            public: self.public.instantiate(allocator)?,
            public_hash: self.public_hash.instantiate(allocator)?,
        })
    }
}

impl ProofInput for WithdrawPrivateInputs {
    type Circuit = WithdrawPrivateInputs;

    fn instantiate(&self, allocator: &Allocator) -> Result<WithdrawPrivateInputs, RelationError> {
        Ok(Self {
            tx_context: self.tx_context.instantiate(allocator)?,
            escrow: self.escrow.instantiate(allocator)?,
            terms: self.terms.instantiate(allocator)?,
            creator_nullifier_pk: self.creator_nullifier_pk.instantiate(allocator)?,
        })
    }
}

impl ProofInput for WithdrawPublicInputs {
    type Circuit = WithdrawPublicInputsCircuit;

    fn instantiate(
        &self,
        allocator: &Allocator,
    ) -> Result<WithdrawPublicInputsCircuit, RelationError> {
        Ok(WithdrawPublicInputsCircuit {
            unlock: self.unlock.instantiate(allocator)?,
            owner_identity: self.owner_identity.instantiate(allocator)?,
        })
    }
}
