use circuit_lib::{
    poseidon, zero, Allocator, Assert, Circuit, CircuitVar, ConfidentialTransaction, DataUtxo,
    ProofInput, PublicHash, PublicInputs, RelationError, TokenUtxo, TxContext, Utxo, U64,
};
use timelock_escrow_program::instructions::escrow::{N_INPUTS, N_OUTPUTS};

use crate::EscrowTerms;

pub const ESCROW_TOKEN_INPUTS: usize = N_INPUTS;

#[derive(Clone, Debug)]
pub struct Escrow {
    pub private: EscrowPrivateInputs,
    pub public: EscrowPublicInputs,
    pub public_hash: PublicHash,
}

#[derive(Clone, Debug)]
pub struct EscrowPrivateInputs {
    pub tx_context: TxContext,
    pub token_utxos_asset_a: [Utxo; ESCROW_TOKEN_INPUTS],
    pub unlock: U64,
    pub amount: U64,
}

#[derive(Clone, Debug)]
pub struct EscrowPublicInputs {
    pub escrow_owner_hash: CircuitVar,
}

pub struct EscrowCircuit {
    pub private: EscrowPrivateInputsCircuit,
    pub public: EscrowPublicInputs,
    pub public_hash: CircuitVar,
}

pub struct EscrowPrivateInputsCircuit {
    pub tx_context: TxContext,
    pub token_utxos_asset_a: [Utxo; ESCROW_TOKEN_INPUTS],
    pub unlock: CircuitVar,
    pub amount: CircuitVar,
}

impl Circuit for EscrowCircuit {
    fn circuit(&self) -> Result<CircuitVar, RelationError> {
        let private = &self.private;
        private
            .amount
            .assert_not_equal(&zero(), "the escrow locks nothing")?;
        let mut tokens = TokenUtxo::new_mut(private.token_utxos_asset_a.clone())?;
        let locked = tokens.transfer(&self.public.escrow_owner_hash, private.amount.clone());
        let mut escrow = DataUtxo::<EscrowTerms>::from_output_utxo(locked)?;
        escrow.creator = tokens.owner().clone();
        escrow.unlock = private.unlock.clone();

        ConfidentialTransaction::<_, N_INPUTS, N_OUTPUTS>::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(escrow)
            .check()
    }

    fn public_hash(&self) -> &CircuitVar {
        &self.public_hash
    }
}

impl PublicInputs for EscrowPublicInputs {
    fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
        poseidon(&[self.escrow_owner_hash.clone(), private_tx_hash.clone()])
    }
}

impl ProofInput for Escrow {
    type Circuit = EscrowCircuit;

    fn instantiate(&self, allocator: &Allocator) -> Result<EscrowCircuit, RelationError> {
        Ok(EscrowCircuit {
            private: self.private.instantiate(allocator)?,
            public: self.public.instantiate(allocator)?,
            public_hash: self.public_hash.instantiate(allocator)?,
        })
    }
}

impl ProofInput for EscrowPrivateInputs {
    type Circuit = EscrowPrivateInputsCircuit;

    fn instantiate(
        &self,
        allocator: &Allocator,
    ) -> Result<EscrowPrivateInputsCircuit, RelationError> {
        Ok(EscrowPrivateInputsCircuit {
            tx_context: self.tx_context.instantiate(allocator)?,
            token_utxos_asset_a: self.token_utxos_asset_a.instantiate(allocator)?,
            unlock: self.unlock.instantiate(allocator)?,
            amount: self.amount.instantiate(allocator)?,
        })
    }
}

impl ProofInput for EscrowPublicInputs {
    type Circuit = EscrowPublicInputs;

    fn instantiate(&self, allocator: &Allocator) -> Result<EscrowPublicInputs, RelationError> {
        Ok(Self {
            escrow_owner_hash: self.escrow_owner_hash.instantiate(allocator)?,
        })
    }
}
