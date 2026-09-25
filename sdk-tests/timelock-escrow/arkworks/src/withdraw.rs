use solana_signature::Signature;
use timelock_escrow_sdk::{escrow_authority, zk_program::ProgramOwner};
use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    RelationError, TxContext,
};
use zolana_transaction::{utxo::Utxo, SppProofOutputUtxo, WalletUtxo};

use crate::{circuit, EscrowTerms};

#[derive(Clone)]
pub struct Withdraw {
    pub private: WithdrawPrivateInputs,
    pub public: WithdrawPublicInputs,
}

#[derive(Clone)]
pub struct WithdrawPrivateInputs {
    pub tx_context: TxContext,
    pub escrow: WalletUtxo,
    pub terms: EscrowTerms,
}

#[derive(Clone)]
pub struct WithdrawPublicInputs {
    pub unlock: u64,
    pub owner_identity: [u8; 32],
}

impl ProofInput for Withdraw {
    type Circuit = circuit::Withdraw;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Withdraw, RelationError> {
        let private = &self.private;
        Ok(circuit::Withdraw {
            private: circuit::WithdrawPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                escrow: private.escrow.instantiate(allocator)?,
                terms: private.terms.instantiate(allocator)?,
            },
            public: circuit::WithdrawPublicInputs {
                unlock: self.public.unlock.instantiate(allocator)?,
                owner_identity: self.public.owner_identity.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for Withdraw {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: WithdrawPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                escrow: Placeholder::placeholder()?,
                terms: Placeholder::placeholder()?,
            },
            public: WithdrawPublicInputs {
                unlock: Placeholder::placeholder()?,
                owner_identity: Placeholder::placeholder()?,
            },
        })
    }
}

pub fn escrow_input(
    output: &SppProofOutputUtxo,
    tree_id: u16,
    leaf_index: u64,
) -> Result<WalletUtxo, RelationError> {
    let invalid = |error: String| RelationError::InvalidInput(error);
    let owner = escrow_authority();
    let key = ProgramOwner::nullifier_key();
    let nullifier_pubkey = ProgramOwner::nullifier_pubkey().map_err(|e| invalid(e.to_string()))?;
    let utxo = Utxo {
        owner: owner.public_key(),
        asset: output.asset,
        amount: output.amount,
        blinding: output.blinding,
        ring_program_id: None,
        data: output.data.clone(),
    };
    let data_hash = output.data_hash.unwrap_or_default();
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &data_hash, &[0u8; 32], tree_id)
        .map_err(|e| invalid(e.to_string()))?;
    if utxo_hash != output.hash(tree_id).map_err(|e| invalid(e.to_string()))? {
        return Err(RelationError::Violated("the output is not an escrow utxo"));
    }
    Ok(WalletUtxo {
        nullifier: utxo
            .nullifier(&utxo_hash, &key)
            .map_err(|e| invalid(e.to_string()))?,
        utxo,
        nullifier_pubkey,
        utxo_hash,
        data_hash: output.data_hash,
        ring_data_hash: None,
        tree_id,
        leaf_index,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    })
}
