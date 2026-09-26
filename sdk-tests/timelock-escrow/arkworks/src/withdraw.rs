use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    RelationError, TxContext,
};
use zolana_transaction::{SppProofOutputUtxo, WalletUtxo};

use crate::{circuit, escrow_authority, EscrowTerms};

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "tsify", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", derive(zk_program_sdk::wasm::ZkProgramWasm))]
pub struct Withdraw {
    pub private: WithdrawPrivateInputs,
    pub public: WithdrawPublicInputs,
}

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "tsify", derive(tsify::Tsify))]
pub struct WithdrawPrivateInputs {
    pub tx_context: TxContext,
    pub escrow: WalletUtxo,
    pub terms: EscrowTerms,
}

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(
    feature = "tsify",
    derive(tsify::Tsify),
    tsify(large_number_types_as_bigints)
)]
pub struct WithdrawPublicInputs {
    pub unlock: u64,
    #[cfg_attr(
        feature = "serde",
        serde(with = "zolana_keypair::serde_helpers::bytes")
    )]
    #[cfg_attr(feature = "tsify", tsify(type = "Uint8Array"))]
    pub owner_identity: [u8; 32],
}

impl zk_program_sdk::circuit::CircuitType for circuit::Withdraw {}

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
    escrow_authority().input(output, tree_id, leaf_index)
}
