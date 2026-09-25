use anyhow::{bail, Result};
use circuit_lib::{
    client::{self, BuiltTransaction, State},
    constant,
    convert::var,
    PublicHash, U64,
};
use solana_address::Address;
use timelock_escrow_program::instructions::{escrow, withdraw};
use timelock_escrow_sdk::{escrow_authority, zk_program::ProgramOwner};
use zolana_hasher::{
    primitives::{right_align, solana_owner_identity},
    Hasher, Poseidon,
};
use zolana_keypair::{ShieldedAddress, ViewingKeyTrait};
use zolana_transaction::{
    utxo::{SppProofInputUtxo, Utxo},
    SppProofOutputUtxo,
};

use crate::ESCROW_TOKEN_INPUTS;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EscrowTerms {
    pub creator: [u8; 32],
    pub unlock: u64,
}

impl State for EscrowTerms {
    type Circuit = crate::EscrowTerms;

    fn circuit_state(&self) -> Result<crate::EscrowTerms> {
        Ok(crate::EscrowTerms {
            creator: var(&self.creator, "escrow creator")?,
            unlock: constant(self.unlock),
        })
    }

    fn utxo_data(&self) -> Vec<u8> {
        self.unlock.to_le_bytes().to_vec()
    }
}

pub struct EscrowPublicInputs {
    pub escrow_owner_hash: [u8; 32],
}

impl client::PublicInputs for EscrowPublicInputs {
    fn hash(&self, private_tx_hash: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(Poseidon::hashv(&[
            self.escrow_owner_hash.as_slice(),
            private_tx_hash.as_slice(),
        ])?)
    }
}

pub struct WithdrawPublicInputs {
    pub unlock: u64,
    pub owner_identity: [u8; 32],
}

impl client::PublicInputs for WithdrawPublicInputs {
    fn hash(&self, private_tx_hash: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(Poseidon::hashv(&[
            right_align(&self.unlock.to_be_bytes()).as_slice(),
            self.owner_identity.as_slice(),
            private_tx_hash.as_slice(),
        ])?)
    }
}

pub struct Escrow {
    pub creator: ShieldedAddress,
    pub token_utxos_asset_a: [SppProofInputUtxo; ESCROW_TOKEN_INPUTS],
    pub amount: u64,
    pub unlock: u64,
    pub payer: Address,
    pub output_tree_id: u16,
}

pub struct EscrowTransaction {
    pub proof_inputs: crate::Escrow,
    pub transaction: BuiltTransaction<{ escrow::N_INPUTS }, { escrow::N_OUTPUTS }>,
}

impl Escrow {
    pub fn build(self, viewing_key: &impl ViewingKeyTrait) -> Result<EscrowTransaction> {
        if self.amount == 0 {
            bail!("the escrow locks nothing");
        }
        let escrow_owner = escrow_authority();
        let public = EscrowPublicInputs {
            escrow_owner_hash: escrow_owner.owner_hash()?,
        };
        let mut tokens = client::TokenUtxo::new_mut(self.creator, self.token_utxos_asset_a)?;
        let locked = tokens.transfer(
            escrow_owner.address(self.creator.viewing_pubkey)?,
            self.amount,
        )?;
        let mut escrow = client::DataUtxo::<EscrowTerms>::from_output_utxo(locked)?;
        escrow.creator = self.creator.owner_hash()?;
        escrow.unlock = self.unlock;
        let token_utxos_asset_a = tokens.circuit_inputs()?;

        let transaction = client::ConfidentialTransaction::<
            _,
            { escrow::N_INPUTS },
            { escrow::N_OUTPUTS },
        >::new(self.payer, self.output_tree_id, &public)
        .with_token_utxos(tokens)
        .with_data_utxo(escrow)
        .build(viewing_key)?;

        let proof_inputs = crate::Escrow {
            private: crate::EscrowPrivateInputs {
                tx_context: transaction.tx_context.circuit()?,
                token_utxos_asset_a,
                unlock: U64::from(self.unlock),
                amount: U64::from(self.amount),
            },
            public: crate::EscrowPublicInputs {
                escrow_owner_hash: var(&public.escrow_owner_hash, "escrow owner hash")?,
            },
            public_hash: PublicHash::new(var(&transaction.public_hash, "public hash")?),
        };
        Ok(EscrowTransaction {
            proof_inputs,
            transaction,
        })
    }
}

pub struct Withdraw {
    pub creator: ShieldedAddress,
    pub escrow: SppProofInputUtxo,
    pub terms: EscrowTerms,
    pub payer: Address,
    pub output_tree_id: u16,
}

pub struct WithdrawTransaction {
    pub proof_inputs: crate::Withdraw,
    pub transaction: BuiltTransaction<{ withdraw::N_INPUTS }, { withdraw::N_OUTPUTS }>,
}

impl Withdraw {
    pub fn build(self, viewing_key: &impl ViewingKeyTrait) -> Result<WithdrawTransaction> {
        if self.terms.creator != self.creator.owner_hash()? {
            bail!("the signer is not the escrow creator");
        }
        let owner_identity = solana_owner_identity(self.creator.solana_address()?.as_array())?;
        let public = WithdrawPublicInputs {
            unlock: self.terms.unlock,
            owner_identity,
        };
        let terms = self.terms.circuit_state()?;
        let mut escrow = client::DataUtxo::new_burn(self.escrow, self.terms)?;
        if escrow.amount() == 0 {
            bail!("the escrow utxo holds nothing");
        }
        let amount = escrow.amount();
        let payout = escrow.transfer(self.creator, amount)?;
        let escrow_input = escrow
            .circuit_input()?
            .ok_or_else(|| anyhow::anyhow!("a burned data utxo has an input"))?;

        let transaction = client::ConfidentialTransaction::<
            _,
            { withdraw::N_INPUTS },
            { withdraw::N_OUTPUTS },
        >::new(self.payer, self.output_tree_id, &public)
        .with_data_utxo(escrow)
        .with_output_token_utxo(payout)
        .build(viewing_key)?;

        let proof_inputs = crate::Withdraw {
            private: crate::WithdrawPrivateInputs {
                tx_context: transaction.tx_context.circuit()?,
                escrow: escrow_input,
                terms,
                creator_nullifier_pk: var(&self.creator.nullifier_pubkey, "creator nullifier pk")?,
            },
            public: crate::WithdrawPublicInputs {
                unlock: U64::from(public.unlock),
                owner_identity: var(&public.owner_identity, "owner identity")?,
            },
            public_hash: PublicHash::new(var(&transaction.public_hash, "public hash")?),
        };
        Ok(WithdrawTransaction {
            proof_inputs,
            transaction,
        })
    }
}

pub fn escrow_input(
    output: &SppProofOutputUtxo,
    tree_id: u16,
    leaf_index: u64,
) -> Result<SppProofInputUtxo> {
    let owner = escrow_authority();
    let key = ProgramOwner::nullifier_key();
    let nullifier_pubkey = ProgramOwner::nullifier_pubkey()?;
    let utxo = Utxo {
        owner: owner.public_key(),
        asset: output.asset,
        amount: output.amount,
        blinding: output.blinding,
        ring_program_id: None,
        data: output.data.clone(),
    };
    let data_hash = output.data_hash.unwrap_or_default();
    let utxo_hash = utxo.hash(&nullifier_pubkey, &data_hash, &[0u8; 32], tree_id)?;
    if utxo_hash != output.hash(tree_id)? {
        bail!("the output is not an escrow utxo");
    }
    let nullifier = utxo.nullifier(&utxo_hash, &key)?;
    Ok(SppProofInputUtxo {
        utxo,
        nullifier_pubkey,
        utxo_hash,
        nullifier,
        data_hash: output.data_hash,
        ring_data_hash: None,
        tree_id,
        leaf_index,
        cache_slot: None,
    })
}
