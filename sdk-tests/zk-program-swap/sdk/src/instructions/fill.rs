use anyhow::Result;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_prover::FillProofInputs;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypairTrait, ViewingKeyTrait};
use zolana_transaction::{
    instructions::transact::{ConfidentialSlot, OutputUtxo, SignedTransaction, Transaction},
    utxo::Blinding,
    AssetRegistry, TransactionError,
};

use crate::{
    err, escrow_authority_pda,
    order::{BlindingField, DataHash, OrderUtxo, Recipient},
    program_id_pubkey, spp_program_meta, tag, FillProof,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillIxData {
    pub proof: FillProof,
    pub transact: TransactIxData,
}

impl FillIxData {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = borsh::to_vec(&self.proof).expect("FillProof serialization is infallible");
        data.extend_from_slice(
            &self
                .transact
                .serialize()
                .expect("transact serialization is infallible"),
        );
        data
    }
}

pub struct FillProofInputParams {
    pub escrow: OrderUtxo,
    pub taker_in: OutputUtxo,
    pub source_output_blinding: Blinding,
    pub external_data_hash: [u8; 32],
    pub maker_recipient: zolana_keypair::ShieldedAddress,
    pub taker_recipient: zolana_keypair::ShieldedAddress,
}

impl FillProofInputParams {
    pub fn destination_output_blinding(&self) -> Result<Blinding> {
        let field = swap_prover::derive_destination_blinding(&self.escrow.blinding.to_field())
            .map_err(err)?;
        let mut blinding = [0u8; BLINDING_LEN];
        blinding.copy_from_slice(field.get(1..32).ok_or_else(|| err("blinding tail"))?);
        Ok(blinding)
    }

    pub fn into_proof_inputs(&self) -> Result<FillProofInputs> {
        let terms = &self.escrow.terms;
        Ok(FillProofInputs {
            source_mint: *self.escrow.source_mint.as_array(),
            source_amount: self.escrow.source_amount,
            escrow_authority: *escrow_authority_pda().as_array(),
            escrow_blinding: self.escrow.blinding.to_field(),
            destination_mint: *terms.destination_mint.as_array(),
            destination_amount: terms.destination_amount,
            maker_owner_hash: terms.destination.owner_hash().map_err(err)?,
            maker_viewing_pk: *terms.destination.viewing_pubkey.as_bytes(),
            expiry: terms.expiry,
            taker_pk_fe: terms.taker.data_hash()?,
            taker_address: self
                .taker_in
                .owner_address
                .ok_or_else(|| err("taker_in owner address"))?
                .owner_hash()
                .map_err(err)?,
            taker_in_blinding: self.taker_in.blinding.to_field(),
            source_output_blinding: self.source_output_blinding.to_field(),
            external_data_hash: self.external_data_hash,
        })
    }

    pub fn destination_output(&self) -> Result<OutputUtxo> {
        Ok(Recipient {
            address: self.maker_recipient,
            amount: self.escrow.terms.destination_amount,
            blinding: self.destination_output_blinding()?,
            mint: self.escrow.terms.destination_mint,
        }
        .output())
    }

    pub fn source_output(&self) -> OutputUtxo {
        Recipient {
            address: self.taker_recipient,
            amount: self.escrow.source_amount,
            blinding: self.source_output_blinding,
            mint: self.escrow.source_mint,
        }
        .output()
    }
}

pub struct EscrowFill {
    pub tx: Transaction,
    pub source_output: OutputUtxo,
    pub destination_output: OutputUtxo,
}

impl EscrowFill {
    pub fn sign<K: ShieldedKeypairTrait + ViewingKeyTrait>(
        self,
        keypair: &K,
        assets: &AssetRegistry,
    ) -> Result<SignedTransaction, TransactionError> {
        let Self {
            tx,
            source_output,
            destination_output,
        } = self;
        if tx.inputs.len() != 2 {
            return Err(TransactionError::TooManyInputs {
                got: tx.inputs.len(),
                max: 2,
            });
        }

        let source_slot = ConfidentialSlot::new(source_output, assets)?;
        let destination_slot = ConfidentialSlot::new(destination_output, assets)?;

        tx.sign_with_slots(&[&source_slot, &destination_slot], keypair)
    }
}

pub struct Fill {
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub fill_proof: FillProof,
    pub spp_proof: TransactIxData,
}

const ESCROW_AUTHORITY_SIGNER_INDEX: u8 = 2;

impl Fill {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            payer,
            tree,
            fill_proof,
            mut spp_proof,
        } = self;
        if let Some(escrow_input) = spp_proof.inputs.get_mut(0) {
            escrow_input.eddsa_signer_index = ESCROW_AUTHORITY_SIGNER_INDEX;
        }

        let data = FillIxData {
            proof: fill_proof,
            transact: spp_proof,
        }
        .serialize();

        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(payer, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(escrow_authority_pda(), false),
            spp_program_meta(),
        ];
        let mut instruction_data = vec![tag::FILL];
        instruction_data.extend_from_slice(&data);
        Ok(Instruction {
            program_id: program_id_pubkey(),
            accounts,
            data: instruction_data,
        })
    }
}
