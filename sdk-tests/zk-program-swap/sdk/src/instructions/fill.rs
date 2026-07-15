use anyhow::{bail, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_program::instructions::fill::verify::FillPublicInput;
use swap_prover::{FillProofInputs, FILL_MODE_DERIVED};
use wincode::SchemaWrite;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_transaction::instructions::transact::{OutputUtxo, PrivateTxHash};

use crate::{
    err, escrow_authority_pda,
    order::{ensure_payout, OrderUtxo},
    program_id_pubkey, spp_program_meta, tag,
    witness::{escrow_owner_hash, order_data_hash, PlainUtxo},
    FillProof,
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaWrite)]
pub struct FillIxData {
    pub proof: FillProof,
    pub transact: TransactIxData,
}

pub struct FillProofInputParams {
    pub escrow: OrderUtxo,
    pub taker_in: OutputUtxo,
    pub source_output: OutputUtxo,
    pub destination_output: OutputUtxo,
    pub external_data_hash: [u8; 32],
}

impl FillProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<FillProofInputs> {
        let terms = &self.escrow.terms;
        let taker = ensure_payout(
            "taker_in",
            &self.taker_in,
            &terms.destination_mint,
            terms.destination_amount,
        )?;
        let source_owner = ensure_payout(
            "source_output",
            &self.source_output,
            &self.escrow.source_mint,
            self.escrow.source_amount,
        )?;
        if source_owner != taker {
            bail!("source output owner does not match the taker input owner");
        }
        let destination_owner = ensure_payout(
            "destination_output",
            &self.destination_output,
            &terms.destination_mint,
            terms.destination_amount,
        )?;
        if destination_owner != terms.destination {
            bail!("destination output owner does not match the order destination");
        }
        if self.destination_output.blinding != self.escrow.derived_destination_blinding()? {
            bail!("destination output blinding does not match the derived blinding");
        }
        if terms.fill_mode != FILL_MODE_DERIVED {
            bail!("order fill_mode does not authorize the derived fill");
        }
        let order = terms.field_elements()?;
        let taker_owner_hash = taker.owner_hash().map_err(err)?;
        let escrow = PlainUtxo {
            owner_hash: escrow_owner_hash(escrow_authority_pda().as_array())?,
            mint: self.escrow.source_mint,
            amount: self.escrow.source_amount,
            blinding: self.escrow.blinding,
            data_hash: order_data_hash(&order)?,
        };
        let taker_in = PlainUtxo {
            owner_hash: taker_owner_hash,
            mint: terms.destination_mint,
            amount: terms.destination_amount,
            blinding: self.taker_in.blinding,
            data_hash: [0u8; 32],
        };
        let source_output = PlainUtxo {
            owner_hash: taker_owner_hash,
            mint: self.escrow.source_mint,
            amount: self.escrow.source_amount,
            blinding: self.source_output.blinding,
            data_hash: [0u8; 32],
        };
        let destination_output = PlainUtxo {
            owner_hash: order.maker_owner_hash,
            mint: terms.destination_mint,
            amount: terms.destination_amount,
            blinding: self.destination_output.blinding,
            data_hash: [0u8; 32],
        };
        let private_tx_hash = PrivateTxHash::new(
            &[escrow.hash()?, taker_in.hash()?],
            &[source_output.hash()?, destination_output.hash()?],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;
        let public_input_hash = FillPublicInput {
            private_tx_hash: &private_tx_hash,
            expiry: terms.expiry,
        }
        .hash()
        .map_err(err)?;
        Ok(FillProofInputs {
            public_input_hash,
            private_tx_hash,
            order,
            escrow: escrow.field_elements()?,
            taker_in: taker_in.field_elements()?,
            source_output: source_output.field_elements()?,
            destination_output: destination_output.field_elements()?,
            external_data_hash: self.external_data_hash,
        })
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

        let data = wincode::serialize(&FillIxData {
            proof: fill_proof,
            transact: spp_proof,
        })
        .map_err(err)?;

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
