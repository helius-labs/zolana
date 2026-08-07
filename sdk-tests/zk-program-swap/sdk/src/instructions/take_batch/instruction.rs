use anyhow::{bail, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use swap_program::instructions::take_batch::TakeBatchIxData;
use zolana_interface::{
    instruction::{
        instruction_data::{
            aggregate_transact::{AggregateTransactIxData, EMPTY_LEG_PROOF},
            transact::{CircuitId, TransactIxData, TransactProof},
        },
        AggregateTransact,
    },
    verifying_keys::{AggregateCircuitId, Bsb22Commitment, InnerCircuitKind},
};

use crate::{err, order_authority_pda, tag, TakeProof};

pub struct TakeBatchLeg {
    pub take_proof: TakeProof,
    pub spp_proof: TransactIxData,
}

/// Fills settled by one recursive proof over the leg public input hashes.
pub struct TakeBatch {
    pub payer: Pubkey,
    pub tree: Pubkey,
    pub proof: TransactProof,
    pub bsb22_commitment: Bsb22Commitment,
    pub legs: Vec<TakeBatchLeg>,
}

impl TakeBatch {
    pub fn instruction(self) -> Result<Instruction> {
        let Self {
            payer,
            tree,
            proof,
            bsb22_commitment,
            legs,
        } = self;

        let Some(first) = legs.first() else {
            bail!("take batch has no legs");
        };
        let CircuitId::ConfidentialEddsa(num_inputs, num_outputs, num_public_asset_slots) =
            first.spp_proof.circuit
        else {
            bail!("swap legs settle on the confidential rail");
        };
        if legs
            .iter()
            .any(|leg| leg.spp_proof.circuit != first.spp_proof.circuit)
        {
            bail!("every leg of a batch shares one circuit");
        }
        let circuit = AggregateCircuitId {
            kind: InnerCircuitKind::ConfidentialEddsa,
            num_inputs,
            num_outputs,
            num_public_asset_slots,
            batch: u8::try_from(legs.len()).map_err(err)?,
        };

        let data = AggregateTransactIxData {
            circuit,
            proof,
            bsb22_commitment,
            legs: legs
                .iter()
                .map(|leg| TransactIxData {
                    proof: EMPTY_LEG_PROOF,
                    ..leg.spp_proof.clone()
                })
                .collect(),
            leg_account_counts: Vec::new(),
        };
        let order_authority = order_authority_pda();
        let (aggregate, spp_accounts) = AggregateTransact {
            payer,
            input_tree: tree,
            output_tree: tree,
            ring_program_ids: vec![Pubkey::default(); legs.len()],
            owner_signers: vec![vec![order_authority]; legs.len()],
            interface_transfer_accounts: vec![Vec::new(); legs.len()],
            data,
        }
        .cpi_parts();

        let mut accounts = Vec::with_capacity(1 + spp_accounts.len());
        accounts.push(AccountMeta::new(payer, true));
        // The order authority is a PDA, so it signs only the CPI the swap
        // program makes, never the instruction the taker sends.
        accounts.extend(spp_accounts.into_iter().map(|mut meta| {
            meta.is_signer &= meta.pubkey != order_authority;
            meta
        }));

        let serialized_ix = wincode::serialize(&TakeBatchIxData {
            take_proofs: legs.into_iter().map(|leg| leg.take_proof).collect(),
            aggregate,
        })
        .map_err(err)?;
        let mut instruction_data = vec![tag::TAKE_BATCH];
        instruction_data.extend_from_slice(&serialized_ix);

        Ok(Instruction {
            program_id: swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
