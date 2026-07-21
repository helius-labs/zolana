use anyhow::{anyhow, Result};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::instruction_data::transact::TransactIxData, SHIELDED_POOL_PROGRAM_ID,
};

use crate::{err, tag, CreateEscrowIxData, EscrowOpenProof};

/// Both `authority` (the pair's maker, funding the reservation and signing the
/// spend of its own funding UTXO) and `owner` (the source UTXO's owner,
/// authorizing the spend) must sign -- SPP authorizes each input by its own
/// signer.
pub struct CreateEscrow {
    pub authority: Pubkey,
    pub owner: Pubkey,
    pub pair: Pubkey,
    pub escrow: Pubkey,
    pub tree: Pubkey,
    pub proof: EscrowOpenProof,
    /// The slot the proof commits to -- see `CreateEscrowIxData`'s doc
    /// comment. Must match whatever value `EscrowOpenProofInputParams::created_at`
    /// used to build the proof.
    pub created_at: u64,
    pub transact: TransactIxData,
}

impl CreateEscrow {
    pub fn instruction(self) -> Result<Instruction> {
        let CreateEscrow {
            authority,
            owner,
            pair,
            escrow,
            tree,
            proof,
            created_at,
            mut transact,
        } = self;

        // SPP resolves each spent input's owner by position within the forwarded
        // transact account tail: [authority(payer)=0, tree=1, owner=2, program=3].
        // create_escrow's two inputs are the source UTXO (owned by `owner`) and
        // maker_funding (owned by `authority`), so route each to its owner's slot.
        const PAYER_POSITION: u8 = 0;
        const OWNER_POSITION: u8 = 2;
        route_input(&mut transact, 0, OWNER_POSITION)?;
        route_input(&mut transact, 1, PAYER_POSITION)?;

        let ix_data = CreateEscrowIxData {
            proof,
            created_at,
            transact,
        };
        let serialized = wincode::serialize(&ix_data).map_err(err)?;

        let mut instruction_data = vec![tag::CREATE_ESCROW];
        instruction_data.extend_from_slice(&serialized);

        let accounts = vec![
            AccountMeta::new(authority, true),
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new_readonly(pair, false),
            AccountMeta::new(escrow, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            // Forwarded SPP `transact` CPI tail: payer, tree, the owner signer,
            // then the shielded-pool program id last.
            AccountMeta::new(authority, true),
            AccountMeta::new(tree, false),
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new_readonly(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
        ];

        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}

/// Points `transact.inputs[input]`'s `eddsa_signer_index` at `position`, the
/// slot of that input's owner within the forwarded SPP `transact` account tail.
fn route_input(transact: &mut TransactIxData, input: usize, position: u8) -> Result<()> {
    transact
        .inputs
        .get_mut(input)
        .ok_or_else(|| anyhow!("transact input {input} out of range"))?
        .eddsa_signer_index = position;
    Ok(())
}
