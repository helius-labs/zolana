use custom_ring_interface::{tag, CustomRingProof};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::instruction::TransactIxData;
use zolana_program::instruction::RingAuthorityTransact;

use crate::{
    instructions::{
        cosigner::RingPrefix,
        transact::{PolicyReads, RingStatementData, TransactInstructionError},
    },
    CustomRing,
};

#[must_use]
pub struct SetDelegate {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub delegate: Address,
}

impl SetDelegate {
    pub fn instruction(self) -> Instruction {
        let Self {
            ring,
            payer,
            authority,
            delegate,
        } = self;
        let mut data = vec![tag::SET_DELEGATE];
        data.extend_from_slice(delegate.as_array());
        Instruction {
            program_id: ring.program_id(),
            accounts: vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new(ring.config_pda(), false),
                AccountMeta::new(ring.delegate_pda(), false),
                AccountMeta::new_readonly(ring.key_registry_root_pda(), false),
                AccountMeta::new_readonly(Address::default(), false),
                AccountMeta::new_readonly(ring.program_id(), false),
                AccountMeta::new_readonly(ring.program_data_pda(), false),
            ],
            data,
        }
    }
}

/// The delegate rail runs on policy rings with key escrow on only.
#[must_use]
pub struct CustomRingDelegateTransact {
    pub ring: CustomRing,
    pub payer: Address,
    /// One per input group, in the order the inputs name them.
    pub input_trees: Vec<Address>,
    pub output_tree: Address,
    pub policy: PolicyReads,
    pub cosigner: Option<Address>,
    pub delegate: Address,
    pub proof: CustomRingProof,
    pub transact: TransactIxData,
}

impl CustomRingDelegateTransact {
    pub fn instruction(self) -> Result<Instruction, TransactInstructionError> {
        let Self {
            ring: deployment,
            payer,
            input_trees,
            output_tree,
            policy,
            cosigner,
            delegate,
            proof,
            transact,
        } = self;
        if !transact.interface_transfers.is_empty() {
            return Err(TransactInstructionError::PublicLeg);
        }
        let rail = RingAuthorityTransact {
            payer,
            input_trees,
            output_tree,
            ring_program_id: deployment.program_id(),
            interface_transfer_accounts: Vec::new(),
            data: transact,
        };
        let spp_accounts = rail.instruction().accounts;

        let mut accounts = vec![AccountMeta::new(payer, true)];
        accounts.extend(
            RingPrefix {
                ring: deployment,
                cosigner,
            }
            .metas(),
        );
        accounts.push(AccountMeta::new_readonly(deployment.delegate_pda(), false));
        accounts.push(AccountMeta::new_readonly(delegate, true));
        accounts.extend(policy.metas(deployment)?);
        accounts.extend(spp_accounts);

        let data = RingStatementData {
            proof,
            policy: Some(&policy),
            approval_required: false,
            transact: rail.data,
        }
        .encode(tag::DELEGATE_TRANSACT)?;
        Ok(Instruction {
            program_id: deployment.program_id(),
            accounts,
            data,
        })
    }
}
