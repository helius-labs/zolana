use custom_ring_interface::{tag, CustomRingProof, CustomRingTransactIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use thiserror::Error;
use zolana_interface::instruction::instruction_data::transact::TreeContext;
use zolana_interface::instruction::{RingAuthorityTransact, TransactIxData};

use crate::{
    instructions::cosigner::{RingPolicy, RingPrefix},
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

#[derive(Debug, Error)]
pub enum DelegateInstructionError {
    #[error("a delegate move settles no public leg")]
    PublicLeg,
    #[error(transparent)]
    Serialize(#[from] wincode::WriteError),
}

#[must_use]
pub struct CustomRingDelegateTransact {
    pub ring: CustomRing,
    pub payer: Address,
    pub input_tree: Address,
    pub output_tree: Address,
    /// The pinned entries tree for a policy ring, `None` for an audit-only ring.
    pub entries_tree: Option<Address>,
    pub cosigner: Option<Address>,
    pub delegate: Address,
    pub proof: CustomRingProof,
    pub transact: TransactIxData,
    pub state_root_index: u16,
    pub nullifier_root_index: u16,
    pub revocation_targets: [[u8; 32]; zolana_ring_policy::ANSWER_SLOTS],
}

impl CustomRingDelegateTransact {
    pub fn instruction(self) -> Result<Instruction, DelegateInstructionError> {
        let Self {
            ring: deployment,
            payer,
            input_tree,
            output_tree,
            entries_tree,
            cosigner,
            delegate,
            proof,
            transact,
            state_root_index,
            nullifier_root_index,
            revocation_targets,
        } = self;
        if !transact.interface_transfers.is_empty() {
            return Err(DelegateInstructionError::PublicLeg);
        }
        let rail = RingAuthorityTransact {
            payer,
            input_trees: vec![input_tree],
            output_tree,
            ring_program_id: deployment.program_id(),
            interface_transfer_accounts: Vec::new(),
            data: transact,
        };
        let spp_accounts = rail.instruction().accounts;
        let transact = rail.data;

        let mut accounts = Vec::with_capacity(8 + spp_accounts.len());
        accounts.push(AccountMeta::new(payer, true));
        let mut prefix = RingPrefix {
            ring: deployment,
            cosigner,
            policy: entries_tree.map_or(RingPolicy::Off, RingPolicy::Entries),
        }
        .metas();
        prefix.insert(
            3,
            AccountMeta::new_readonly(deployment.delegate_pda(), false),
        );
        prefix.insert(4, AccountMeta::new_readonly(delegate, true));
        accounts.extend(prefix);
        if entries_tree.is_some() {
            accounts.push(AccountMeta::new_readonly(
                deployment.key_registry_root_pda(),
                false,
            ));
        }
        if let Some(entries_tree) = entries_tree {
            accounts.extend(
                revocation_targets
                    .iter()
                    .filter(|target| target.iter().any(|byte| *byte != 0))
                    .map(|target| {
                        AccountMeta::new_readonly(
                            zolana_interface::pda::nullifier_pda(&entries_tree, target).0,
                            false,
                        )
                    }),
            );
        }
        accounts.extend(spp_accounts);

        let body = wincode::serialize(&CustomRingTransactIxData {
            proof,
            policy_trees: entries_tree
                .iter()
                .map(|_| TreeContext {
                    utxo_tree_root_index: state_root_index,
                    nullifier_tree_root_index: nullifier_root_index,
                })
                .collect(),
            key_registry_root_index: 0,
            approval_required: 0,
            revocation_targets,
            revocation_tree_indexes: [0; zolana_ring_policy::ANSWER_SLOTS],
            transact,
        })?;
        let mut data = Vec::with_capacity(1 + body.len());
        data.push(tag::DELEGATE_TRANSACT);
        data.extend_from_slice(&body);
        Ok(Instruction {
            program_id: deployment.program_id(),
            accounts,
            data,
        })
    }
}
