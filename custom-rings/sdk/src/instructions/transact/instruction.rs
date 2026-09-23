use custom_ring_interface::{tag, CustomRingProof, CustomRingTransactIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use thiserror::Error;
use zolana_interface::instruction::instruction_data::transact::TreeContext;
use zolana_interface::instruction::TransactIxData;
use zolana_program::instruction::{RingTransact, TransactInterfaceTransferAccounts};
use zolana_ring_policy::ANSWER_SLOTS;
use zolana_transaction::SOL_MINT;

use crate::{
    instructions::{cosigner::RingPrefix, spend_window::window_metas},
    CurrentKeyRegistryRoot, CustomRing,
};

#[derive(Debug, Error)]
pub enum TransactInstructionError {
    #[error("a delegate move settles no public leg")]
    PublicLeg,
    #[error("revocation slot {slot} names policy tree {index}, the statement reads {trees} trees")]
    RevocationTree {
        slot: usize,
        index: u8,
        trees: usize,
    },
    #[error(transparent)]
    Serialize(#[from] wincode::WriteError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyTreeContext {
    pub tree: Address,
    pub context: TreeContext,
}

/// The key registry root an escrowed statement binds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EscrowBinding {
    #[default]
    Off,
    Registry {
        root_index: u8,
    },
}

impl EscrowBinding {
    /// `None` with escrow off.
    pub(crate) fn of(root: Option<CurrentKeyRegistryRoot>) -> Self {
        root.map_or(Self::Off, |root| Self::Registry {
            root_index: root.history_index,
        })
    }

    /// The wire byte, zero with escrow off.
    pub(crate) const fn root_index(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Registry { root_index } => root_index,
        }
    }

    pub(crate) fn meta(self, ring: CustomRing) -> Option<AccountMeta> {
        match self {
            Self::Off => None,
            Self::Registry { .. } => Some(AccountMeta::new_readonly(
                ring.key_registry_root_pda(),
                false,
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyReads {
    pub trees: Vec<PolicyTreeContext>,
    pub escrow: EscrowBinding,
    pub revocation_targets: [[u8; 32]; ANSWER_SLOTS],
    /// Per fact slot, the index into `trees` its target is nullified in.
    pub revocation_tree_indexes: [u8; ANSWER_SLOTS],
}

impl PolicyReads {
    /// `[policy_config, trees.., key_registry_root?, revocation PDAs..]`, the program's read order.
    pub(crate) fn metas(
        &self,
        ring: CustomRing,
    ) -> Result<Vec<AccountMeta>, TransactInstructionError> {
        let mut metas = Vec::with_capacity(2 + self.trees.len() + ANSWER_SLOTS);
        metas.push(AccountMeta::new_readonly(ring.policy_config_pda(), false));
        metas.extend(
            self.trees
                .iter()
                .map(|tree| AccountMeta::new_readonly(tree.tree, false)),
        );
        metas.extend(self.escrow.meta(ring));
        for (slot, (target, &index)) in self
            .revocation_targets
            .iter()
            .zip(&self.revocation_tree_indexes)
            .enumerate()
            .filter(|(_, (target, _))| **target != [0u8; 32])
        {
            let tree = self.trees.get(usize::from(index)).ok_or(
                TransactInstructionError::RevocationTree {
                    slot,
                    index,
                    trees: self.trees.len(),
                },
            )?;
            metas.push(AccountMeta::new_readonly(
                zolana_interface::pda::nullifier_pda(&tree.tree, target).0,
                false,
            ));
        }
        Ok(metas)
    }

    pub(crate) fn contexts(&self) -> Vec<TreeContext> {
        self.trees.iter().map(|tree| tree.context).collect()
    }
}

pub(crate) struct RingStatementData<'a> {
    pub proof: CustomRingProof,
    pub policy: Option<&'a PolicyReads>,
    pub approval_required: bool,
    pub transact: TransactIxData,
}

impl RingStatementData<'_> {
    pub(crate) fn encode(self, instruction_tag: u8) -> Result<Vec<u8>, TransactInstructionError> {
        let body = wincode::serialize(&CustomRingTransactIxData {
            proof: self.proof,
            policy_trees: self.policy.map(PolicyReads::contexts).unwrap_or_default(),
            key_registry_root_index: self.policy.map_or(0, |policy| policy.escrow.root_index()),
            approval_required: u8::from(self.approval_required),
            revocation_targets: self.policy.map_or([[0u8; 32]; ANSWER_SLOTS], |policy| {
                policy.revocation_targets
            }),
            revocation_tree_indexes: self
                .policy
                .map_or([0u8; ANSWER_SLOTS], |policy| policy.revocation_tree_indexes),
            transact: self.transact,
        })?;
        let mut data = Vec::with_capacity(1 + body.len());
        data.push(instruction_tag);
        data.extend_from_slice(&body);
        Ok(data)
    }
}

#[must_use]
/// Audited ring transact: the ring's auditor key-encryption proof followed by the
/// SPP content it forwards.
///
/// A policy ring prepends `[payer, config, cosigner_pda, cosigner]` and its
/// [`PolicyReads`] accounts to SPP's own `RING_TRANSACT` list, an audit-only ring
/// prepends just `[payer, config, cosigner_pda, cosigner]`, then one spend window
/// slot per public leg. The `cosigner` slot signs only when the ring has a
/// co-signer, else it repeats `cosigner_pda`.
/// The config holds the auditor key the public-input hash is recomputed against.
/// Everything after the prefix is forwarded to SPP position for
/// position, so it is taken straight from [`RingTransact::instruction`] rather
/// than re-listed here -- a hand-written copy would be a second definition of
/// SPP's loader order, free to drift from it.
///
/// `ring_config` (this program's `ring_auth` PDA) stays unsigned: no keypair
/// exists for it, and the program is what flips the meta to a signer inside its
/// CPI. Marking it a signer here would make the transaction unsignable.
pub struct CustomRingTransact {
    pub ring: CustomRing,
    pub payer: Address,
    /// One per input group, in the order the inputs name them.
    pub input_trees: Vec<Address>,
    pub output_tree: Address,
    /// `None` for an audit-only ring.
    pub policy: Option<PolicyReads>,
    pub cosigner: Option<Address>,
    /// The eddsa owners of the spent UTXOs; SPP requires each as a signer.
    pub owner_signers: Vec<Address>,
    /// Settlement accounts for the content's `interface_transfers`, in the same
    /// order.
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    /// Proof of the selected ring statement, from `to_instruction_proof`.
    pub proof: CustomRingProof,
    /// The SPP content. Its `messages` must already carry the auditor message that
    /// the proof commits to, and its `private_tx_hash` must be the one the SPP
    /// proof was generated for.
    pub transact: TransactIxData,
    /// The dual control bit the velocity statement proves, the co-signer then signs.
    pub approval_required: bool,
}

impl CustomRingTransact {
    pub fn instruction(self) -> Result<Instruction, TransactInstructionError> {
        let Self {
            ring: deployment,
            payer,
            input_trees,
            output_tree,
            policy,
            cosigner,
            owner_signers,
            interface_transfer_accounts,
            proof,
            transact,
            approval_required,
        } = self;

        let windows: Vec<AccountMeta> = window_metas(
            deployment,
            interface_transfer_accounts.iter().map(settled_mint),
        )
        .collect();
        let ring = RingTransact {
            payer,
            input_trees,
            output_tree,
            ring_program_id: deployment.program_id(),
            owner_signers,
            interface_transfer_accounts,
            data: transact,
        };
        // `.instruction()` (not `.cpi_instruction()`) is the client-facing form:
        // it targets a ring program and leaves `ring_config` unsigned.
        let mut spp_accounts = ring.instruction().accounts;
        // The program raises the namespace PDA as a signer inside its CPI.
        let namespace = deployment.namespace_pda();
        for meta in spp_accounts
            .iter_mut()
            .filter(|meta| meta.pubkey == namespace)
        {
            meta.is_signer = false;
        }

        let mut accounts = vec![AccountMeta::new(payer, true)];
        accounts.extend(
            RingPrefix {
                ring: deployment,
                cosigner,
            }
            .metas(),
        );
        if let Some(policy) = &policy {
            accounts.extend(policy.metas(deployment)?);
        }
        accounts.extend(windows);
        accounts.extend(spp_accounts);

        let data = RingStatementData {
            proof,
            policy: policy.as_ref(),
            approval_required,
            transact: ring.data,
        }
        .encode(tag::TRANSACT)?;
        Ok(Instruction {
            program_id: deployment.program_id(),
            accounts,
            data,
        })
    }
}

fn settled_mint(accounts: &TransactInterfaceTransferAccounts) -> Address {
    match accounts {
        TransactInterfaceTransferAccounts::Sol(_) => SOL_MINT,
        TransactInterfaceTransferAccounts::SplDeposit(spl) => spl.mint,
        TransactInterfaceTransferAccounts::SplWithdrawal(spl) => spl.mint,
    }
}
