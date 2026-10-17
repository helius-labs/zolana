use custom_ring_interface::{tag, CustomRingProof, CustomRingTransactIxData, N_FOREIGN};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::instruction::{instruction_data::transact::TreeContext, TransactIxData};
use zolana_program::instruction::{
    RingAuthorityTransact, RingTransact, TransactInterfaceTransferAccounts,
};

use crate::{CurrentRegistryRoot, CustomRing, RingError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyTreeContext {
    pub tree: Address,
    pub context: TreeContext,
}

/// The ring's registry root a policy statement binds, named by its history slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RegistryBinding {
    /// A later batch may overwrite the slot, the submission then proves again.
    pub root_index: u8,
    pub root: [u8; 32],
}

impl RegistryBinding {
    pub(crate) fn of(root: CurrentRegistryRoot) -> Self {
        Self {
            root_index: root.history_index,
            root: root.root,
        }
    }
}

/// The curator registry the policy sources name and the root bound from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForeignBinding {
    /// The curator's `MemberRegistryRoot` account, as the policy config pins it.
    pub registry: Address,
    pub curator: CustomRing,
    pub root_index: u8,
    pub root: [u8; 32],
    pub next_index: u64,
}

/// The registry root an escrowed deposit binds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EscrowBinding {
    #[default]
    Off,
    Registry(RegistryBinding),
}

impl EscrowBinding {
    pub(crate) fn of(root: Option<CurrentRegistryRoot>) -> Self {
        root.map_or(Self::Off, |root| Self::Registry(RegistryBinding::of(root)))
    }

    pub(crate) const fn root_index(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Registry(binding) => binding.root_index,
        }
    }

    pub(crate) fn meta(self, ring: CustomRing) -> Option<AccountMeta> {
        (self != Self::Off)
            .then(|| AccountMeta::new_readonly(ring.member_registry_root_pda(), false))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyReads {
    pub trees: Vec<PolicyTreeContext>,
    pub registry: RegistryBinding,
    pub foreign: Option<ForeignBinding>,
}

impl PolicyReads {
    /// `[policy_config, trees.., member_registry_root, foreign_root?]`, the program's read order.
    fn metas(&self, ring: CustomRing) -> Vec<AccountMeta> {
        let mut metas = vec![AccountMeta::new_readonly(ring.policy_config_pda(), false)];
        metas.extend(
            self.trees
                .iter()
                .map(|tree| AccountMeta::new_readonly(tree.tree, false)),
        );
        metas.push(AccountMeta::new_readonly(
            ring.member_registry_root_pda(),
            false,
        ));
        metas.extend(
            self.foreign
                .map(|foreign| AccountMeta::new_readonly(foreign.registry, false)),
        );
        metas
    }

    fn foreign_root_indexes(&self) -> [u8; N_FOREIGN] {
        [self.foreign.map_or(0, |foreign| foreign.root_index)]
    }
}

/// `[config, cosigner_pda, cosigner]`, unset the co-signer slot repeats the PDA.
pub(crate) fn ring_prefix(ring: CustomRing, cosigner: Option<Address>) -> [AccountMeta; 3] {
    let pda = ring.cosigner_pda();
    [
        AccountMeta::new_readonly(ring.config_pda(), false),
        AccountMeta::new_readonly(pda, false),
        match cosigner {
            Some(cosigner) => AccountMeta::new_readonly(cosigner, true),
            None => AccountMeta::new_readonly(pda, false),
        },
    ]
}

/// `[config, cosigner_pda, cosigner]`, the policy reads, then SPP's
/// `RING_TRANSACT` list. The program signs `ring_config`.
#[must_use]
pub struct CustomRingTransact {
    pub ring: CustomRing,
    /// SPP's fee payer.
    pub payer: Address,
    /// One per input tree, in first-use order.
    pub input_trees: Vec<Address>,
    pub output_tree: Address,
    /// `None` for an audit-only ring.
    pub policy: Option<PolicyReads>,
    pub cosigner: Option<Address>,
    /// The eddsa owners of the spent UTXOs, each signs.
    pub owner_signers: Vec<Address>,
    /// Settlement accounts for the content's `interface_transfers`, in the same order.
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub proof: CustomRingProof,
    /// Its `messages` carry the auditor message the proof commits to.
    pub transact: TransactIxData,
    /// The dual control bit the outflow limits prove, the co-signer then signs.
    pub approval_required: bool,
}

/// The delegate rail runs on policy rings with key escrow on only.
#[must_use]
pub struct CustomRingDelegateTransact {
    pub ring: CustomRing,
    pub payer: Address,
    pub input_trees: Vec<Address>,
    pub output_tree: Address,
    pub policy: PolicyReads,
    pub cosigner: Option<Address>,
    pub delegate: Address,
    pub proof: CustomRingProof,
    pub transact: TransactIxData,
    pub approval_required: bool,
}

impl CustomRingTransact {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        self.instruction_with_policy_shape(false)
    }

    pub fn instruction_with_policy_shape(
        self,
        two_by_three: bool,
    ) -> Result<Instruction, RingError> {
        self.instruction_with_policy_kind(if two_by_three {
            custom_ring_interface::PolicyProofKind::TwoByThree
        } else {
            custom_ring_interface::PolicyProofKind::Legacy
        })
    }

    pub fn instruction_with_policy_kind(
        self,
        kind: custom_ring_interface::PolicyProofKind,
    ) -> Result<Instruction, RingError> {
        if kind.public_table() && self.policy.is_none() {
            return Err(RingError::PolicyShapeUnsupported);
        }
        if kind == custom_ring_interface::PolicyProofKind::TwoByThree
            && (self.policy.is_none()
                || self.transact.inputs.len() != 2
                || self.transact.outputs.len() != 3)
        {
            return Err(RingError::PolicyShapeUnsupported);
        }
        let spp = RingTransact {
            payer: self.payer,
            input_trees: self.input_trees,
            output_tree: self.output_tree,
            ring_program_id: self.ring.program_id(),
            owner_signers: self.owner_signers,
            interface_transfer_accounts: self.interface_transfer_accounts,
            data: self.transact,
        };
        RingStatement {
            ring: self.ring,
            cosigner: self.cosigner,
            policy: self.policy.as_ref(),
            approval_required: self.approval_required,
            proof: self.proof,
        }
        .instruction(
            match kind {
                custom_ring_interface::PolicyProofKind::Legacy => tag::TRANSACT,
                custom_ring_interface::PolicyProofKind::TwoByThree => tag::TRANSACT_TWO_BY_THREE,
                custom_ring_interface::PolicyProofKind::General => tag::TRANSACT_SHAPED,
                custom_ring_interface::PolicyProofKind::Subtree => tag::TRANSACT_SHAPED_SUBTREE,
            },
            Vec::new(),
            spp.instruction().accounts,
            spp.data,
        )
    }
}

impl CustomRingDelegateTransact {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        self.instruction_with_policy_shape(false)
    }

    pub fn instruction_with_policy_shape(
        self,
        two_by_three: bool,
    ) -> Result<Instruction, RingError> {
        self.instruction_with_policy_kind(if two_by_three {
            custom_ring_interface::PolicyProofKind::TwoByThree
        } else {
            custom_ring_interface::PolicyProofKind::Legacy
        })
    }

    pub fn instruction_with_policy_kind(
        self,
        kind: custom_ring_interface::PolicyProofKind,
    ) -> Result<Instruction, RingError> {
        if kind == custom_ring_interface::PolicyProofKind::TwoByThree
            && (self.transact.inputs.len() != 2 || self.transact.outputs.len() != 3)
        {
            return Err(RingError::PolicyShapeUnsupported);
        }
        if !self.transact.interface_transfers.is_empty() {
            return Err(RingError::DelegatePublicLeg);
        }
        let spp = RingAuthorityTransact {
            payer: self.payer,
            input_trees: self.input_trees,
            output_tree: self.output_tree,
            ring_program_id: self.ring.program_id(),
            interface_transfer_accounts: Vec::new(),
            data: self.transact,
        };
        let delegate = vec![
            AccountMeta::new_readonly(self.ring.delegate_pda(), false),
            AccountMeta::new_readonly(self.delegate, true),
        ];
        RingStatement {
            ring: self.ring,
            cosigner: self.cosigner,
            policy: Some(&self.policy),
            approval_required: self.approval_required,
            proof: self.proof,
        }
        .instruction(
            match kind {
                custom_ring_interface::PolicyProofKind::Legacy => tag::DELEGATE_TRANSACT,
                custom_ring_interface::PolicyProofKind::TwoByThree => {
                    tag::DELEGATE_TRANSACT_TWO_BY_THREE
                }
                custom_ring_interface::PolicyProofKind::General => tag::DELEGATE_TRANSACT_SHAPED,
                custom_ring_interface::PolicyProofKind::Subtree => {
                    tag::DELEGATE_TRANSACT_SHAPED_SUBTREE
                }
            },
            delegate,
            spp.instruction().accounts,
            spp.data,
        )
    }
}

struct RingStatement<'a> {
    ring: CustomRing,
    cosigner: Option<Address>,
    policy: Option<&'a PolicyReads>,
    approval_required: bool,
    proof: CustomRingProof,
}

impl RingStatement<'_> {
    /// `rail` sits between the prefix and the policy reads, `forwarded` after them.
    fn instruction(
        self,
        instruction_tag: u8,
        rail: Vec<AccountMeta>,
        forwarded: Vec<AccountMeta>,
        transact: TransactIxData,
    ) -> Result<Instruction, RingError> {
        if self.approval_required && self.cosigner.is_none() {
            return Err(RingError::ApprovalWithoutCoSigner);
        }
        let mut accounts = ring_prefix(self.ring, self.cosigner).to_vec();
        accounts.extend(rail);
        if let Some(policy) = self.policy {
            accounts.extend(policy.metas(self.ring));
        }
        accounts.extend(forwarded);
        let policy = self.policy;
        let mut data = vec![instruction_tag];
        data.extend(wincode::serialize(&CustomRingTransactIxData {
            proof: self.proof,
            policy_trees: policy
                .map(|policy| policy.trees.iter().map(|tree| tree.context).collect())
                .unwrap_or_default(),
            registry_root_index: policy.map_or(0, |policy| policy.registry.root_index),
            foreign_root_indexes: policy.map_or([0; N_FOREIGN], PolicyReads::foreign_root_indexes),
            approval_required: self.approval_required,
            transact,
        })?);
        Ok(Instruction {
            program_id: self.ring.program_id(),
            accounts,
            data,
        })
    }
}
