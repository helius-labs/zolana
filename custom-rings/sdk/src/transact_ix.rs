use custom_ring_interface::{tag, CustomRingProof, CustomRingTransactIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::{
    instruction::{instruction_data::transact::TreeContext, TransactIxData},
    pda,
};
use zolana_program::instruction::{
    RingAuthorityTransact, RingTransact, TransactInterfaceTransferAccounts,
};
use zolana_ring_policy::ANSWER_SLOTS;
use zolana_transaction::SOL_MINT;

use crate::{CurrentKeyRegistryRoot, CustomRing, RingError};

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
    /// The program accepts any root its history still holds.
    Registry { root: [u8; 32] },
}

impl EscrowBinding {
    pub(crate) fn of(root: Option<CurrentKeyRegistryRoot>) -> Self {
        root.map_or(Self::Off, |root| Self::Registry { root: root.root })
    }

    pub(crate) const fn root(self) -> Option<[u8; 32]> {
        match self {
            Self::Off => None,
            Self::Registry { root } => Some(root),
        }
    }

    pub(crate) fn meta(self, ring: CustomRing) -> Option<AccountMeta> {
        (self != Self::Off).then(|| AccountMeta::new_readonly(ring.key_registry_root_pda(), false))
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
    fn metas(&self, ring: CustomRing) -> Result<Vec<AccountMeta>, RingError> {
        let mut metas = vec![AccountMeta::new_readonly(ring.policy_config_pda(), false)];
        metas.extend(
            self.trees
                .iter()
                .map(|tree| AccountMeta::new_readonly(tree.tree, false)),
        );
        metas.extend(self.escrow.meta(ring));
        let targets = self
            .revocation_targets
            .iter()
            .zip(&self.revocation_tree_indexes);
        for (slot, (target, &index)) in targets.enumerate() {
            if *target == [0; 32] {
                continue;
            }
            let tree = self
                .trees
                .get(usize::from(index))
                .ok_or(RingError::RevocationTree {
                    slot,
                    index,
                    trees: self.trees.len(),
                })?;
            metas.push(AccountMeta::new_readonly(
                pda::nullifier_pda(&tree.tree, target).0,
                false,
            ));
        }
        Ok(metas)
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

/// One writable window slot per public leg, in leg order.
pub(crate) fn window_metas(
    ring: CustomRing,
    mints: impl IntoIterator<Item = Address>,
) -> impl Iterator<Item = AccountMeta> {
    mints
        .into_iter()
        .map(move |mint| AccountMeta::new(ring.spend_window_pda(&mint), false))
}

/// `[config, cosigner_pda, cosigner]`, the policy reads, one window per public
/// leg, then SPP's `RING_TRANSACT` list. The program signs `ring_config`.
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
    /// The dual control bit the velocity statement proves, the co-signer then signs.
    pub approval_required: bool,
    /// The window a windowed statement proves, zero otherwise.
    pub window_index: u64,
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
        let windows = window_metas(
            self.ring,
            self.interface_transfer_accounts.iter().map(settled_mint),
        )
        .collect::<Vec<_>>();
        let spp = RingTransact {
            payer: self.payer,
            input_trees: self.input_trees,
            output_tree: self.output_tree,
            ring_program_id: self.ring.program_id(),
            owner_signers: self.owner_signers,
            interface_transfer_accounts: self.interface_transfer_accounts,
            data: self.transact,
        };
        let namespace = self.ring.namespace_pda();
        let mut accounts = spp.instruction().accounts;
        // The program raises the namespace PDA as a signer inside its CPI.
        for meta in accounts.iter_mut().filter(|meta| meta.pubkey == namespace) {
            meta.is_signer = false;
        }
        accounts.splice(0..0, windows);
        RingStatement {
            ring: self.ring,
            cosigner: self.cosigner,
            policy: self.policy.as_ref(),
            approval_required: self.approval_required,
            window_index: self.window_index,
            proof: self.proof,
        }
        .instruction(tag::TRANSACT, Vec::new(), accounts, spp.data)
    }
}

impl CustomRingDelegateTransact {
    pub fn instruction(self) -> Result<Instruction, RingError> {
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
            window_index: 0,
            proof: self.proof,
        }
        .instruction(
            tag::DELEGATE_TRANSACT,
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
    window_index: u64,
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
            accounts.extend(policy.metas(self.ring)?);
        }
        accounts.extend(forwarded);
        let policy = self.policy;
        let mut data = vec![instruction_tag];
        data.extend(wincode::serialize(&CustomRingTransactIxData {
            proof: self.proof,
            policy_trees: policy
                .map(|policy| policy.trees.iter().map(|tree| tree.context).collect())
                .unwrap_or_default(),
            window_index: self.window_index,
            key_registry_root: policy.and_then(|policy| policy.escrow.root()),
            approval_required: self.approval_required,
            revocation_targets: policy
                .map_or([[0; 32]; ANSWER_SLOTS], |policy| policy.revocation_targets),
            revocation_tree_indexes: policy
                .map_or([0; ANSWER_SLOTS], |policy| policy.revocation_tree_indexes),
            transact,
        })?);
        Ok(Instruction {
            program_id: self.ring.program_id(),
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
