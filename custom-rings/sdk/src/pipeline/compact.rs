//! The compact transact data a proven transfer owns, and its instruction.

use custom_ring_interface::{
    stream::RingTag, tag, AnchorRoot, AnonymousProofData, CustomRingProof, InputTrees,
    PlainGroth16Proof, PolicyProof, RingOutput, RingProgramConfig, RingRail, RingTransactData,
    AUDIT_CIPHERTEXT_LEN, RING_DELIVERED_BODY_LEN,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::{
    instruction::{InterfaceTransfer, TransactProof},
    RING_TRANSACT_ACCOUNT_PREFIX_LEN,
};
use zolana_program::instruction::{
    RingAuthorityTransact, RingTransact, TransactInterfaceTransferAccounts,
};

use crate::{CustomRing, RingError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OwnedOutput {
    Packed {
        hash: [u8; 32],
        u: [u8; 32],
        ciphertext: Vec<u8>,
    },
    Delivered {
        hash: [u8; 32],
        u: [u8; 32],
        body: [u8; RING_DELIVERED_BODY_LEN],
    },
    Anonymous {
        hash: [u8; 32],
        tag: RingTag,
        body: [u8; RING_DELIVERED_BODY_LEN],
    },
    Exit {
        hash: [u8; 32],
        owner_tag: [u8; 32],
        payload: Vec<u8>,
    },
}

impl OwnedOutput {
    pub fn of(output: RingOutput<'_>) -> Self {
        match output {
            RingOutput::Packed {
                hash,
                u,
                ciphertext,
            } => Self::Packed {
                hash: *hash,
                u: *u,
                ciphertext: ciphertext.to_vec(),
            },
            RingOutput::Delivered { hash, u, body } => Self::Delivered {
                hash: *hash,
                u: *u,
                body: *body,
            },
            RingOutput::Anonymous { hash, tag, body } => Self::Anonymous {
                hash: *hash,
                tag,
                body: *body,
            },
            RingOutput::Exit {
                hash,
                owner_tag,
                payload,
            } => Self::Exit {
                hash: *hash,
                owner_tag: *owner_tag,
                payload: payload.to_vec(),
            },
        }
    }

    pub fn view(&self) -> RingOutput<'_> {
        match self {
            Self::Packed {
                hash,
                u,
                ciphertext,
            } => RingOutput::Packed {
                hash,
                u,
                ciphertext,
            },
            Self::Delivered { hash, u, body } => RingOutput::Delivered { hash, u, body },
            Self::Anonymous { hash, tag, body } => RingOutput::Anonymous {
                hash,
                tag: *tag,
                body,
            },
            Self::Exit {
                hash,
                owner_tag,
                payload,
            } => RingOutput::Exit {
                hash,
                owner_tag,
                payload,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnedPolicyProof {
    pub proof: CustomRingProof,
    pub own_root_index: u8,
    pub curator_root_index: Option<u8>,
    pub sender_commitment: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnedAnonymousProofData {
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
    pub default_owner_tag: Option<[u8; 32]>,
}

/// [`RingTransactData`] with every borrowed part owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransactParts {
    pub rail: RingRail,
    pub n_in: u8,
    pub n_out: u8,
    pub audit_proof: CustomRingProof,
    pub policy: Option<OwnedPolicyProof>,
    pub approval_required: bool,
    pub previous_epoch: bool,
    pub anchor: Option<AnchorRoot>,
    pub expiry_unix_ts: u32,
    pub tx_viewing_u: [u8; 32],
    pub salt: [u8; 16],
    pub interface_transfers: Vec<InterfaceTransfer>,
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    pub data_free: bool,
    pub key_escrow: bool,
    pub full_openings: bool,
    pub outputs: Vec<OwnedOutput>,
    pub eph_u: [u8; 32],
    pub sealed: [u8; AUDIT_CIPHERTEXT_LEN],
    pub disclosure: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    pub anonymous: Option<OwnedAnonymousProofData>,
    pub spp_proof: PlainGroth16Proof,
    pub nullifiers: Vec<[u8; 32]>,
    pub input_trees: InputTrees,
}

impl TransactParts {
    pub fn data(&self) -> RingTransactData<'_> {
        RingTransactData {
            rail: self.rail,
            n_in: self.n_in,
            n_out: self.n_out,
            audit_proof: &self.audit_proof,
            policy: self.policy.as_ref().map(|policy| PolicyProof {
                proof: &policy.proof,
                own_root_index: policy.own_root_index,
                curator_root_index: policy.curator_root_index,
                sender_commitment: policy.sender_commitment.as_ref(),
            }),
            approval_required: self.approval_required,
            previous_epoch: self.previous_epoch,
            anchor: self.anchor,
            expiry_unix_ts: self.expiry_unix_ts,
            tx_viewing_u: &self.tx_viewing_u,
            salt: &self.salt,
            interface_transfers: self.interface_transfers.clone(),
            data_hash: self.data_hash.as_ref(),
            ring_data_hash: self.ring_data_hash.as_ref(),
            data_free: self.data_free,
            key_escrow: self.key_escrow,
            full_openings: self.full_openings,
            outputs: self.outputs.iter().map(OwnedOutput::view).collect(),
            eph_u: &self.eph_u,
            sealed: &self.sealed,
            disclosure: &self.disclosure,
            private_tx_hash: &self.private_tx_hash,
            anonymous: self.anonymous.as_ref().map(|anonymous| AnonymousProofData {
                commitment: &anonymous.commitment,
                commitment_pok: &anonymous.commitment_pok,
                default_owner_tag: anonymous.default_owner_tag.as_ref(),
            }),
            spp_proof: &self.spp_proof,
            nullifiers: &self.nullifiers,
            input_trees: self.input_trees,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransactAccounts {
    pub payer: Address,
    /// One per tree context, in the data's order.
    pub input_trees: Vec<Address>,
    pub output_tree: Address,
    /// Only the confidential rail names owner signers.
    pub owner_signers: Vec<Address>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    /// Set exactly on a policy ring.
    pub registry: Option<Address>,
    pub curator: Option<Address>,
    pub co_signer: Option<Address>,
    pub delegate: Option<Address>,
    /// The first-contact tree of a pair-anchored anonymous payment.
    pub anchor_tree: Option<Address>,
}

impl TransactAccounts {
    /// The anchor tree's account index, in SPP's list or the prefix slot after the delegate.
    pub fn anchor_slot(&self) -> Option<u8> {
        let tree = self.anchor_tree?;
        let prefix = 1
            + usize::from(self.registry.is_some())
            + usize::from(self.curator.is_some())
            + usize::from(self.co_signer.is_some())
            + usize::from(self.delegate.is_some());
        u8::try_from(self.spp_slot(tree).map_or(prefix, |slot| prefix + slot)).ok()
    }

    /// `None` for a tree SPP's own account list does not name.
    fn spp_slot(&self, tree: Address) -> Option<usize> {
        match tree == self.output_tree {
            true => Some(1),
            false => self
                .input_trees
                .iter()
                .position(|input| *input == tree)
                .map(|index| RING_TRANSACT_ACCOUNT_PREFIX_LEN + index),
        }
    }

    /// The ring prefix, then SPP's own list, the data's tag by its rail.
    pub fn instruction(
        &self,
        ring: CustomRing,
        config: &RingProgramConfig,
        parts: &TransactParts,
    ) -> Result<Instruction, RingError> {
        let data = parts.data();
        let expanded = data.transact_ix_data(config, TransactProof::zeroed())?;
        let spp = match parts.rail {
            RingRail::Delegate => {
                RingAuthorityTransact {
                    payer: self.payer,
                    input_trees: self.input_trees.clone(),
                    output_tree: self.output_tree,
                    ring_program_id: ring.program_id(),
                    interface_transfer_accounts: Vec::new(),
                    data: expanded,
                }
                .instruction()
                .accounts
            }
            RingRail::Confidential | RingRail::Anonymous => {
                RingTransact {
                    payer: self.payer,
                    input_trees: self.input_trees.clone(),
                    output_tree: self.output_tree,
                    ring_program_id: ring.program_id(),
                    owner_signers: self.owner_signers.clone(),
                    interface_transfer_accounts: self.interface_transfer_accounts.clone(),
                    data: expanded,
                }
                .instruction()
                .accounts
            }
        };
        let mut accounts = vec![AccountMeta::new_readonly(ring.config_pda(), false)];
        accounts.extend(
            self.registry
                .map(|registry| AccountMeta::new_readonly(registry, false)),
        );
        accounts.extend(
            self.curator
                .map(|curator| AccountMeta::new_readonly(curator, false)),
        );
        accounts.extend(
            self.co_signer
                .map(|co_signer| AccountMeta::new_readonly(co_signer, true)),
        );
        accounts.extend(
            self.delegate
                .map(|delegate| AccountMeta::new_readonly(delegate, true)),
        );
        accounts.extend(
            self.anchor_tree
                .filter(|tree| self.spp_slot(*tree).is_none())
                .map(|tree| AccountMeta::new_readonly(tree, false)),
        );
        accounts.extend(spp);
        let mut bytes = vec![match parts.rail {
            RingRail::Delegate => tag::DELEGATE_TRANSACT,
            RingRail::Confidential | RingRail::Anonymous => tag::TRANSACT,
        }];
        bytes.extend(data.encode()?);
        Ok(Instruction {
            program_id: ring.program_id(),
            accounts,
            data: bytes,
        })
    }
}
