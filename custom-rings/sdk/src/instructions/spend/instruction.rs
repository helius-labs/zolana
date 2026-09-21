#[cfg(feature = "solana-rpc")]
use crate::instructions::transact::ProvedWindow;
use custom_ring_interface::{
    tag, HeadMapTransition, PlainGroth16Proof, PolicyConfig, RegisterSpendIxData,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_client::{AsyncRpc, Rpc};
use zolana_interface::{pda, SHIELDED_POOL_PROGRAM_ID};
use zolana_ring_policy::{
    entry_nullifier, spend_seed, ListNamespace, Member, SpendCounters, SpendRecord,
};

use crate::{
    head_map::{HeadRegistration, RegisterHead},
    instructions::entry::{
        AddressClaim, EntryError, EntryProof, EntryProofError, NamespaceProof, NamespaceWrite,
    },
    policy_config_table, to_plain_proof, AsyncTransferProofEnvironment, CustomRing,
    TransferProofEnvironment,
};

#[must_use]
#[derive(Clone, Copy)]
pub struct RegisterSpend {
    pub ring: CustomRing,
    pub payer: Address,
}

impl RegisterSpend {
    /// A window boundary crossed between proving and execution fails the proof.
    pub fn prove<I: Rpc, R: Rpc>(
        self,
        env: TransferProofEnvironment<'_, I, R>,
    ) -> Result<ProvenSpendRegistration, EntryError> {
        let TransferProofEnvironment {
            indexer,
            rpc,
            prover,
        } = env;
        let policy = self
            .ring
            .read_policy_config(rpc)?
            .ok_or(EntryError::MissingPolicyConfig)?;
        let draft = self.draft(policy, rpc.get_slot()?)?;
        let head = self
            .ring
            .read_head_map_root(rpc)?
            .ok_or(EntryProofError::MissingHeadMap)?;
        let query = self.ring.member_proof_request(&draft.record.member, head);
        let head_witness = indexer.get_ring_head_register_proof(query.clone())?;
        let entry = draft.write()?.prove(
            TransferProofEnvironment {
                indexer,
                rpc,
                prover,
            },
            |blinding| draft.record(blinding).to_output_data().to_vec(),
        )?;
        let HeadRegistration {
            request,
            transition,
        } = RegisterHead {
            query: &query,
            response: head_witness,
            genesis: draft.genesis(entry.blinding)?,
        }
        .prepare()?;
        let head_proof = to_plain_proof(prover.prove(&request)?)?;
        Ok(draft.finish(RegistrationProofs {
            entry,
            head_transition: transition,
            head_next_index: head.next_index,
            head_proof,
        }))
    }

    pub async fn prove_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: AsyncTransferProofEnvironment<'_, I, R>,
    ) -> Result<ProvenSpendRegistration, EntryError> {
        let AsyncTransferProofEnvironment {
            indexer,
            rpc,
            prover,
        } = env;
        let policy = self
            .ring
            .read_policy_config_async(rpc)
            .await?
            .ok_or(EntryError::MissingPolicyConfig)?;
        let draft = self.draft(policy, rpc.get_slot().await?)?;
        let head = self
            .ring
            .read_head_map_root_async(rpc)
            .await?
            .ok_or(EntryProofError::MissingHeadMap)?;
        let query = self.ring.member_proof_request(&draft.record.member, head);
        let head_witness = indexer.get_ring_head_register_proof(query.clone()).await?;
        let entry = draft
            .write()?
            .prove_async(
                AsyncTransferProofEnvironment {
                    indexer,
                    rpc,
                    prover,
                },
                |blinding| draft.record(blinding).to_output_data().to_vec(),
            )
            .await?;
        let HeadRegistration {
            request,
            transition,
        } = RegisterHead {
            query: &query,
            response: head_witness,
            genesis: draft.genesis(entry.blinding)?,
        }
        .prepare()?;
        let head_proof = to_plain_proof(prover.prove(&request).await?)?;
        Ok(draft.finish(RegistrationProofs {
            entry,
            head_transition: transition,
            head_next_index: head.next_index,
            head_proof,
        }))
    }

    fn draft(self, policy: PolicyConfig, slot: u64) -> Result<RegistrationDraft, EntryError> {
        let window_slots = policy_config_table(&policy)?.window_slots();
        if window_slots == 0 {
            return Err(EntryError::VelocityDisabled);
        }
        let owner = ListNamespace::new(self.ring.namespace_pda().as_array())
            .map_err(|_| EntryError::Hashing)?;
        let member = Member::owner_tag(self.payer.as_array()).map_err(|_| EntryError::Hashing)?;
        let address = owner
            .spend_address(&member, policy.entries_tree_id())
            .map_err(|_| EntryError::Hashing)?;
        let record = SpendRecord {
            member,
            version: 0,
            window: slot / window_slots,
            blinding: [0; 32],
            counters_commitment: SpendCounters::EMPTY
                .commitment()
                .map_err(|_| EntryError::Hashing)?,
        };
        Ok(RegistrationDraft {
            #[cfg(feature = "solana-rpc")]
            window_slots,
            registration: self,
            policy,
            owner,
            address,
            record,
        })
    }
}

struct RegistrationDraft {
    #[cfg(feature = "solana-rpc")]
    window_slots: u64,
    registration: RegisterSpend,
    policy: PolicyConfig,
    owner: ListNamespace,
    address: [u8; 32],
    record: SpendRecord,
}

struct RegistrationProofs {
    entry: NamespaceProof,
    head_transition: HeadMapTransition,
    head_next_index: u64,
    head_proof: PlainGroth16Proof,
}

impl RegistrationDraft {
    fn record(&self, blinding: [u8; 32]) -> SpendRecord {
        SpendRecord {
            blinding,
            ..self.record
        }
    }

    fn write(&self) -> Result<NamespaceWrite<'_>, EntryError> {
        let seed = spend_seed(&self.record.member).map_err(|_| EntryError::Hashing)?;
        Ok(NamespaceWrite {
            owner: &self.owner,
            namespace: self.registration.ring.namespace_pda(),
            entries_tree: self.policy.entries_tree,
            entries_tree_id: self.policy.entries_tree_id(),
            payer: self.registration.payer,
            slot: AddressClaim {
                owner: &self.owner,
                seed,
                address: self.address,
                tree_id: self.policy.entries_tree_id(),
            }
            .slot()?,
            output_data_hash: self
                .record
                .data_hash(&self.address)
                .map_err(|_| EntryError::Hashing)?,
        })
    }

    fn genesis(&self, blinding: [u8; 32]) -> Result<[u8; 32], EntryError> {
        let hash = self
            .record(blinding)
            .utxo_hash(&self.owner, &self.address, self.policy.entries_tree_id())
            .map_err(|_| EntryError::Hashing)?;
        entry_nullifier(&hash, &blinding).map_err(|_| EntryError::Hashing)
    }

    fn finish(self, proofs: RegistrationProofs) -> ProvenSpendRegistration {
        ProvenSpendRegistration {
            #[cfg(feature = "solana-rpc")]
            window: ProvedWindow {
                slots: self.window_slots,
                index: self.record.window,
            },
            ring: self.registration.ring,
            payer: self.registration.payer,
            entries_tree: self.policy.entries_tree,
            record: self.record(proofs.entry.blinding),
            proof: proofs.entry.proof,
            head_transition: proofs.head_transition,
            head_next_index: proofs.head_next_index,
            head_proof: proofs.head_proof,
        }
    }
}

#[must_use]
pub struct ProvenSpendRegistration {
    #[cfg(feature = "solana-rpc")]
    pub(crate) window: ProvedWindow,
    ring: CustomRing,
    payer: Address,
    entries_tree: Address,
    record: SpendRecord,
    proof: EntryProof,
    head_transition: HeadMapTransition,
    head_next_index: u64,
    head_proof: PlainGroth16Proof,
}

impl ProvenSpendRegistration {
    pub const fn record(&self) -> SpendRecord {
        self.record
    }

    pub fn instruction(self) -> Result<Instruction, EntryError> {
        let Self {
            ring,
            payer,
            entries_tree,
            record,
            proof,
            head_transition,
            head_next_index,
            head_proof,
            #[cfg(feature = "solana-rpc")]
                window: _,
        } = self;
        let mut data = vec![tag::REGISTER_SPEND];
        data.extend_from_slice(&wincode::serialize(&RegisterSpendIxData {
            blinding: record.blinding,
            private_tx_blinding: proof.private_tx_blinding,
            nullifier_tree_root_index: proof.nullifier_tree_root_index,
            utxo_tree_root_index: proof.utxo_tree_root_index,
            proof: proof.proof,
            head_old_root: head_transition.old_root,
            head_new_root: head_transition.new_root,
            head_next_index,
            head_proof,
        })?);
        Ok(Instruction {
            program_id: ring.program_id(),
            accounts: vec![
                AccountMeta::new_readonly(ring.config_pda(), false),
                AccountMeta::new_readonly(ring.policy_config_pda(), false),
                AccountMeta::new(payer, true),
                AccountMeta::new(entries_tree, false),
                AccountMeta::new_readonly(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
                AccountMeta::new_readonly(Address::default(), false),
                AccountMeta::new(entries_tree, false),
                AccountMeta::new(pda::nullifier_pda(&entries_tree, &proof.nullifier).0, false),
                AccountMeta::new_readonly(ring.namespace_pda(), false),
                AccountMeta::new(ring.head_map_root_pda(), false),
            ],
            data,
        })
    }
}
