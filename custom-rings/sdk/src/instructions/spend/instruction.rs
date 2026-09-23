#[cfg(feature = "solana-rpc")]
use crate::instructions::transact::ProvedWindow;
use custom_ring_interface::{tag, PolicyConfig, RegisterSpendIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_client::{AsyncRpc, Rpc};
use zolana_interface::{pda, SHIELDED_POOL_PROGRAM_ID};
use zolana_ring_policy::{spend_seed, ListNamespace, Member, SpendCounters, SpendRecord};

use crate::{
    instructions::entry::{AddressClaim, EntryError, EntryProof, NamespaceProof, NamespaceWrite},
    policy_config_table, AsyncTransferProofEnvironment, CustomRing, TransferProofEnvironment,
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
        let policy = self
            .ring
            .read_policy_config(env.rpc)?
            .ok_or(EntryError::MissingPolicyConfig)?;
        let draft = self.draft(policy, env.rpc.get_slot()?)?;
        let entry = draft.write()?.prove(env, |blinding| {
            draft.record(blinding).to_output_data().to_vec()
        })?;
        Ok(draft.finish(entry))
    }

    pub async fn prove_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: AsyncTransferProofEnvironment<'_, I, R>,
    ) -> Result<ProvenSpendRegistration, EntryError> {
        let policy = self
            .ring
            .read_policy_config_async(env.rpc)
            .await?
            .ok_or(EntryError::MissingPolicyConfig)?;
        let draft = self.draft(policy, env.rpc.get_slot().await?)?;
        let entry = draft
            .write()?
            .prove_async(env, |blinding| {
                draft.record(blinding).to_output_data().to_vec()
            })
            .await?;
        Ok(draft.finish(entry))
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

    fn finish(self, entry: NamespaceProof) -> ProvenSpendRegistration {
        ProvenSpendRegistration {
            #[cfg(feature = "solana-rpc")]
            window: ProvedWindow {
                slots: self.window_slots,
                index: self.record.window,
            },
            ring: self.registration.ring,
            payer: self.registration.payer,
            entries_tree: self.policy.entries_tree,
            record: self.record(entry.blinding),
            proof: entry.proof,
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
            ],
            data,
        })
    }
}
