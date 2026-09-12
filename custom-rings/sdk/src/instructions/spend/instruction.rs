use custom_ring_interface::{tag, RegisterSpendIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_client::{ClientError, ProverClient, Rpc};
use zolana_interface::{pda, SHIELDED_POOL_PROGRAM_ID};
use zolana_ring_policy::{spend_seed, ListNamespace, Member, SpendCounters, SpendRecord};

use crate::{
    instructions::entry::{EntryError, EntryProof, EntryProofError, InputSlot, NamespaceWrite},
    instructions::spend::ReadSpendRecord,
    policy_config_table, CustomRing,
};

/// Claims the payer's record at version zero, once per member.
#[must_use]
pub struct RegisterSpend {
    pub ring: CustomRing,
    pub payer: Address,
}

/// The connections one registration proof needs.
pub struct SpendProofEnvironment<'a, I: Rpc, R: Rpc> {
    pub indexer: &'a I,
    pub rpc: &'a R,
    pub prover: &'a ProverClient,
}

impl RegisterSpend {
    /// A window boundary crossed between proving and execution fails the proof.
    pub fn prove<I: Rpc, R: Rpc>(
        self,
        environment: SpendProofEnvironment<'_, I, R>,
    ) -> Result<ProvenSpendRegistration, EntryError> {
        let policy_config = self
            .ring
            .read_policy_config(environment.rpc)?
            .ok_or(EntryError::MissingPolicyConfig)?;
        let window_slots = policy_config_table(&policy_config)?.window_slots();
        if window_slots == 0 {
            return Err(EntryError::VelocityDisabled);
        }
        let namespace = self.ring.namespace_pda();
        let owner = ListNamespace::new(namespace.as_array()).map_err(|_| EntryError::Hashing)?;
        let member = Member::owner_tag(self.payer.as_array()).map_err(|_| EntryError::Hashing)?;
        let entries_tree_id = policy_config.entries_tree_id();
        let registered = ReadSpendRecord {
            entries_tree: policy_config.entries_tree,
            entries_tree_id,
            namespace,
            member,
        }
        .read(environment.indexer)?;
        if registered.is_some() {
            return Err(EntryError::SpendRecordExists);
        }
        let slot = environment
            .rpc
            .get_slot()
            .map_err(|error| EntryProofError::Client(Box::new(error)))?;
        let address = owner
            .spend_address(&member, entries_tree_id)
            .map_err(|_| EntryError::Hashing)?;
        let seed = spend_seed(&member).map_err(|_| EntryError::Hashing)?;
        let draft = SpendRecord {
            member,
            version: 0,
            window: slot / window_slots,
            counters_commitment: SpendCounters::zero(&[])
                .commitment()
                .map_err(|_| EntryError::Hashing)?,
            blinding: [0u8; 32],
        };
        let output_data_hash = draft.data_hash(&address).map_err(|_| EntryError::Hashing)?;
        let (blinding, proof) = NamespaceWrite {
            owner: &owner,
            namespace,
            entries_tree: policy_config.entries_tree,
            entries_tree_id,
            payer: self.payer,
            slot: InputSlot::claim(&owner, seed, address, entries_tree_id)?,
            output_data_hash,
        }
        .prove(
            environment.indexer,
            environment.rpc,
            environment.prover,
            |blinding| SpendRecord { blinding, ..draft }.to_output_data().to_vec(),
        )?;
        Ok(ProvenSpendRegistration {
            ring: self.ring,
            payer: self.payer,
            entries_tree: policy_config.entries_tree,
            record: SpendRecord { blinding, ..draft },
            proof,
        })
    }
}

/// A proven registration, ready to become one instruction.
#[must_use]
pub struct ProvenSpendRegistration {
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
            // The entry mutation layout, everything after the two config
            // accounts is forwarded to SPP position for position.
            accounts: vec![
                AccountMeta::new_readonly(ring.config_pda(), false),
                AccountMeta::new_readonly(ring.policy_config_pda(), false),
                AccountMeta::new(payer, true),
                AccountMeta::new(entries_tree, false),
                AccountMeta::new(entries_tree, false),
                AccountMeta::new_readonly(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
                AccountMeta::new_readonly(Address::default(), false),
                AccountMeta::new(pda::nullifier_pda(&entries_tree, &proof.nullifier).0, false),
                AccountMeta::new_readonly(ring.namespace_pda(), false),
                AccountMeta::new(ring.spend_record_head_pda(record.member.as_bytes()), false),
            ],
            data,
        })
    }
}

impl From<ClientError> for EntryError {
    fn from(error: ClientError) -> Self {
        Self::Proof(EntryProofError::Client(Box::new(error)))
    }
}
