use custom_ring_interface::{tag, RegisterSpendIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_client::{AsyncProverClient, AsyncRpc, ClientError, ProverClient, Rpc};
use zolana_interface::{pda, SHIELDED_POOL_PROGRAM_ID};
use zolana_ring_policy::{
    entry_nullifier, spend_seed, ListNamespace, Member, SpendCounters, SpendRecord,
};

use crate::{
    instructions::entry::{EntryError, EntryProof, EntryProofError, InputSlot, NamespaceWrite},
    policy_config_table, CustomRing,
};

/// Registers the payer's zero-counter record in SPP and the ring's current-record map.
#[must_use]
#[derive(Clone, Copy)]
pub struct RegisterSpend {
    pub ring: CustomRing,
    pub payer: Address,
}

/// Supplies chain state and provers for record creation and head-map insertion.
pub struct SpendProofEnvironment<'a, I: Rpc, R: Rpc> {
    pub indexer: &'a I,
    pub rpc: &'a R,
    pub prover: &'a ProverClient,
}

/// Supplies asynchronous chain reads and provers for both registration statements.
pub struct AsyncSpendProofEnvironment<'a, I: AsyncRpc, R: AsyncRpc> {
    pub indexer: &'a I,
    pub rpc: &'a R,
    pub prover: &'a AsyncProverClient,
}

impl RegisterSpend {
    /// A window boundary crossed between proving and execution fails the proof.
    pub fn prove<I: Rpc, R: Rpc>(
        self,
        environment: SpendProofEnvironment<'_, I, R>,
    ) -> Result<ProvenSpendRegistration, EntryError> {
        // 1. Bind registration to the configured namespace, current window and current head root.
        let policy_config = self
            .ring
            .read_policy_config(environment.rpc)?
            .ok_or(EntryError::MissingPolicyConfig)?;
        let draft = RegistrationDraft::new(self, policy_config, environment.rpc.get_slot()?)?;
        let head = self
            .ring
            .read_head_map_root(environment.rpc)?
            .ok_or(EntryProofError::MissingHeadMap)?;
        let query = crate::head_map::request(self.ring, draft.record.member.as_bytes(), &head);
        let head_witness = environment
            .indexer
            .get_ring_head_register_proof(query.clone())?;
        // 2. Prove the SPP address claim and creation of its zero-counter record.
        let (blinding, proof) = draft.write()?.prove(
            environment.indexer,
            environment.rpc,
            environment.prover,
            |blinding| draft.record(blinding).to_output_data().to_vec(),
        )?;
        // 3. Insert that record's nullifier into the shared map under the separate ring proof.
        let genesis = draft.genesis(blinding)?;
        let (request, head_transition) =
            crate::head_map::RegisterProofRequest::build(&query, head_witness, &genesis)?;
        let head_proof = plain_proof(environment.prover.prove(&request)?)?;
        Ok(draft.finish(
            blinding,
            proof,
            head_transition,
            head.next_index(),
            head_proof,
        ))
    }

    pub async fn prove_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        environment: AsyncSpendProofEnvironment<'_, I, R>,
    ) -> Result<ProvenSpendRegistration, EntryError> {
        // 1. Bind registration to the configured namespace, current window and current head root.
        let policy = self
            .ring
            .read_policy_config_async(environment.rpc)
            .await?
            .ok_or(EntryError::MissingPolicyConfig)?;
        let draft = RegistrationDraft::new(self, policy, environment.rpc.get_slot().await?)?;
        let head = self
            .ring
            .read_head_map_root_async(environment.rpc)
            .await?
            .ok_or(EntryProofError::MissingHeadMap)?;
        let query = crate::head_map::request(self.ring, draft.record.member.as_bytes(), &head);
        let head_witness = environment
            .indexer
            .get_ring_head_register_proof(query.clone())
            .await?;
        // 2. Prove the SPP address claim and creation of its zero-counter record.
        let (blinding, proof) = draft
            .write()?
            .prove_async(
                environment.indexer,
                environment.rpc,
                environment.prover,
                |blinding| draft.record(blinding).to_output_data().to_vec(),
            )
            .await?;
        // 3. Insert that record's nullifier into the shared map under the separate ring proof.
        let genesis = draft.genesis(blinding)?;
        let (request, head_transition) =
            crate::head_map::RegisterProofRequest::build(&query, head_witness, &genesis)?;
        let head_proof = plain_proof(environment.prover.prove(&request).await?)?;
        Ok(draft.finish(
            blinding,
            proof,
            head_transition,
            head.next_index(),
            head_proof,
        ))
    }
}

/// Fixes the initial record identity and counters before SPP derives its output blinding.
struct RegistrationDraft {
    registration: RegisterSpend,
    policy: custom_ring_interface::PolicyConfig,
    owner: ListNamespace,
    address: [u8; 32],
    record: SpendRecord,
}

impl RegistrationDraft {
    fn new(
        registration: RegisterSpend,
        policy: custom_ring_interface::PolicyConfig,
        slot: u64,
    ) -> Result<Self, EntryError> {
        let window_slots = policy_config_table(&policy)?.window_slots();
        if window_slots == 0 {
            return Err(EntryError::VelocityDisabled);
        }
        let owner = ListNamespace::new(registration.ring.namespace_pda().as_array())
            .map_err(|_| EntryError::Hashing)?;
        let member =
            Member::owner_tag(registration.payer.as_array()).map_err(|_| EntryError::Hashing)?;
        let address = owner
            .spend_address(&member, policy.entries_tree_id())
            .map_err(|_| EntryError::Hashing)?;
        let record = SpendRecord {
            member,
            version: 0,
            window: slot / window_slots,
            blinding: [0; 32],
            counters_commitment: SpendCounters::zero(&[])
                .commitment()
                .map_err(|_| EntryError::Hashing)?,
        };
        Ok(Self {
            registration,
            policy,
            owner,
            address,
            record,
        })
    }

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
            slot: InputSlot::claim(
                &self.owner,
                seed,
                self.address,
                self.policy.entries_tree_id(),
            )?,
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

    fn finish(
        self,
        blinding: [u8; 32],
        proof: EntryProof,
        head_transition: custom_ring_interface::HeadMapTransition,
        head_next_index: u64,
        head_proof: custom_ring_interface::PlainGroth16Proof,
    ) -> ProvenSpendRegistration {
        ProvenSpendRegistration {
            ring: self.registration.ring,
            payer: self.registration.payer,
            entries_tree: self.policy.entries_tree,
            record: self.record(blinding),
            proof,
            head_transition,
            head_next_index,
            head_proof,
        }
    }
}

/// Combines SPP record creation and current-record insertion for atomic execution.
#[must_use]
pub struct ProvenSpendRegistration {
    ring: CustomRing,
    payer: Address,
    entries_tree: Address,
    record: SpendRecord,
    proof: EntryProof,
    head_transition: custom_ring_interface::HeadMapTransition,
    head_next_index: u64,
    head_proof: custom_ring_interface::PlainGroth16Proof,
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

fn plain_proof(
    proof: zolana_client::Proof,
) -> Result<custom_ring_interface::PlainGroth16Proof, EntryError> {
    use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};
    if proof.commitment.is_some() {
        return Err(EntryProofError::InvalidProof.into());
    }
    Ok(custom_ring_interface::PlainGroth16Proof {
        proof_a: alt_bn128_g1_compress_be(&proof.a).map_err(|_| EntryProofError::InvalidProof)?,
        proof_b: alt_bn128_g2_compress_be(&proof.b).map_err(|_| EntryProofError::InvalidProof)?,
        proof_c: alt_bn128_g1_compress_be(&proof.c).map_err(|_| EntryProofError::InvalidProof)?,
    })
}

impl From<ClientError> for EntryError {
    fn from(error: ClientError) -> Self {
        Self::Proof(EntryProofError::Client(Box::new(error)))
    }
}
