//! The sender's spend record on a velocity ring.

use custom_ring_interface::{tag, RegisterSpendIxData};
use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::{
    indexer::decode_shielded_transaction, AsyncIndexer, AsyncRpc, AsyncZolanaClient, ClientError,
    IndexerRpcConfig,
};
use zolana_indexer_api::{Hash, RingSpendRecordRequest, SerializablePubkey};
use zolana_interface::{event::confidential_encrypted_output_body, instruction::MessageData, pda};
use zolana_keypair::{constants::SALT_LEN, P256Pubkey};
use zolana_ring_policy::{
    entry_nullifier, spend_seed, ListNamespace, Member, SpendCounters, SpendRecord,
};

use crate::{
    entry::{
        namespace_write_metas, walk, EntryProof, InputSlot, LineageLookup, NamespaceWrite,
        SpentSlot,
    },
    policy_config_table,
    projection::retry_projection_lag,
    velocity::window_index,
    CustomRing, PoolTree, RingError,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordOrigin {
    pub first_nullifier: [u8; 32],
    pub tx_viewing_pk: Option<P256Pubkey>,
    pub salt: Option<[u8; SALT_LEN]>,
    pub messages: Vec<MessageData>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveSpendRecord {
    pub record: SpendRecord,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
    /// Its leaf hashes under the id of the tree it landed in.
    pub tree_id: u16,
    pub leaf_index: u64,
    pub origin: RecordOrigin,
}

#[must_use]
pub struct ReadSpendRecord {
    pub ring: CustomRing,
    pub address_tree_id: u16,
    pub member: Member,
    indexer_config: Option<IndexerRpcConfig>,
}

impl ReadSpendRecord {
    pub fn new(ring: CustomRing, address_tree_id: u16, member: Member) -> Self {
        Self {
            ring,
            address_tree_id,
            member,
            indexer_config: None,
        }
    }

    /// [`Self::read`] waits until the indexer persisted `config.require_slot`.
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    /// `None` until the member registers.
    pub async fn read_current(
        &self,
        client: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<LiveSpendRecord>, RingError> {
        retry_projection_lag(|| self.current(client)).await
    }

    /// The indexed record, refused while its nullifier is spent on chain.
    pub(crate) async fn current(
        &self,
        client: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<LiveSpendRecord>, RingError> {
        let request = RingSpendRecordRequest {
            ring_program_id: SerializablePubkey::from(self.ring.program_id().to_bytes()),
            member: Hash(*self.member.as_bytes()),
        };
        let Some(record) = client.get_ring_spend_record(request).await?.record else {
            return Ok(None);
        };
        let transaction = decode_shielded_transaction(record.transaction)?;
        let slot = transaction
            .output_slots
            .get(usize::from(record.output_index))
            .ok_or(RingError::InvalidSpendRecord)?;
        let lookup = self.lookup()?;
        let live = lookup
            .decode(
                &lookup.address()?,
                SpentSlot {
                    transaction: &transaction,
                    slot,
                },
            )
            .ok_or(RingError::InvalidSpendRecord)?;
        let spent = pda::nullifier_pda(&pda::tree(live.tree_id), &live.nullifier).0;
        if client.get_account(spent).await?.is_some() {
            return Err(ClientError::RingSpendRecordOutOfSync.into());
        }
        Ok(Some(live))
    }

    /// Unauthenticated history, unsuitable for transfer preparation.
    pub async fn read(
        self,
        indexer: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<LiveSpendRecord>, RingError> {
        let mut lineages = walk(indexer, &[self.lookup()?], self.indexer_config).await?;
        Ok(lineages.pop().flatten())
    }

    fn lookup(&self) -> Result<SpendLookup, RingError> {
        Ok(SpendLookup {
            owner: ListNamespace::new(self.ring.namespace_pda().as_array())?,
            member: self.member,
            address_tree_id: self.address_tree_id,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SpendLookup {
    pub owner: ListNamespace,
    pub member: Member,
    pub address_tree_id: u16,
}

impl LineageLookup for SpendLookup {
    type Live = LiveSpendRecord;

    fn address(&self) -> Result<[u8; 32], RingError> {
        Ok(self
            .owner
            .spend_address(&self.member, self.address_tree_id)?)
    }

    /// A registration carries its record inline, a successor in the one message its slot tags.
    fn decode(&self, address: &[u8; 32], slot: SpentSlot<'_>) -> Option<LiveSpendRecord> {
        let SpentSlot { transaction, slot } = slot;
        if ListNamespace::new(&slot.view_tag).ok()? != self.owner {
            return None;
        }
        let context = &slot.output_context;
        let record = match SpendRecord::from_output_data(&slot.payload) {
            Some(record) => Some(record).filter(|record| {
                record.version == 0
                    && record.utxo_hash(&self.owner, address, context.tree_id).ok()
                        == Some(context.hash)
            })?,
            None => {
                confidential_encrypted_output_body(&slot.payload)?;
                SpendRecord::open_carrier(
                    &slot.view_tag,
                    &self.owner,
                    self.address_tree_id,
                    transaction
                        .messages
                        .iter()
                        .map(|message| (&message.view_tag, message.data.as_slice())),
                    &context.hash,
                    context.tree_id,
                )
                .ok()?
            }
        };
        (record.member == self.member).then_some(LiveSpendRecord {
            nullifier: entry_nullifier(&context.hash, &record.blinding).ok()?,
            record,
            utxo_hash: context.hash,
            tree_id: context.tree_id,
            leaf_index: context.leaf_index,
            origin: RecordOrigin {
                first_nullifier: transaction.nullifiers.first().copied()?,
                tx_viewing_pk: transaction.tx_viewing_pk,
                salt: transaction.salt,
                messages: transaction.messages.clone(),
            },
        })
    }

    fn nullifier(live: &LiveSpendRecord) -> [u8; 32] {
        live.nullifier
    }

    fn version(live: &LiveSpendRecord) -> u64 {
        live.record.version
    }

    fn broken(&self, version: u64) -> RingError {
        RingError::BrokenSpendLineage {
            member: *self.member.as_bytes(),
            version,
        }
    }
}

#[must_use]
#[derive(Clone, Copy)]
pub struct RegisterSpend {
    pub ring: CustomRing,
    pub payer: Address,
}

#[must_use]
pub struct ProvenSpendRegistration {
    ring: CustomRing,
    payer: Address,
    address_tree: Address,
    record: SpendRecord,
    proof: EntryProof,
}

impl RegisterSpend {
    /// Refuses near a window boundary, the window index is part of the proven record.
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<ProvenSpendRegistration, RingError> {
        let policy = self
            .ring
            .policy_config(client)
            .await?
            .ok_or(RingError::MissingPolicyConfig)?;
        let window_slots = policy_config_table(&policy)?.window_slots();
        if window_slots == 0 {
            return Err(RingError::VelocityDisabled);
        }
        let owner = ListNamespace::new(self.ring.namespace_pda().as_array())?;
        let member = Member::owner_tag(self.payer.as_array())?;
        let address = owner.spend_address(&member, policy.address_tree_id())?;
        let record = SpendRecord {
            member,
            version: 0,
            window: window_index(client.get_slot().await?, window_slots)?,
            blinding: [0; 32],
            counters_commitment: SpendCounters::EMPTY.commitment()?,
        };
        let address_tree = PoolTree::address_tree(&policy);
        let (blinding, proof) = NamespaceWrite {
            owner: &owner,
            namespace: self.ring.namespace_pda(),
            input_tree: address_tree,
            output_tree: address_tree,
            payer: self.payer,
            slot: InputSlot::claim(&owner, spend_seed(&member)?, address, address_tree.id),
            output_data_hash: record.data_hash(&address)?,
        }
        .prove(client, |blinding| {
            SpendRecord { blinding, ..record }.to_output_data().to_vec()
        })
        .await?;
        Ok(ProvenSpendRegistration {
            ring: self.ring,
            payer: self.payer,
            address_tree: address_tree.address,
            record: SpendRecord { blinding, ..record },
            proof,
        })
    }
}

impl ProvenSpendRegistration {
    pub const fn record(&self) -> SpendRecord {
        self.record
    }

    pub fn instruction(self) -> Result<Instruction, RingError> {
        let data = crate::admin::tagged(
            tag::REGISTER_SPEND,
            &RegisterSpendIxData {
                blinding: self.record.blinding,
                window_index: self.record.window,
                private_tx_blinding: self.proof.private_tx_blinding,
                nullifier_tree_root_index: self.proof.nullifier_tree_root_index,
                utxo_tree_root_index: self.proof.utxo_tree_root_index,
                proof: self.proof.proof,
            },
        )?;
        Ok(Instruction {
            program_id: self.ring.program_id(),
            accounts: namespace_write_metas(
                self.ring,
                self.payer,
                self.address_tree,
                self.address_tree,
                self.proof.nullifier,
            ),
            data,
        })
    }
}
