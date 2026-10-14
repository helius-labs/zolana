//! A list entry write is a 1-in 2-out transfer the namespace PDA owns.
//! A create spends the address slot, an update spends the live version.

use std::collections::HashSet;

use custom_ring_interface::{tag, CreateEntryIxData, UpdateEntryIxData};
use num_bigint::BigUint;
use rand::{rngs::OsRng, RngCore};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_client::{
    prover::{field::be, requests},
    rpc::GetShieldedTransactionsByNullifiersResponse,
    AsyncIndexer, AsyncRpc, AsyncZolanaClient, IndexerRpcConfig, MerkleProof, OutputSlot,
    ProofCompressed, ProofInputUtxo, PublicInputs, PublicTransfers, ShieldedTransaction,
    TransferInput, TransferInputs, TransferOutput, TreeSlotFields, STATE_TREE_HEIGHT,
};
use zolana_hasher::primitives::{right_align, solana_owner_identity};
use zolana_interface::{
    event::OutputDataEncoding,
    instruction::instruction_data::transact::{OwnerTag, TransactOutput, TransactProof},
    pda,
    state::cache::empty_cached_input_fields,
    tree_slot::{pack_input_flags, tree_id_field, TreeSlot},
    ADDRESS_DOMAIN, INPUT_TREES, SHIELDED_POOL_PROGRAM_ID, SOL_ASSET_FIELD, UTXO_DOMAIN,
};
use zolana_keypair::NullifierKey;
use zolana_ring_policy::{
    entry_nullifier, entry_seed, EntryState, ListEntry, ListId, ListNamespace, Member,
};
use zolana_transaction::{
    instructions::transact::{ExternalData, PrivateTxHash},
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    },
    SppProofOutputUtxo,
};

use crate::{trees::read_tree, CustomRing, PoolTree, RingError};

/// A lineage walk reads at most this many versions.
const MAX_LINEAGE_VERSIONS: usize = 1 << 16;
/// One round reads at most this many pages.
const MAX_PAGES_PER_ROUND: usize = 64;

/// The current version of a lineage with its tree position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveEntry {
    pub entry: ListEntry,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
    /// Its leaf hashes under the id of the tree it landed in.
    pub tree_id: u16,
}

#[must_use]
pub struct ReadEntry {
    pub address_tree_id: u16,
    pub namespace: Address,
    pub list_id: ListId,
    pub member: Member,
    indexer_config: Option<IndexerRpcConfig>,
}

impl ReadEntry {
    pub fn new(address_tree_id: u16, namespace: Address, list_id: ListId, member: Member) -> Self {
        Self {
            address_tree_id,
            namespace,
            list_id,
            member,
            indexer_config: None,
        }
    }

    /// Waits until the indexer persisted `config.require_slot`, an indexer behind an update reads the version before it.
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    /// `None` when the address was never claimed, a cleared entry still reads back.
    pub async fn read(
        self,
        indexer: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<LiveEntry>, RingError> {
        let lookup = EntryLookup {
            owner: ListNamespace::new(self.namespace.as_array())?,
            list_id: self.list_id,
            member: self.member,
            address_tree_id: self.address_tree_id,
        };
        let mut lineages = walk(indexer, &[lookup], self.indexer_config).await?;
        Ok(lineages.pop().flatten())
    }
}

/// One output of the transaction consuming the lineage's current nullifier.
#[derive(Clone, Copy)]
pub(crate) struct SpentSlot<'a> {
    pub transaction: &'a ShieldedTransaction,
    pub slot: &'a OutputSlot,
}

pub(crate) trait LineageLookup {
    type Live: Clone;

    fn address(&self) -> Result<[u8; 32], RingError>;

    /// `None` unless the slot reproduces the on-chain leaf at `address`.
    fn decode(&self, address: &[u8; 32], slot: SpentSlot<'_>) -> Option<Self::Live>;

    fn nullifier(live: &Self::Live) -> [u8; 32];

    fn version(live: &Self::Live) -> u64;

    fn broken(&self, version: u64) -> RingError;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EntryLookup {
    pub owner: ListNamespace,
    pub list_id: ListId,
    pub member: Member,
    pub address_tree_id: u16,
}

impl LineageLookup for EntryLookup {
    type Live = LiveEntry;

    fn address(&self) -> Result<[u8; 32], RingError> {
        Ok(self
            .owner
            .address(self.list_id, &self.member, self.address_tree_id)?)
    }

    fn decode(&self, address: &[u8; 32], slot: SpentSlot<'_>) -> Option<LiveEntry> {
        let slot = slot.slot;
        let tree_id = slot.output_context.tree_id;
        let OutputDataEncoding::Plaintext(content) = slot.output_data()? else {
            return None;
        };
        let entry = ListEntry::from_entry_bytes(&content)?;
        if entry.list_id != self.list_id || entry.member != self.member {
            return None;
        }
        let utxo_hash = entry.utxo_hash(&self.owner, address, tree_id).ok()?;
        (utxo_hash == slot.output_context.hash).then_some(LiveEntry {
            entry,
            utxo_hash,
            nullifier: entry_nullifier(&utxo_hash, &entry.blinding).ok()?,
            tree_id,
        })
    }

    fn nullifier(live: &LiveEntry) -> [u8; 32] {
        live.nullifier
    }

    fn version(live: &LiveEntry) -> u64 {
        live.entry.version
    }

    fn broken(&self, version: u64) -> RingError {
        RingError::BrokenLineage {
            list_id: self.list_id,
            member: *self.member.as_bytes(),
            version,
        }
    }
}

/// One live version per lookup. Every pending lineage advances one version per
/// round, a round ends on the page that reports `scanned_through`.
pub(crate) async fn walk<L: LineageLookup>(
    indexer: &(impl AsyncRpc + ?Sized),
    lookups: &[L],
    config: Option<IndexerRpcConfig>,
) -> Result<Vec<Option<L::Live>>, RingError> {
    let mut heads = lookups
        .iter()
        .map(|lookup| {
            let address = lookup.address()?;
            Ok((address, address, None, false))
        })
        .collect::<Result<Vec<(_, _, Option<L::Live>, bool)>, RingError>>()?;
    let mut seen: HashSet<[u8; 32]> = heads.iter().map(|(_, nullifier, ..)| *nullifier).collect();
    for _ in 0..MAX_LINEAGE_VERSIONS {
        let nullifiers: Vec<_> = heads
            .iter()
            .filter(|(.., ended)| !ended)
            .map(|(_, nullifier, ..)| *nullifier)
            .collect();
        if nullifiers.is_empty() {
            return Ok(heads.into_iter().map(|(_, _, live, _)| live).collect());
        }
        let spenders = round(indexer, nullifiers, config).await?;
        for ((address, nullifier, live, ended), lookup) in heads.iter_mut().zip(lookups) {
            if *ended {
                continue;
            }
            let Some(spender) = spenders
                .iter()
                .find(|spender| spender.nullifiers.contains(nullifier))
            else {
                *ended = true;
                continue;
            };
            let version = live
                .as_ref()
                .map_or(0, |live| L::version(live).saturating_add(1));
            let successor = spender.output_slots.iter().find_map(|slot| {
                lookup.decode(
                    address,
                    SpentSlot {
                        transaction: spender,
                        slot,
                    },
                )
            });
            let successor = successor.ok_or_else(|| lookup.broken(version))?;
            if L::version(&successor) != version {
                return Err(RingError::LineageStalled { version });
            }
            *nullifier = L::nullifier(&successor);
            if !seen.insert(*nullifier) {
                return Err(RingError::LineageCycle);
            }
            *live = Some(successor);
        }
    }
    Err(RingError::LineageBound)
}

/// Every spender of `nullifiers`, across the pages of one round.
async fn round(
    indexer: &(impl AsyncRpc + ?Sized),
    nullifiers: Vec<[u8; 32]>,
    config: Option<IndexerRpcConfig>,
) -> Result<Vec<ShieldedTransaction>, RingError> {
    let mut spenders = Vec::new();
    let mut cursor = None;
    for _ in 0..MAX_PAGES_PER_ROUND {
        let GetShieldedTransactionsByNullifiersResponse {
            transactions,
            next_cursor,
            scanned_through,
            ..
        } = indexer
            .get_shielded_transactions_by_nullifiers(
                nullifiers.clone(),
                cursor.clone(),
                None,
                config,
            )
            .await?;
        spenders.extend(transactions);
        cursor = zolana_client::next_page(&cursor, next_cursor, &scanned_through)?;
        if cursor.is_none() {
            return Ok(spenders);
        }
    }
    Err(RingError::LineageBound)
}

/// Claims the pair's address at version zero, the address tree is the SPP input.
#[must_use]
pub struct CreateEntry {
    pub ring: CustomRing,
    pub payer: Address,
    pub address_tree: PoolTree,
    pub output_tree: PoolTree,
    pub list_id: ListId,
    pub member: Member,
    pub state: EntryState,
    pub content_hash: [u8; 32],
}

/// Spends the live version in its tree and writes its successor at the same address.
#[must_use]
pub struct UpdateEntry {
    pub ring: CustomRing,
    pub payer: Address,
    pub address_tree: PoolTree,
    pub output_tree: PoolTree,
    pub spent: LiveEntry,
    pub state: EntryState,
    pub content_hash: [u8; 32],
}

/// A proven mutation, ready to become one instruction.
#[must_use]
pub struct ProvenEntry {
    ring: CustomRing,
    payer: Address,
    output_tree: Address,
    input_tree: Address,
    entry: ListEntry,
    spent: Option<ListEntry>,
    proof: EntryProof,
}

impl CreateEntry {
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<ProvenEntry, RingError> {
        let entry = ListEntry {
            list_id: self.list_id,
            member: self.member,
            state: self.state,
            version: 0,
            content_hash: self.content_hash,
            blinding: [0; 32],
        };
        let write = EntryWrite {
            ring: self.ring,
            payer: self.payer,
            address_tree: self.address_tree,
            output_tree: self.output_tree,
        };
        write.prove(client, entry, None).await
    }
}

impl UpdateEntry {
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<ProvenEntry, RingError> {
        let spent = self.spent.entry;
        let entry = ListEntry {
            state: self.state,
            version: spent
                .version
                .checked_add(1)
                .ok_or(RingError::VersionOverflow)?,
            content_hash: self.content_hash,
            blinding: [0; 32],
            ..spent
        };
        let write = EntryWrite {
            ring: self.ring,
            payer: self.payer,
            address_tree: self.address_tree,
            output_tree: self.output_tree,
        };
        write.prove(client, entry, Some(self.spent)).await
    }
}

struct EntryWrite {
    ring: CustomRing,
    payer: Address,
    address_tree: PoolTree,
    output_tree: PoolTree,
}

impl EntryWrite {
    async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<R, I>,
        entry: ListEntry,
        spent: Option<LiveEntry>,
    ) -> Result<ProvenEntry, RingError> {
        if !entry.list_id.admits_content(entry.content_hash) {
            return Err(RingError::InvalidContent(entry.list_id));
        }
        let namespace = self.ring.namespace_pda();
        let owner = ListNamespace::new(namespace.as_array())?;
        let address = owner.address(entry.list_id, &entry.member, self.address_tree.id)?;
        let (input_tree, slot) = match spent {
            None => (
                self.address_tree,
                InputSlot::claim(
                    &owner,
                    entry_seed(entry.list_id, &entry.member)?,
                    address,
                    self.address_tree.id,
                ),
            ),
            Some(spent) => {
                let tree = self.address_tree.sibling(spent.tree_id);
                let data_hash = spent.entry.data_hash(&address)?;
                let slot =
                    InputSlot::spend(client, &owner, tree, data_hash, spent.entry.blinding).await?;
                (tree, slot)
            }
        };
        let write = NamespaceWrite {
            owner: &owner,
            namespace,
            input_tree,
            output_tree: self.output_tree,
            payer: self.payer,
            slot,
            output_data_hash: entry.data_hash(&address)?,
        };
        let (blinding, proof) = write
            .prove(client, |blinding| {
                ListEntry { blinding, ..entry }.to_output_data().to_vec()
            })
            .await?;
        Ok(ProvenEntry {
            ring: self.ring,
            payer: self.payer,
            output_tree: self.output_tree.address,
            input_tree: input_tree.address,
            entry: ListEntry { blinding, ..entry },
            spent: spent.map(|spent| spent.entry),
            proof,
        })
    }
}

impl ProvenEntry {
    pub const fn entry(&self) -> ListEntry {
        self.entry
    }

    pub fn instruction(self) -> Result<Instruction, RingError> {
        let Self {
            ring,
            payer,
            output_tree,
            input_tree,
            entry,
            spent,
            proof,
        } = self;
        let data = match spent {
            None => crate::admin::tagged(
                tag::CREATE_ENTRY,
                &CreateEntryIxData {
                    list_id: entry.list_id as u8,
                    member: *entry.member.as_bytes(),
                    state: entry.state as u8,
                    content_hash: entry.content_hash,
                    blinding: entry.blinding,
                    private_tx_blinding: proof.private_tx_blinding,
                    nullifier_tree_root_index: proof.nullifier_tree_root_index,
                    utxo_tree_root_index: proof.utxo_tree_root_index,
                    proof: proof.proof,
                },
            )?,
            Some(spent) => crate::admin::tagged(
                tag::UPDATE_ENTRY,
                &UpdateEntryIxData {
                    list_id: entry.list_id as u8,
                    member: *entry.member.as_bytes(),
                    spent_state: spent.state as u8,
                    spent_content_hash: spent.content_hash,
                    spent_version: spent.version,
                    spent_blinding: spent.blinding,
                    state: entry.state as u8,
                    content_hash: entry.content_hash,
                    blinding: entry.blinding,
                    private_tx_blinding: proof.private_tx_blinding,
                    nullifier_tree_root_index: proof.nullifier_tree_root_index,
                    utxo_tree_root_index: proof.utxo_tree_root_index,
                    proof: proof.proof,
                },
            )?,
        };
        Ok(Instruction {
            program_id: ring.program_id(),
            accounts: namespace_write_metas(ring, payer, input_tree, output_tree, proof.nullifier),
            data,
        })
    }
}

/// The two config accounts, then the list SPP's transact reads position for position.
pub(crate) fn namespace_write_metas(
    ring: CustomRing,
    payer: Address,
    input_tree: Address,
    output_tree: Address,
    nullifier: [u8; 32],
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(ring.config_pda(), false),
        AccountMeta::new_readonly(ring.policy_config_pda(), false),
        AccountMeta::new(payer, true),
        AccountMeta::new(output_tree, false),
        AccountMeta::new_readonly(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
        AccountMeta::new_readonly(Address::default(), false),
        AccountMeta::new(input_tree, false),
        AccountMeta::new(pda::nullifier_pda(&input_tree, &nullifier).0, false),
        AccountMeta::new_readonly(ring.namespace_pda(), false),
    ]
}

/// A one-in one-out SPP transfer proof carrying one namespace write.
pub(crate) struct EntryProof {
    pub proof: TransactProof,
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    /// The public input nullifier whose writable queue PDA SPP requires.
    pub nullifier: [u8; 32],
    /// The program folds it into `private_tx_hash`, it never reaches the record.
    pub private_tx_blinding: [u8; 32],
}

/// The input the transfer spends. A claim spends an address slot without a state
/// path, an update the live leaf.
pub(crate) struct InputSlot {
    utxo: ProofInputUtxo,
    input_hash: [u8; 32],
    /// The address a claim inserts, the chain element of its slot.
    address_nullifier: Option<[u8; 32]>,
    nullifier: [u8; 32],
    state: Option<MerkleProof>,
}

impl InputSlot {
    /// The address slot of `seed`, its blinding is the seed.
    pub(crate) fn claim(
        owner: &ListNamespace,
        seed: [u8; 32],
        address: [u8; 32],
        tree_id: u16,
    ) -> Self {
        Self {
            utxo: ProofInputUtxo {
                domain: right_align(&ADDRESS_DOMAIN.to_be_bytes()),
                tree_id: tree_id_field(tree_id),
                owner_hash: owner.owner_hash,
                blinding: seed,
                ..ProofInputUtxo::default()
            },
            input_hash: [0; 32],
            address_nullifier: Some(address),
            nullifier: address,
            state: None,
        }
    }

    async fn spend(
        indexer: &(impl AsyncRpc + ?Sized),
        owner: &ListNamespace,
        tree: PoolTree,
        data_hash: [u8; 32],
        blinding: [u8; 32],
    ) -> Result<Self, RingError> {
        let input_hash = owner.leaf_hash(&data_hash, &blinding, tree.id)?;
        let state = indexer
            .get_merkle_proofs(tree.address, vec![input_hash], None)
            .await?
            .proofs
            .pop()
            .ok_or(RingError::MissingProof)?;
        state.check_leaf(&input_hash, &tree.address, 0)?;
        Ok(Self {
            utxo: ProofInputUtxo {
                domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
                tree_id: tree_id_field(tree.id),
                owner_hash: owner.owner_hash,
                asset: SOL_ASSET_FIELD,
                blinding,
                data_hash,
                ..ProofInputUtxo::default()
            },
            input_hash,
            address_nullifier: None,
            nullifier: entry_nullifier(&input_hash, &blinding)?,
            state: Some(state),
        })
    }
}

pub(crate) struct NamespaceWrite<'a> {
    pub owner: &'a ListNamespace,
    pub namespace: Address,
    /// The spent slot's tree, a claim spends its address from the address tree.
    pub input_tree: PoolTree,
    pub output_tree: PoolTree,
    pub payer: Address,
    pub slot: InputSlot,
    /// Must not depend on the derived blinding.
    pub output_data_hash: [u8; 32],
}

impl NamespaceWrite<'_> {
    /// `content` publishes the successor under the derived output blinding.
    pub(crate) async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<R, I>,
        content: impl FnOnce([u8; 32]) -> Vec<u8>,
    ) -> Result<([u8; 32], EntryProof), RingError> {
        let tree = self.input_tree.address;
        let absence = client
            .get_non_inclusion_proofs(tree, vec![self.slot.nullifier], None)
            .await?
            .proofs
            .pop()
            .ok_or(RingError::MissingProof)?;
        absence.check_leaf(&self.slot.nullifier, &tree, 0)?;
        let live = match &self.slot.state {
            Some(state) => (state.root, state.root_index),
            None => {
                let roots = read_tree(client, tree).await?.roots;
                (roots.state, roots.state_index)
            }
        };
        let slot = &self.slot;
        let input_tree_id = self.input_tree.id;
        let output_tree_id = self.output_tree.id;
        // SPP derives every output blinding from the first nullifier and a private seed.
        let mut blinding_seed = [0u8; 32];
        OsRng.fill_bytes(&mut blinding_seed[1..]);
        let output_seed = derive_output_blinding_seed(&slot.nullifier, &blinding_seed)?;
        let blinding = derive_transact_output_blinding(&slot.nullifier, &output_seed, 0)?;
        let private_tx_blinding = derive_private_tx_blinding(&slot.nullifier, &blinding_seed)?;
        let padding = SppProofOutputUtxo {
            blinding: derive_transact_output_blinding(&slot.nullifier, &output_seed, 1)?,
            compact: true,
            ..SppProofOutputUtxo::default()
        };
        let padding_hash = padding.hash(output_tree_id)?;
        let owner_pk_hash = solana_owner_identity(self.namespace.as_array())?;
        let payer_hash = solana_owner_identity(self.payer.as_array())?;
        let output_hash =
            self.owner
                .leaf_hash(&self.output_data_hash, &blinding, output_tree_id)?;
        let external = ExternalData::new(
            [0; 33],
            [0; 16],
            vec![TransactOutput {
                utxo_hash: output_hash,
                owner_tag: OwnerTag::Inline(self.namespace.to_bytes()),
                data: Some(content(blinding)),
            }],
            vec![self.namespace.to_bytes()],
            Vec::new(),
        );
        let external_hash = external.hash()?;
        let address_nullifiers = slot.address_nullifier.map(|nullifier| [nullifier]);
        let private_tx = PrivateTxHash {
            input_hashes: &[slot.input_hash],
            output_hashes: &[output_hash],
            address_nullifiers: address_nullifiers.as_ref().map(|slice| slice.as_slice()),
            blinding: &private_tx_blinding,
        }
        .hash()?;
        // An address slot proves no inclusion, its path is zero and any live root serves.
        let (state_path, state_index) = match &slot.state {
            Some(state) => (
                state.path.iter().map(be).collect(),
                BigUint::from(state.leaf_index),
            ),
            None => (vec![BigUint::ZERO; STATE_TREE_HEIGHT], BigUint::ZERO),
        };
        let mut tree_slots = [TreeSlot::ZERO; INPUT_TREES];
        tree_slots[0] = TreeSlot::new(input_tree_id, live.0, absence.root);
        let signer_hashes = [payer_hash, owner_pk_hash];
        let output_hashes = [output_hash, padding_hash];
        let output_owner_hashes = [owner_pk_hash, [0; 32]];
        let public_transfers = PublicTransfers::default();
        // One real input in tree slot 0, dummy inputs allowed.
        let input_flags = pack_input_flags(true, [0u8])?;
        let cached_inputs = empty_cached_input_fields(1)?;
        let public_hash = PublicInputs {
            nullifiers: &[slot.nullifier],
            output_hashes: &output_hashes,
            tree_slots: &tree_slots,
            output_tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_hash,
            public_transfers: &public_transfers,
            ring_program_id: &[0; 32],
            input_flags: &input_flags,
            signer_pk_hashes: &signer_hashes,
            output_owner_pk_hashes: Some(&output_owner_hashes),
            cached_inputs,
        }
        .hash()?;
        let inputs = TransferInputs {
            inputs: vec![TransferInput {
                utxo: slot.utxo.clone(),
                is_dummy: BigUint::ZERO,
                state_path_elements: state_path,
                state_path_index: state_index,
                nullifier_low_value: be(&absence.low_element),
                nullifier_next_value: be(&absence.high_element),
                nullifier_low_path_elements: absence.path.iter().map(be).collect(),
                nullifier_low_path_index: BigUint::from(absence.low_element_index),
                tree_slot: BigUint::ZERO,
                nullifier: be(&slot.nullifier),
                owner_pk_hash: be(&owner_pk_hash),
                // The zero secret nullifies an entry slot, no authority fills it in.
                nullifier_secret: Some(BigUint::ZERO),
            }],
            outputs: vec![
                TransferOutput {
                    utxo: ProofInputUtxo {
                        domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
                        tree_id: tree_id_field(output_tree_id),
                        owner_hash: self.owner.owner_hash,
                        asset: SOL_ASSET_FIELD,
                        blinding,
                        data_hash: self.output_data_hash,
                        ..ProofInputUtxo::default()
                    },
                    is_dummy: BigUint::ZERO,
                    hash: be(&output_hash),
                    owner_pk_hash: be(&owner_pk_hash),
                    nullifier_pk: be(&zero_nullifier_key().pubkey()?),
                },
                TransferOutput {
                    utxo: ProofInputUtxo::try_from((&padding, output_tree_id))?,
                    is_dummy: BigUint::from(1u8),
                    hash: be(&padding_hash),
                    owner_pk_hash: BigUint::ZERO,
                    nullifier_pk: BigUint::ZERO,
                },
            ],
            tree_slots: TreeSlotFields::encode_all(&tree_slots),
            output_tree_id: BigUint::from(output_tree_id),
            blinding_seed: be(&blinding_seed),
            external_data_hash: be(&external_hash),
            private_tx_hash: be(&private_tx),
            cache: zolana_client::CacheReadInputs::uncached(cached_inputs),
            public_assets: core::array::from_fn(|_| BigUint::ZERO),
            public_amounts: core::array::from_fn(|_| BigUint::ZERO),
            ring_program_id: BigUint::ZERO,
            signer_pk_hashes: signer_hashes.iter().map(be).collect(),
            input_flags: be(&input_flags),
            published_output_owner_pk_hashes: output_owner_hashes.iter().map(be).collect(),
            public_input_hash: be(&public_hash),
        };
        let proof = client.prove_request(&requests::transfer(&inputs)?).await?;
        if proof.commitment.is_some() {
            return Err(RingError::InvalidProof);
        }
        Ok((
            blinding,
            EntryProof {
                proof: ProofCompressed::try_from(proof)?.to_transact_proof(),
                nullifier_tree_root_index: absence.root_index,
                utxo_tree_root_index: live.1,
                nullifier: slot.nullifier,
                private_tx_blinding,
            },
        ))
    }
}

/// The nullifier key every PDA-owned record carries.
pub(crate) fn zero_nullifier_key() -> NullifierKey {
    NullifierKey::from_secret([0; 31])
}

#[cfg(test)]
#[path = "tests/entry.rs"]
mod tests;
