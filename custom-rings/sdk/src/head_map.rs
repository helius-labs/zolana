use custom_ring_interface::{
    HeadMapInsert, HeadMapRoot, HeadMapTransfer, HeadMapTransition, HEAD_MAP_HEIGHT,
};
use serde::Serialize;
use zeroize::Zeroizing;
use zolana_client::{
    prover::{Delivery, ProveRequest},
    AsyncRpc, ClientError, Rpc,
};
use zolana_hasher::primitives::right_align;
use zolana_indexer_api::{
    GetRingHeadProofRequest, GetRingHeadRegisterProofResponse, GetRingHeadTransferProofResponse,
    Hash, SerializablePubkey,
};

use crate::{
    instructions::{
        entry::{EntryProofError, LineageLookup},
        spend::{discovery::SpendLookup, LiveSpendRecord, ReadSpendRecord},
    },
    AccountReadError, CustomRing,
};

#[derive(Clone, Debug)]
pub(crate) struct HeadWitness {
    pub root: [u8; 32],
    pub next: [u8; 32],
    pub index: u64,
    pub proof: Vec<[u8; 32]>,
}

impl HeadWitness {
    pub fn transition(
        &self,
        member: &[u8; 32],
        spent: &[u8; 32],
        successor: &[u8; 32],
    ) -> Result<HeadMapTransition, EntryProofError> {
        let new_root = HeadMapTransfer {
            root: &self.root,
            member,
            next: &self.next,
            spent,
            successor,
            index: self.index,
            proof: &self.proof,
        }
        .verify()
        .map_err(|_| EntryProofError::InvalidHeadProof)?;
        Ok(HeadMapTransition {
            old_root: self.root,
            new_root,
        })
    }
}

pub(crate) fn request(
    ring: CustomRing,
    member: &[u8; 32],
    root: &HeadMapRoot,
) -> GetRingHeadProofRequest {
    GetRingHeadProofRequest {
        ring_program_id: SerializablePubkey::from(ring.program_id().to_bytes()),
        member: Hash(*member),
        expected_root: Hash(root.root),
        expected_next_index: root.next_index(),
    }
}

pub(crate) fn read<I: Rpc, R: Rpc>(
    ring: CustomRing,
    read: ReadSpendRecord,
    indexer: &I,
    rpc: &R,
) -> Result<(LiveSpendRecord, HeadWitness), EntryProofError> {
    let root = ring
        .read_head_map_root(rpc)
        .map_err(account_error)?
        .ok_or(EntryProofError::MissingHeadMap)?;
    let query = request(ring, read.member.as_bytes(), &root);
    let response = indexer.get_ring_head_transfer_proof(query.clone())?;
    decode(read, &query, response)
}

pub(crate) async fn read_async<I: AsyncRpc, R: AsyncRpc>(
    ring: CustomRing,
    read: ReadSpendRecord,
    indexer: &I,
    rpc: &R,
) -> Result<(LiveSpendRecord, HeadWitness), EntryProofError> {
    let root = ring
        .read_head_map_root_async(rpc)
        .await
        .map_err(account_error)?
        .ok_or(EntryProofError::MissingHeadMap)?;
    let query = request(ring, read.member.as_bytes(), &root);
    let response = indexer.get_ring_head_transfer_proof(query.clone()).await?;
    decode(read, &query, response)
}

fn account_error(error: AccountReadError) -> EntryProofError {
    match error {
        AccountReadError::Client(error) => error.into(),
        AccountReadError::InvalidAccount { .. } => EntryProofError::InvalidHeadProof,
    }
}

fn decode(
    read: ReadSpendRecord,
    query: &GetRingHeadProofRequest,
    response: GetRingHeadTransferProofResponse,
) -> Result<(LiveSpendRecord, HeadWitness), EntryProofError> {
    if response.root != query.expected_root
        || response.member != query.member
        || response.next_index != query.expected_next_index
        || response.index == 0
        || response.index >= response.next_index
        || response.next_index > (1u64 << HEAD_MAP_HEIGHT)
    {
        return Err(EntryProofError::InvalidHeadProof);
    }
    let witness = HeadWitness {
        root: response.root.0,
        next: response.next.0,
        index: response.index,
        proof: response.proof.into_iter().map(|hash| hash.0).collect(),
    };
    witness.transition(
        read.member.as_bytes(),
        &response.nullifier.0,
        &response.nullifier.0,
    )?;
    let transaction = zolana_client::indexer::convert_shielded_transaction(
        "record.transaction",
        response.record.transaction,
    )?;
    let output = transaction
        .output_slots
        .get(usize::from(response.record.output_index))
        .ok_or(EntryProofError::InvalidHeadProof)?;
    if output.output_context.tree != read.entries_tree || transaction.proofless {
        return Err(EntryProofError::InvalidHeadProof);
    }
    let lookup = SpendLookup {
        owner: zolana_ring_policy::ListNamespace::new(read.namespace.as_array())
            .map_err(|_| EntryProofError::Hashing)?,
        member: read.member,
        tree_id: read.entries_tree_id,
    };
    let live = lookup
        .decode(&lookup.address()?, &transaction, output)
        .ok_or(EntryProofError::InvalidHeadProof)?;
    if live.nullifier != response.nullifier.0 {
        return Err(EntryProofError::InvalidHeadProof);
    }
    Ok((live, witness))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterProofRequest {
    circuit_type: &'static str,
    public_input_hash: String,
    head_old_root: String,
    head_new_root: String,
    member: String,
    genesis: String,
    new_index: String,
    low_member: String,
    low_next: String,
    low_nullifier: String,
    low_index: String,
    low_proof: Vec<String>,
    new_proof: Vec<String>,
}

impl RegisterProofRequest {
    pub fn build(
        query: &GetRingHeadProofRequest,
        response: GetRingHeadRegisterProofResponse,
        genesis: &[u8; 32],
    ) -> Result<(Self, HeadMapTransition), EntryProofError> {
        if response.root != query.expected_root
            || response.member != query.member
            || response.next_index != query.expected_next_index
            || response.low_index >= response.next_index
        {
            return Err(EntryProofError::InvalidHeadProof);
        }
        let low_proof: Vec<_> = response.low_proof.iter().map(|hash| hash.0).collect();
        let new_proof: Vec<_> = response.new_proof.iter().map(|hash| hash.0).collect();
        let new_root = HeadMapInsert {
            root: &response.root.0,
            append_index: response.next_index,
            member: &response.member.0,
            genesis,
            low_member: &response.low_member.0,
            low_next: &response.low_next.0,
            low_nullifier: &response.low_nullifier.0,
            low_index: response.low_index,
            low_proof: &low_proof,
            new_proof: &new_proof,
        }
        .verify()
        .map_err(|_| EntryProofError::InvalidHeadProof)?;
        let transition = HeadMapTransition {
            old_root: response.root.0,
            new_root,
        };
        let public_input = custom_ring_interface::CompressedRegisterPublicInput {
            head_old_root: &transition.old_root,
            head_new_root: &transition.new_root,
            member: &response.member.0,
            genesis,
            new_index: response.next_index,
        }
        .hash()
        .map_err(|_| EntryProofError::Hashing)?;
        Ok((
            Self {
                circuit_type: "custom-ring-compressed-register",
                public_input_hash: hex(&public_input),
                head_old_root: hex(&transition.old_root),
                head_new_root: hex(&transition.new_root),
                member: hex(&response.member.0),
                genesis: hex(genesis),
                new_index: index_hex(response.next_index),
                low_member: hex(&response.low_member.0),
                low_next: hex(&response.low_next.0),
                low_nullifier: hex(&response.low_nullifier.0),
                low_index: index_hex(response.low_index),
                low_proof: low_proof.iter().map(hex).collect(),
                new_proof: new_proof.iter().map(hex).collect(),
            },
            transition,
        ))
    }
}

impl ProveRequest for RegisterProofRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        serde_json::to_string(self)
            .map(Zeroizing::new)
            .map_err(|error| ClientError::Prover(error.to_string()))
    }
    fn delivery(&self) -> Delivery {
        Delivery::Queued
    }
}

pub(crate) fn hex(field: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut encoded = String::with_capacity(66);
    encoded.push_str("0x");
    for byte in field {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String");
    }
    encoded
}

pub(crate) fn index_hex(index: u64) -> String {
    hex(&right_align(&index.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_address::Address;
    use zolana_indexer_api::{
        Base64String, Context, RingHeadRecord, RingsOutputContext, RingsOutputSlot,
        ShieldedTransaction,
    };
    use zolana_ring_head_map::HeadMap;
    use zolana_ring_policy::{entry_nullifier, ListNamespace, Member, SpendCounters, SpendRecord};

    fn register_fixture() -> (
        GetRingHeadProofRequest,
        GetRingHeadRegisterProofResponse,
        [u8; 32],
        [u8; 32],
    ) {
        let mut map = HeadMap::new().unwrap();
        let member = Member::owner_tag(&[7; 32]).unwrap();
        let genesis = right_align(&19u64.to_be_bytes());
        let witness = map.register(*member.as_bytes(), genesis).unwrap();
        let query = GetRingHeadProofRequest {
            ring_program_id: SerializablePubkey::from([5; 32]),
            member: Hash(witness.member),
            expected_root: Hash(witness.old_root),
            expected_next_index: witness.new_index,
        };
        let response = GetRingHeadRegisterProofResponse {
            context: Context::default(),
            root: Hash(witness.old_root),
            next_index: witness.new_index,
            member: Hash(witness.member),
            low_member: Hash(witness.low_member),
            low_next: Hash(witness.low_next),
            low_nullifier: Hash(witness.low_nullifier),
            low_index: witness.low_index,
            low_proof: witness.low_proof.into_iter().map(Hash).collect(),
            new_proof: witness.new_proof.into_iter().map(Hash).collect(),
        };
        (query, response, genesis, witness.new_root)
    }

    #[test]
    fn registration_matches_the_reference_and_encodes_full_width_indexes() {
        let (query, response, genesis, expected) = register_fixture();
        let (proof, transition) = RegisterProofRequest::build(&query, response, &genesis).unwrap();
        assert_eq!(transition.old_root, query.expected_root.0);
        assert_eq!(transition.new_root, expected);
        let json: serde_json::Value = serde_json::from_str(proof.body().unwrap().as_str()).unwrap();
        assert_eq!(json["circuitType"], "custom-ring-compressed-register");
        assert_eq!(json["newIndex"], index_hex(1));
        assert_eq!(json["lowProof"].as_array().unwrap().len(), HEAD_MAP_HEIGHT);
        assert_eq!(json["headNewRoot"], hex(&expected));
    }

    #[test]
    fn registration_rejects_response_substitution_and_malformed_paths() {
        let (query, response, genesis, _) = register_fixture();
        let mutations: [fn(&mut GetRingHeadRegisterProofResponse); 6] = [
            |response| response.root.0[31] ^= 1,
            |response| response.member.0[31] ^= 1,
            |response| response.next_index += 1,
            |response| {
                response.low_proof.pop();
            },
            |response| response.low_index = 1u64 << HEAD_MAP_HEIGHT,
            |response| response.new_proof[0].0[31] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = response.clone();
            mutate(&mut changed);
            assert!(matches!(
                RegisterProofRequest::build(&query, changed, &genesis),
                Err(EntryProofError::InvalidHeadProof)
            ));
        }
    }

    fn transfer_fixture() -> (
        ReadSpendRecord,
        GetRingHeadProofRequest,
        GetRingHeadTransferProofResponse,
    ) {
        let ring = CustomRing::new(Address::new_from_array([5; 32]));
        let namespace = ring.namespace_pda();
        let owner = ListNamespace::new(namespace.as_array()).unwrap();
        let member = Member::owner_tag(&[7; 32]).unwrap();
        let address = owner.spend_address(&member, 4).unwrap();
        let record = SpendRecord {
            member,
            version: 0,
            window: 3,
            blinding: right_align(&91u64.to_be_bytes()),
            counters_commitment: SpendCounters::zero(&[]).commitment().unwrap(),
        };
        let hash = record.utxo_hash(&owner, &address, 4).unwrap();
        let nullifier = entry_nullifier(&hash, &record.blinding).unwrap();
        let mut map = HeadMap::new().unwrap();
        map.register(*member.as_bytes(), nullifier).unwrap();
        let proof = map
            .transfer(member.as_bytes(), &nullifier, nullifier)
            .unwrap();
        let tree = Address::new_from_array([6; 32]);
        let query = GetRingHeadProofRequest {
            ring_program_id: SerializablePubkey::from(ring.program_id().to_bytes()),
            member: Hash(*member.as_bytes()),
            expected_root: Hash(proof.old_root),
            expected_next_index: 2,
        };
        let response = GetRingHeadTransferProofResponse {
            context: Context::default(),
            root: Hash(proof.old_root),
            next_index: 2,
            member: Hash(proof.member),
            next: Hash(proof.next),
            nullifier: Hash(nullifier),
            index: proof.index,
            proof: proof.proof.into_iter().map(Hash).collect(),
            record: RingHeadRecord {
                output_index: 0,
                transaction: ShieldedTransaction {
                    slot: 2,
                    tx_signature: Default::default(),
                    tx_viewing_pk: None,
                    salt: None,
                    output_slots: vec![RingsOutputSlot {
                        view_tag: Hash(namespace.to_bytes()),
                        payload: Base64String(record.to_output_data().to_vec()),
                        output_context: RingsOutputContext {
                            hash: Hash(hash),
                            tree: SerializablePubkey::from(tree.to_bytes()),
                            leaf_index: 7,
                        },
                    }],
                    messages: Vec::new(),
                    nullifiers: vec![Hash(address)],
                    proofless: false,
                    ring_config: None,
                    ring_program_id: Some(query.ring_program_id),
                },
            },
        };
        (
            ReadSpendRecord {
                entries_tree: tree,
                entries_tree_id: 4,
                namespace,
                member,
            },
            query,
            response,
        )
    }

    #[test]
    fn the_current_record_is_bound_to_the_requested_head() {
        let (read, query, response) = transfer_fixture();
        let nullifier = response.nullifier.0;
        let (live, witness) = decode(read, &query, response).unwrap();
        assert_eq!(live.nullifier, nullifier);
        assert_eq!(live.record.version, 0);
        assert_eq!(witness.root, query.expected_root.0);
    }

    #[test]
    fn a_valid_head_path_does_not_validate_a_substituted_record() {
        let mutations: [fn(&mut GetRingHeadTransferProofResponse); 8] = [
            |response| response.member.0[31] ^= 1,
            |response| response.root.0[31] ^= 1,
            |response| response.record.output_index = 1,
            |response| {
                response.record.transaction.output_slots[0]
                    .output_context
                    .hash
                    .0[31] ^= 1
            },
            |response| {
                response.record.transaction.output_slots[0]
                    .output_context
                    .tree = SerializablePubkey::from([8; 32])
            },
            |response| response.record.transaction.proofless = true,
            |response| response.index = 1u64 << HEAD_MAP_HEIGHT,
            |response| {
                response.proof.pop();
            },
        ];
        for mutate in mutations {
            let (read, query, mut response) = transfer_fixture();
            mutate(&mut response);
            assert!(matches!(
                decode(read, &query, response),
                Err(EntryProofError::InvalidHeadProof)
            ));
        }
    }
}
