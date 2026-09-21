use custom_ring_interface::{
    CompressedRegisterPublicInput, HeadMapInsert, HeadMapTransfer, HeadMapTransition,
    HEAD_MAP_CAPACITY,
};
use serde::Serialize;
use zeroize::Zeroizing;
use zolana_client::{
    indexer::decode_shielded_transaction,
    prover::{Delivery, ProveRequest},
    AsyncRpc, ClientError, Rpc,
};
use zolana_indexer_api::{
    GetRingHeadRegisterProofResponse, GetRingHeadTransferProofResponse,
    GetRingKeyRegistryRegisterProofResponse, Hash, RingMemberProofRequest, SerializablePubkey,
};
use zolana_ring_policy::Member;

use crate::{
    instructions::{
        entry::{EntryProofError, LineageLookup, SpentSlot},
        spend::{LiveSpendRecord, ReadEnvironment, ReadSpendRecord},
        transact::request::{field_hex, index_hex, json_body},
    },
    AccountReadError, CustomRing, IndexedMapRoot,
};

#[derive(Clone, Debug)]
pub(crate) struct HeadWitness {
    pub root: [u8; 32],
    pub next: [u8; 32],
    pub index: u64,
    pub proof: Vec<[u8; 32]>,
}

pub(crate) struct HeadMove<'a> {
    pub member: &'a [u8; 32],
    pub spent: &'a [u8; 32],
    pub successor: &'a [u8; 32],
}

impl HeadWitness {
    pub fn transition(
        &self,
        head_move: HeadMove<'_>,
    ) -> Result<HeadMapTransition, EntryProofError> {
        let new_root = HeadMapTransfer {
            root: &self.root,
            member: head_move.member,
            next: &self.next,
            spent: head_move.spent,
            successor: head_move.successor,
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

    fn verify_current(
        &self,
        member: &[u8; 32],
        nullifier: &[u8; 32],
    ) -> Result<(), EntryProofError> {
        self.transition(HeadMove {
            member,
            spent: nullifier,
            successor: nullifier,
        })
        .map(drop)
    }
}

pub(crate) struct CurrentHead {
    pub record: LiveSpendRecord,
    pub witness: HeadWitness,
}

impl CustomRing {
    pub(crate) fn member_proof_request(
        self,
        member: &Member,
        root: IndexedMapRoot,
    ) -> RingMemberProofRequest {
        RingMemberProofRequest {
            ring_program_id: SerializablePubkey::from(self.program_id().to_bytes()),
            member: Hash(*member.as_bytes()),
            expected_root: Hash(root.root),
            expected_next_index: root.next_index,
        }
    }
}

impl ReadSpendRecord {
    /// The root comes from Solana, the indexer serves only the record under it.
    pub(crate) fn current<I: Rpc, R: Rpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<CurrentHead, EntryProofError> {
        let root = self
            .ring
            .read_head_map_root(env.rpc)
            .map_err(account_error)?
            .ok_or(EntryProofError::MissingHeadMap)?;
        let query = self.ring.member_proof_request(&self.member, root);
        let response = env.indexer.get_ring_head_transfer_proof(query.clone())?;
        self.authenticate(&query, response)
    }

    pub(crate) async fn current_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<CurrentHead, EntryProofError> {
        let root = self
            .ring
            .read_head_map_root_async(env.rpc)
            .await
            .map_err(account_error)?
            .ok_or(EntryProofError::MissingHeadMap)?;
        let query = self.ring.member_proof_request(&self.member, root);
        let response = env
            .indexer
            .get_ring_head_transfer_proof(query.clone())
            .await?;
        self.authenticate(&query, response)
    }

    fn authenticate(
        self,
        query: &RingMemberProofRequest,
        response: GetRingHeadTransferProofResponse,
    ) -> Result<CurrentHead, EntryProofError> {
        // 1. The response must match the member and root requested from Solana.
        if response.root != query.expected_root
            || response.member != query.member
            || response.next_index != query.expected_next_index
            || response.index == 0
            || response.index >= response.next_index
            || response.next_index > HEAD_MAP_CAPACITY
        {
            return Err(EntryProofError::InvalidHeadProof);
        }
        let witness = HeadWitness {
            root: response.root.0,
            next: response.next.0,
            index: response.index,
            proof: response.proof.into_iter().map(|hash| hash.0).collect(),
        };
        // 2. The Merkle path authenticates the current record nullifier.
        witness.verify_current(self.member.as_bytes(), &response.nullifier.0)?;
        let transaction = decode_shielded_transaction(response.record.transaction)?;
        let output = transaction
            .output_slots
            .get(usize::from(response.record.output_index))
            .ok_or(EntryProofError::InvalidHeadProof)?;
        if output.output_context.tree != self.entries_tree || transaction.proofless {
            return Err(EntryProofError::InvalidHeadProof);
        }
        let lookup = self.lookup()?;
        // 3. The published record must reproduce the authenticated nullifier.
        let record = lookup
            .decode(
                &lookup.address()?,
                SpentSlot {
                    transaction: &transaction,
                    slot: output,
                },
            )
            .ok_or(EntryProofError::InvalidHeadProof)?;
        if record.nullifier != response.nullifier.0 {
            return Err(EntryProofError::InvalidHeadProof);
        }
        Ok(CurrentHead { record, witness })
    }
}

fn account_error(error: AccountReadError) -> EntryProofError {
    match error {
        AccountReadError::Client(error) => error.into(),
        AccountReadError::InvalidAccount { address } => {
            EntryProofError::InvalidHeadMapRoot { address }
        }
    }
}

pub(crate) struct InsertProof<'a> {
    root: &'a Hash,
    next_index: u64,
    member: &'a Hash,
    low_member: &'a Hash,
    low_next: &'a Hash,
    low_nullifier: &'a Hash,
    low_index: u64,
    low_proof: &'a [Hash],
    new_proof: &'a [Hash],
}

impl<'a> From<&'a GetRingHeadRegisterProofResponse> for InsertProof<'a> {
    fn from(response: &'a GetRingHeadRegisterProofResponse) -> Self {
        Self {
            root: &response.root,
            next_index: response.next_index,
            member: &response.member,
            low_member: &response.low_member,
            low_next: &response.low_next,
            low_nullifier: &response.low_nullifier,
            low_index: response.low_index,
            low_proof: &response.low_proof,
            new_proof: &response.new_proof,
        }
    }
}

impl<'a> From<&'a GetRingKeyRegistryRegisterProofResponse> for InsertProof<'a> {
    fn from(response: &'a GetRingKeyRegistryRegisterProofResponse) -> Self {
        Self {
            root: &response.root,
            next_index: response.next_index,
            member: &response.member,
            low_member: &response.low_member,
            low_next: &response.low_next,
            low_nullifier: &response.low_ct_commitment,
            low_index: response.low_index,
            low_proof: &response.low_proof,
            new_proof: &response.new_proof,
        }
    }
}

pub(crate) struct IndexedInsert<'a> {
    pub query: &'a RingMemberProofRequest,
    pub response: InsertProof<'a>,
    pub genesis: &'a [u8; 32],
}

pub(crate) struct VerifiedInsert {
    pub transition: HeadMapTransition,
    pub low_proof: Vec<[u8; 32]>,
    pub new_proof: Vec<[u8; 32]>,
}

/// The response answers another query or breaks the ordered insertion.
#[derive(Debug)]
pub(crate) struct InsertMismatch;

impl IndexedInsert<'_> {
    pub(crate) fn verify(self) -> Result<VerifiedInsert, InsertMismatch> {
        let response = self.response;
        if response.root != &self.query.expected_root
            || response.member != &self.query.member
            || response.next_index != self.query.expected_next_index
            || response.low_index >= response.next_index
        {
            return Err(InsertMismatch);
        }
        let low_proof: Vec<_> = response.low_proof.iter().map(|hash| hash.0).collect();
        let new_proof: Vec<_> = response.new_proof.iter().map(|hash| hash.0).collect();
        let new_root = HeadMapInsert {
            root: &response.root.0,
            append_index: response.next_index,
            member: &response.member.0,
            genesis: self.genesis,
            low_member: &response.low_member.0,
            low_next: &response.low_next.0,
            low_nullifier: &response.low_nullifier.0,
            low_index: response.low_index,
            low_proof: &low_proof,
            new_proof: &new_proof,
        }
        .verify()
        .map_err(|_| InsertMismatch)?;
        Ok(VerifiedInsert {
            transition: HeadMapTransition {
                old_root: response.root.0,
                new_root,
            },
            low_proof,
            new_proof,
        })
    }
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

impl ProveRequest for RegisterProofRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        json_body(self)
    }

    fn delivery(&self) -> Delivery {
        Delivery::Queued
    }
}

pub(crate) struct RegisterHead<'a> {
    pub query: &'a RingMemberProofRequest,
    pub response: GetRingHeadRegisterProofResponse,
    pub genesis: [u8; 32],
}

pub(crate) struct HeadRegistration {
    pub request: RegisterProofRequest,
    pub transition: HeadMapTransition,
}

impl RegisterHead<'_> {
    pub(crate) fn prepare(self) -> Result<HeadRegistration, EntryProofError> {
        let response = self.response;
        let VerifiedInsert {
            transition,
            low_proof,
            new_proof,
        } = IndexedInsert {
            query: self.query,
            response: (&response).into(),
            genesis: &self.genesis,
        }
        .verify()
        .map_err(|_| EntryProofError::InvalidHeadProof)?;
        let public_input = CompressedRegisterPublicInput {
            head_old_root: &transition.old_root,
            head_new_root: &transition.new_root,
            member: &response.member.0,
            genesis: &self.genesis,
            new_index: response.next_index,
        }
        .hash()
        .map_err(|_| EntryProofError::Hashing)?;
        Ok(HeadRegistration {
            request: RegisterProofRequest {
                circuit_type: "custom-ring-compressed-register",
                public_input_hash: field_hex(&public_input),
                head_old_root: field_hex(&transition.old_root),
                head_new_root: field_hex(&transition.new_root),
                member: field_hex(&response.member.0),
                genesis: field_hex(&self.genesis),
                new_index: index_hex(response.next_index),
                low_member: field_hex(&response.low_member.0),
                low_next: field_hex(&response.low_next.0),
                low_nullifier: field_hex(&response.low_nullifier.0),
                low_index: index_hex(response.low_index),
                low_proof: low_proof.iter().map(field_hex).collect(),
                new_proof: new_proof.iter().map(field_hex).collect(),
            },
            transition,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use custom_ring_interface::HEAD_MAP_HEIGHT;
    use solana_address::Address;
    use zolana_hasher::primitives::right_align;
    use zolana_indexer_api::{
        Base64String, Context, RingHeadRecord, RingsOutputContext, RingsOutputSlot,
        ShieldedTransaction,
    };
    use zolana_ring_head_map::{HeadMap, HeadTransfer, Registration};
    use zolana_ring_policy::{entry_nullifier, ListNamespace, SpendCounters, SpendRecord};

    struct RegisterFixture {
        query: RingMemberProofRequest,
        response: GetRingHeadRegisterProofResponse,
        genesis: [u8; 32],
        new_root: [u8; 32],
    }

    impl RegisterFixture {
        fn new() -> Self {
            let mut map = HeadMap::new().unwrap();
            let member = Member::owner_tag(&[7; 32]).unwrap();
            let genesis = right_align(&19u64.to_be_bytes());
            let proof_inputs = map
                .register(Registration {
                    member: *member.as_bytes(),
                    genesis,
                })
                .unwrap();
            let query = CustomRing::new(Address::new_from_array([5; 32])).member_proof_request(
                &member,
                IndexedMapRoot {
                    root: proof_inputs.old_root,
                    next_index: proof_inputs.new_index,
                },
            );
            let response = GetRingHeadRegisterProofResponse {
                context: Context::default(),
                root: Hash(proof_inputs.old_root),
                next_index: proof_inputs.new_index,
                member: Hash(proof_inputs.member),
                low_member: Hash(proof_inputs.low_member),
                low_next: Hash(proof_inputs.low_next),
                low_nullifier: Hash(proof_inputs.low_nullifier),
                low_index: proof_inputs.low_index,
                low_proof: proof_inputs.low_proof.into_iter().map(Hash).collect(),
                new_proof: proof_inputs.new_proof.into_iter().map(Hash).collect(),
            };
            Self {
                query,
                response,
                genesis,
                new_root: proof_inputs.new_root,
            }
        }

        fn prepare(
            &self,
            response: GetRingHeadRegisterProofResponse,
        ) -> Result<HeadRegistration, EntryProofError> {
            RegisterHead {
                query: &self.query,
                response,
                genesis: self.genesis,
            }
            .prepare()
        }
    }

    #[test]
    fn registration_matches_the_reference_and_encodes_full_width_indexes() {
        let fixture = RegisterFixture::new();
        let HeadRegistration {
            request,
            transition,
        } = fixture.prepare(fixture.response.clone()).unwrap();
        assert_eq!(transition.old_root, fixture.query.expected_root.0);
        assert_eq!(transition.new_root, fixture.new_root);
        let json: serde_json::Value =
            serde_json::from_str(request.body().unwrap().as_str()).unwrap();
        assert_eq!(json["circuitType"], "custom-ring-compressed-register");
        assert_eq!(json["newIndex"], index_hex(1));
        assert_eq!(json["lowProof"].as_array().unwrap().len(), HEAD_MAP_HEIGHT);
        assert_eq!(json["headNewRoot"], field_hex(&fixture.new_root));
    }

    #[test]
    fn registration_rejects_response_substitution_and_malformed_paths() {
        let fixture = RegisterFixture::new();
        let mutations: [fn(&mut GetRingHeadRegisterProofResponse); 6] = [
            |response| response.root.0[31] ^= 1,
            |response| response.member.0[31] ^= 1,
            |response| response.next_index += 1,
            |response| {
                response.low_proof.pop();
            },
            |response| response.low_index = HEAD_MAP_CAPACITY,
            |response| response.new_proof[0].0[31] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = fixture.response.clone();
            mutate(&mut changed);
            assert!(matches!(
                fixture.prepare(changed),
                Err(EntryProofError::InvalidHeadProof)
            ));
        }
    }

    struct TransferFixture {
        read: ReadSpendRecord,
        query: RingMemberProofRequest,
        response: GetRingHeadTransferProofResponse,
    }

    impl TransferFixture {
        fn new() -> Self {
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
                counters_commitment: SpendCounters::EMPTY.commitment().unwrap(),
            };
            let hash = record.utxo_hash(&owner, &address, 4).unwrap();
            let nullifier = entry_nullifier(&hash, &record.blinding).unwrap();
            let mut map = HeadMap::new().unwrap();
            map.register(Registration {
                member: *member.as_bytes(),
                genesis: nullifier,
            })
            .unwrap();
            let proof = map
                .transfer(HeadTransfer {
                    member: *member.as_bytes(),
                    spent: nullifier,
                    successor: nullifier,
                })
                .unwrap();
            let tree = Address::new_from_array([6; 32]);
            let query = ring.member_proof_request(
                &member,
                IndexedMapRoot {
                    root: proof.old_root,
                    next_index: 2,
                },
            );
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
                        event_index: Some(0),
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
            Self {
                read: ReadSpendRecord {
                    ring,
                    entries_tree: tree,
                    entries_tree_id: 4,
                    member,
                },
                query,
                response,
            }
        }
    }

    #[test]
    fn the_current_record_is_bound_to_the_requested_head() {
        let fixture = TransferFixture::new();
        let nullifier = fixture.response.nullifier.0;
        let head = fixture
            .read
            .authenticate(&fixture.query, fixture.response)
            .unwrap();
        assert_eq!(head.record.nullifier, nullifier);
        assert_eq!(head.record.record.version, 0);
        assert_eq!(head.witness.root, fixture.query.expected_root.0);
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
            |response| response.index = HEAD_MAP_CAPACITY,
            |response| {
                response.proof.pop();
            },
        ];
        for mutate in mutations {
            let mut fixture = TransferFixture::new();
            mutate(&mut fixture.response);
            assert!(matches!(
                fixture.read.authenticate(&fixture.query, fixture.response),
                Err(EntryProofError::InvalidHeadProof)
            ));
        }
    }
}
