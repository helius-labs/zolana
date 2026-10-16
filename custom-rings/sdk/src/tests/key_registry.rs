use std::sync::Mutex;

use async_trait::async_trait;
use custom_ring_interface::{
    KeyRegistryLeaf, KeyRegistryRoot, MerklePath, RegisteredKey, KEY_REGISTRY_HEIGHT,
    KEY_REGISTRY_ROOT, KEY_REGISTRY_ROOT_HISTORY,
};
use solana_account::Account;
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_client::{
    AsyncRpc, ClientError, GetRingKeyRegistryEntryResponse,
    GetRingKeyRegistryRegisterProofResponse, RingMemberProofRequest,
};
use zolana_hasher::primitives::right_align;
use zolana_indexer_api::{Base64String, Context, Hash};
use zolana_interface::merge_utils::ciphertext_hash;
use zolana_keypair::{NullifierKey, X25519Secret};
use zolana_ring_client::NullifierKeyEnvelope;
use zolana_ring_key_registry::{KeyRegistryTree, Registration};
use zolana_ring_policy::{Member, ZERO_NULLIFIER_PK};

use super::support::account;
use crate::{
    escrow::{KeyRegistry, OutputKey},
    key_registry::register,
    projection::retry_projection_lag,
    prover::RingRequest,
    CurrentKeyRegistryRoot, CustomRing, ReadCurrentSealedKey, ReadSealedKey, RingError,
};
use zolana_client::ProveRequest;

struct Fixture {
    ring: CustomRing,
    member: Member,
    query: RingMemberProofRequest,
    response: GetRingKeyRegistryRegisterProofResponse,
    auditor: X25519Secret,
    nullifier_key: NullifierKey,
    envelope: NullifierKeyEnvelope,
    tree: KeyRegistryTree,
    new_root: [u8; 32],
}

impl Fixture {
    /// One sealed key at index 1 above the sentinel, with the response an indexer serves for it.
    fn new() -> Self {
        let ring = CustomRing::new(Address::new_from_array([5; 32]));
        let auditor = X25519Secret::new();
        let nullifier_key = NullifierKey::from_secret([7; 31]);
        let envelope = NullifierKeyEnvelope::new(&nullifier_key, &auditor.pubkey()).unwrap();
        let member = Member::owner_tag(&[9; 32]).unwrap();
        let key = RegisteredKey {
            nullifier_pk: &envelope.nullifier_pk,
            ciphertext: &envelope.sealed.ciphertext,
        }
        .hash()
        .unwrap();
        let mut tree = KeyRegistryTree::new().unwrap();
        let inserted = tree
            .register(Registration {
                member: *member.as_bytes(),
                key,
            })
            .unwrap();
        let query = ring.member_proof_request(
            &member,
            CurrentKeyRegistryRoot {
                root: inserted.old_root,
                next_index: inserted.new_index,
                history_index: 0,
            },
        );
        let response = GetRingKeyRegistryRegisterProofResponse {
            context: Context::default(),
            root: Hash(inserted.old_root),
            next_index: inserted.new_index,
            member: Hash(inserted.member),
            low_member: Hash(inserted.low_member),
            low_next: Hash(inserted.low_next),
            low_key_hash: Hash(inserted.low_key),
            low_index: inserted.low_index,
            low_proof: inserted.low_proof.into_iter().map(Hash).collect(),
            new_proof: inserted.new_proof.into_iter().map(Hash).collect(),
        };
        Self {
            ring,
            member,
            query,
            response,
            auditor,
            nullifier_key,
            envelope,
            tree,
            new_root: inserted.new_root,
        }
    }

    fn secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(right_align(&self.nullifier_key.secret()))
    }

    fn root(&self) -> CurrentKeyRegistryRoot {
        CurrentKeyRegistryRoot {
            root: self.new_root,
            next_index: 2,
            history_index: 1,
        }
    }

    /// The registered slot as the indexer serves it after the append.
    fn entry(&self) -> (RingMemberProofRequest, GetRingKeyRegistryEntryResponse) {
        let inclusion = self.tree.member_proof(self.member.as_bytes()).unwrap();
        let query = self.ring.member_proof_request(&self.member, self.root());
        let response = GetRingKeyRegistryEntryResponse {
            context: Context::default(),
            root: Hash(self.new_root),
            next_index: 2,
            member: Hash(*self.member.as_bytes()),
            next: Hash(inclusion.next),
            index: inclusion.index,
            eph_pk: Base64String(self.envelope.sealed.eph_pk.as_bytes().to_vec()),
            ciphertext: Base64String(self.envelope.sealed.ciphertext.to_vec()),
            proof: inclusion.proof.into_iter().map(Hash).collect(),
        };
        (query, response)
    }

    fn read(&self) -> ReadSealedKey {
        ReadSealedKey {
            ring: self.ring,
            member: self.member,
            root: self.root(),
        }
    }
}

#[test]
fn registration_matches_the_reference_and_encodes_the_prover_wire() {
    let fixture = Fixture::new();
    let (body, transition) = register(
        &fixture.envelope,
        fixture.auditor.pubkey(),
        fixture.secret(),
        &fixture.query,
        fixture.response.clone(),
    )
    .unwrap();
    assert_eq!(transition.old_root, fixture.query.expected_root.0);
    assert_eq!(transition.new_root, fixture.new_root);
    let json: serde_json::Value =
        serde_json::from_str(&RingRequest(&body).body().unwrap()).unwrap();
    assert_eq!(json["circuitType"], "custom-ring-register-key");
    assert_eq!(
        json["newIndex"],
        format!("0x{:064x}", fixture.query.expected_next_index)
    );
    assert_eq!(
        json["registryNewRoot"],
        format!("0x{}", hex::encode(fixture.new_root))
    );
    assert_eq!(
        json["lowProof"].as_array().unwrap().len(),
        KEY_REGISTRY_HEIGHT
    );
    assert_eq!(
        json["newProof"].as_array().unwrap().len(),
        KEY_REGISTRY_HEIGHT
    );
    // The nullifier secret rides right aligned, its high byte pins it below the field order.
    let secret = json["nullifierSecret"].as_str().unwrap();
    assert_eq!(secret.len(), 66);
    assert!(secret.starts_with("0x00"));
    // The auditor coordinate is witnessed as 32 little-endian bytes behind the `0x`.
    assert_eq!(json["auditorPk"].as_str().unwrap().len(), 66);
    assert_eq!(json["ephSk"].as_str().unwrap().len(), 66);
}

#[test]
fn registration_rejects_response_substitution_and_malformed_paths() {
    let fixture = Fixture::new();
    let mutations: [fn(&mut GetRingKeyRegistryRegisterProofResponse); 6] = [
        |response| response.root.0[31] ^= 1,
        |response| response.member.0[31] ^= 1,
        |response| response.next_index += 1,
        |response| response.low_index = response.next_index,
        |response| {
            response.low_proof.pop();
        },
        |response| response.new_proof[0].0[31] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = fixture.response.clone();
        mutate(&mut changed);
        assert!(matches!(
            register(
                &fixture.envelope,
                fixture.auditor.pubkey(),
                fixture.secret(),
                &fixture.query,
                changed,
            ),
            Err(RingError::InvalidRegisterProof)
        ));
    }
}

#[test]
fn the_registered_entry_opens_to_the_sealed_key_under_the_root() {
    let fixture = Fixture::new();
    let (query, response) = fixture.entry();
    let entry = fixture.read().decode(&query, response).unwrap();
    assert_eq!(entry.sealed, fixture.envelope.sealed);
    let opened = entry.open(&fixture.auditor).unwrap();
    assert_eq!(
        opened.secret().as_slice(),
        fixture.nullifier_key.secret().as_slice()
    );
    assert!(entry.open(&X25519Secret::new()).is_err());
}

#[test]
fn a_known_nullifier_public_key_authenticates_the_entry_without_decryption() {
    let fixture = Fixture::new();
    let (query, response) = fixture.entry();
    let public_key = fixture.nullifier_key.pubkey().unwrap();
    let entry = fixture.read().decode(&query, response.clone()).unwrap();
    entry.verify_nullifier_pubkey(&public_key).unwrap();
    let other = NullifierKey::from_secret([8; 31]).pubkey().unwrap();
    assert!(matches!(
        entry.verify_nullifier_pubkey(&other),
        Err(RingError::InvalidEntryProof)
    ));
    assert!(matches!(
        entry.opening(&other),
        Err(RingError::UnregisteredOutputKey { owner }) if owner == fixture.member
    ));

    let mutations: [fn(&mut GetRingKeyRegistryEntryResponse); 2] = [
        |response| response.ciphertext.0[31] ^= 1,
        |response| response.proof[0].0[31] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = response.clone();
        mutate(&mut changed);
        let entry = fixture.read().decode(&query, changed).unwrap();
        assert!(matches!(
            entry.verify_nullifier_pubkey(&public_key),
            Err(RingError::InvalidEntryProof)
        ));
    }
}

#[test]
fn a_substituted_entry_or_path_is_refused() {
    let mutations: [fn(&mut GetRingKeyRegistryEntryResponse); 7] = [
        |response| response.root.0[31] ^= 1,
        |response| response.member.0[31] ^= 1,
        |response| response.next_index += 1,
        |response| response.index = 0,
        |response| response.index = response.next_index,
        |response| {
            response.proof.pop();
        },
        |response| {
            response.eph_pk.0.pop();
        },
    ];
    for mutate in mutations {
        let fixture = Fixture::new();
        let (query, mut response) = fixture.entry();
        mutate(&mut response);
        assert!(matches!(
            fixture.read().decode(&query, response),
            Err(RingError::InvalidEntryProof)
        ));
    }
    // A path that verifies under another leaf opens to nothing.
    let fixture = Fixture::new();
    let (query, mut response) = fixture.entry();
    response.proof[0].0[31] ^= 1;
    let entry = fixture.read().decode(&query, response).unwrap();
    assert!(matches!(
        entry.open(&fixture.auditor),
        Err(RingError::InvalidEntryProof)
    ));
}

/// Serves the registry root and the fixture's entry, every other member is unregistered.
struct EntryIndexer {
    ring: CustomRing,
    entry: (RingMemberProofRequest, GetRingKeyRegistryEntryResponse),
    calls: Mutex<usize>,
    root_reads: Mutex<usize>,
    /// Answered in order before the entry.
    lag: Mutex<Vec<ClientError>>,
}

impl EntryIndexer {
    fn new(fixture: &Fixture) -> Self {
        Self {
            ring: fixture.ring,
            entry: fixture.entry(),
            calls: Mutex::new(0),
            root_reads: Mutex::new(0),
            lag: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }

    fn root_reads(&self) -> usize {
        *self.root_reads.lock().unwrap()
    }
}

#[async_trait]
impl AsyncRpc for EntryIndexer {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        assert_eq!(address, self.ring.key_registry_root_pda());
        *self.root_reads.lock().unwrap() += 1;
        let mut history = [[0; 32]; KEY_REGISTRY_ROOT_HISTORY];
        history[1] = self.entry.1.root.0;
        let root = KeyRegistryRoot {
            discriminator: KEY_REGISTRY_ROOT,
            next_index: self.entry.1.next_index.to_le_bytes(),
            bump: Address::find_program_address(&[KeyRegistryRoot::SEED], &self.ring.program_id())
                .1,
            history_cursor: 1,
            history,
        };
        Ok(Some(account(self.ring.program_id(), &root)))
    }

    async fn get_ring_key_registry_entry(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
        *self.calls.lock().unwrap() += 1;
        let mut lag = self.lag.lock().unwrap();
        if !lag.is_empty() {
            return Err(lag.remove(0));
        }
        if request == self.entry.0 {
            return Ok(self.entry.1.clone());
        }
        Err(ClientError::RingKeyRegistryMemberUnregistered)
    }
}

fn output_key(owner: &Member, nullifier_pk: [u8; 32]) -> Option<OutputKey> {
    Some(OutputKey {
        owner_pk_hash: *owner.as_bytes(),
        nullifier_pk,
    })
}

#[tokio::test]
async fn an_enrolled_output_key_opens_its_registry_leaf_once_per_owner() {
    let fixture = Fixture::new();
    let indexer = EntryIndexer::new(&fixture);
    let registry = KeyRegistry { ring: fixture.ring };
    let key = output_key(&fixture.member, fixture.envelope.nullifier_pk);
    let escrowed = registry
        .openings(&indexer, &[key, None, key])
        .await
        .unwrap();
    assert_eq!(escrowed.root, fixture.root());
    assert_eq!(indexer.calls(), 1);
    let openings = escrowed.keys;
    assert_eq!(openings[1], None);
    let opening = openings[0].unwrap();
    assert_eq!(openings[2], Some(opening));
    assert_eq!(opening.index, 1);
    assert_eq!(
        opening.ct_hash,
        ciphertext_hash(&fixture.envelope.sealed.ciphertext).unwrap()
    );
    let leaf = KeyRegistryLeaf {
        member: fixture.member.as_bytes(),
        next: &opening.next,
        key: &RegisteredKey {
            nullifier_pk: &fixture.envelope.nullifier_pk,
            ciphertext: &fixture.envelope.sealed.ciphertext,
        }
        .hash()
        .unwrap(),
    }
    .hash()
    .unwrap();
    assert_eq!(
        MerklePath {
            index: opening.index,
            siblings: &opening.path,
        }
        .root_of(leaf)
        .unwrap(),
        fixture.new_root
    );
}

#[tokio::test]
async fn a_zero_key_output_is_refused_before_proving() {
    let fixture = Fixture::new();
    let indexer = EntryIndexer::new(&fixture);
    let registry = KeyRegistry { ring: fixture.ring };
    let stranger = Member::owner_tag(&[4; 32]).unwrap();
    for owner in [stranger, fixture.member] {
        assert!(matches!(
            registry.openings(&indexer, &[output_key(&owner, ZERO_NULLIFIER_PK)]).await,
            Err(RingError::UnregisteredOutputKey { owner: refused }) if refused == owner
        ));
    }
}

#[tokio::test]
async fn an_unregistered_owner_or_another_key_is_refused_before_proving() {
    let fixture = Fixture::new();
    let indexer = EntryIndexer::new(&fixture);
    let registry = KeyRegistry { ring: fixture.ring };
    let stranger = Member::owner_tag(&[4; 32]).unwrap();
    assert!(matches!(
        registry.openings(&indexer, &[output_key(&stranger, [7; 32])]).await,
        Err(RingError::UnregisteredOutputKey { owner }) if owner == stranger
    ));
    let other_key = NullifierKey::from_secret([8; 31]).pubkey().unwrap();
    assert!(matches!(
        registry.openings(&indexer, &[output_key(&fixture.member, other_key)]).await,
        Err(RingError::UnregisteredOutputKey { owner }) if owner == fixture.member
    ));
}

#[tokio::test]
async fn openings_leave_a_lagging_projection_to_the_caller() {
    let fixture = Fixture::new();
    let indexer = EntryIndexer::new(&fixture);
    let registry = KeyRegistry { ring: fixture.ring };
    let key = output_key(&fixture.member, fixture.envelope.nullifier_pk);
    *indexer.lag.lock().unwrap() = vec![ClientError::RingKeyRegistryRootChanged];
    let lagging = registry.openings(&indexer, &[key]).await;
    assert!(matches!(
        lagging,
        Err(RingError::Client(ClientError::RingKeyRegistryRootChanged))
    ));
    assert!(lagging.unwrap_err().is_projection_lag());
    assert_eq!(indexer.calls(), 1);
}

#[tokio::test]
async fn a_lagging_projection_is_asked_again_under_a_fresh_root() {
    let fixture = Fixture::new();
    let indexer = EntryIndexer::new(&fixture);
    let registry = KeyRegistry { ring: fixture.ring };
    *indexer.lag.lock().unwrap() = vec![
        ClientError::RingKeyRegistryRootChanged,
        ClientError::RingKeyRegistryOutOfSync,
    ];
    let keys = [output_key(&fixture.member, fixture.envelope.nullifier_pk)];
    let escrowed = retry_projection_lag(|| registry.openings(&indexer, &keys))
        .await
        .unwrap();
    assert!(escrowed.keys[0].is_some());
    assert_eq!(indexer.calls(), 3);
    assert_eq!(indexer.root_reads(), 3);
}

#[tokio::test]
async fn the_current_sealed_key_reads_under_the_on_chain_root() {
    let fixture = Fixture::new();
    let indexer = EntryIndexer::new(&fixture);
    *indexer.lag.lock().unwrap() = vec![ClientError::RingKeyRegistryOutOfSync];
    let entry = ReadCurrentSealedKey {
        ring: fixture.ring,
        member: fixture.member,
    }
    .read(&indexer)
    .await
    .unwrap()
    .unwrap();
    assert_eq!(entry.sealed, fixture.envelope.sealed);
    assert_eq!(indexer.root_reads(), 2);
}

#[test]
fn a_prover_registry_miss_names_the_unenrolled_owner() {
    let member = Member::owner_tag(&[9; 32]).unwrap();
    assert!(matches!(
        RingError::from(ClientError::RegistryMemberMissing {
            member: *member.as_bytes()
        }),
        RingError::UnregisteredOutputKey { owner } if owner == member
    ));
    // The zero pad is no owner, the client error stays.
    assert!(matches!(
        RingError::from(ClientError::RegistryMemberMissing { member: [0; 32] }),
        RingError::Client(ClientError::RegistryMemberMissing { .. })
    ));
}
