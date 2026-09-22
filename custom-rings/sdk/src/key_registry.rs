//! Seals a member's nullifier key to the ring auditor and appends it to the key registry.

use custom_ring_interface::{
    tag, CustomRingProof, KeyRegistryInsert, KeyRegistryLeaf, KeyRegistryTransition, MerklePath,
    RegisterKeyIxData, RegisterKeyPublicInput, RegisteredKey, AUDIT_CIPHERTEXT_LEN,
    COMPRESSED_P256_KEY_LEN, KEY_REGISTRY_CAPACITY, KEY_REGISTRY_HEIGHT,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Serialize;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_client::{
    prover::{Delivery, ProveRequest, Prover},
    AsyncRpc, ClientError, Rpc,
};
use zolana_hasher::primitives::right_align;
use zolana_indexer_api::{
    GetRingKeyRegistryEntryResponse, GetRingKeyRegistryRegisterProofResponse, Hash,
    RingMemberProofRequest, SerializablePubkey,
};
use zolana_interface::merge_utils::ciphertext_hash;
use zolana_keypair::{KeypairError, NullifierKey, P256Pubkey, ShieldedKeypair, ViewingKey};
use zolana_ring_client::{AuditEncryptionError, NullifierKeyEnvelope, SealedNullifierKey};
use zolana_ring_policy::Member;

use crate::{
    escrow::RegistryKeyOpening,
    instructions::transact::request::{bytes_to_hex, field_hex, index_hex, json_body, SecretHex},
    projection::{retry_projection_lag, retry_projection_lag_async, ProjectionLag},
    to_instruction_proof, AccountReadError, AsyncTransferProofEnvironment, CurrentKeyRegistryRoot,
    CustomRing, CustomRingProofError, TransferProofEnvironment,
};

#[derive(Debug, Error)]
pub enum KeyRegistrationError {
    #[error(transparent)]
    Client(Box<ClientError>),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Envelope(#[from] AuditEncryptionError),
    #[error("the ring has no config")]
    MissingRingConfig,
    #[error("the ring has no key registry")]
    MissingKeyRegistry,
    #[error("the member's nullifier key does not derive its address")]
    NullifierKeyMismatch,
    #[error("hashing failed")]
    Hashing,
    #[error("the key-registry response does not match the requested root or member")]
    InvalidRegisterProof,
    #[error("the key-registry entry is not included under the requested root")]
    InvalidEntryProof,
    #[error("{owner:?} enrolled no matching nullifier key")]
    UnregisteredOutputKey { owner: Member },
    #[error(transparent)]
    Proof(#[from] CustomRingProofError),
    #[error(transparent)]
    Encoding(#[from] wincode::WriteError),
}

impl KeyRegistrationError {
    /// Photon trails or passed the root asked for, a fresh chain root settles either.
    pub fn is_projection_lag(&self) -> bool {
        matches!(self, Self::Client(error) if matches!(
            error.as_ref(),
            ClientError::RingKeyRegistryOutOfSync | ClientError::RingKeyRegistryRootChanged
        ))
    }
}

impl ProjectionLag for KeyRegistrationError {
    fn is_projection_lag(&self) -> bool {
        KeyRegistrationError::is_projection_lag(self)
    }
}

impl From<ClientError> for KeyRegistrationError {
    fn from(error: ClientError) -> Self {
        Self::Client(Box::new(error))
    }
}

#[must_use]
#[derive(Clone, Copy)]
pub struct RegisterKey<'a> {
    pub ring: CustomRing,
    /// Also the payer, the member identity derives from it.
    pub member: &'a ShieldedKeypair,
}

impl RegisterKey<'_> {
    pub fn prove<I: Rpc, R: Rpc>(
        self,
        env: TransferProofEnvironment<'_, I, R>,
    ) -> Result<ProvenKeyRegistration, KeyRegistrationError> {
        // 1. Solana state pins the auditor recipient and the registry root.
        let auditor = self
            .ring
            .read_config(env.rpc)?
            .ok_or(KeyRegistrationError::MissingRingConfig)?
            .auditor_pubkey;
        let Witnessed {
            staged,
            registration:
                KeyRegistration {
                    request,
                    transition,
                },
        } = retry_projection_lag(|| {
            let root = self
                .ring
                .read_key_registry_root(env.rpc)?
                .ok_or(KeyRegistrationError::MissingKeyRegistry)?;
            let staged = self.stage(auditor, root)?;
            let response = env
                .indexer
                .get_ring_key_registry_register_proof(staged.query.clone())?;
            staged.witnessed(response)
        })?;
        // 2. Registration proves key disclosure without authorizing ownership
        // transfers or withdrawals.
        let proof = to_instruction_proof(env.prover.prove(&request)?)?;
        Ok(staged.finish(transition, proof))
    }

    pub async fn prove_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: AsyncTransferProofEnvironment<'_, I, R>,
    ) -> Result<ProvenKeyRegistration, KeyRegistrationError> {
        let auditor = self
            .ring
            .read_config_async(env.rpc)
            .await?
            .ok_or(KeyRegistrationError::MissingRingConfig)?
            .auditor_pubkey;
        let (rpc, indexer) = (env.rpc, env.indexer);
        let Witnessed {
            staged,
            registration:
                KeyRegistration {
                    request,
                    transition,
                },
        } = retry_projection_lag_async(|| async move {
            let root = self
                .ring
                .read_key_registry_root_async(rpc)
                .await?
                .ok_or(KeyRegistrationError::MissingKeyRegistry)?;
            let staged = self.stage(auditor, root)?;
            let response = indexer
                .get_ring_key_registry_register_proof(staged.query.clone())
                .await?;
            staged.witnessed(response)
        })
        .await?;
        let proof = to_instruction_proof(env.prover.prove(&request).await?)?;
        Ok(staged.finish(transition, proof))
    }

    /// Registration binds the submitted key, not the keys of future notes.
    fn stage(
        self,
        auditor: P256Pubkey,
        root: CurrentKeyRegistryRoot,
    ) -> Result<StagedKeyRegistration, KeyRegistrationError> {
        let address = Address::new_from_array(self.member.signing_pubkey().as_ed25519()?);
        if self.member.nullifier_key.pubkey()? != self.member.shielded_address()?.nullifier_pubkey {
            return Err(KeyRegistrationError::NullifierKeyMismatch);
        }
        let envelope = NullifierKeyEnvelope::new(&self.member.nullifier_key, &auditor)?;
        let secret = Zeroizing::new(right_align(&self.member.nullifier_key.secret()));
        let member =
            Member::owner_tag(address.as_array()).map_err(|_| KeyRegistrationError::Hashing)?;
        Ok(StagedKeyRegistration {
            ring: self.ring,
            member: address,
            auditor,
            envelope,
            secret,
            query: self.ring.member_proof_request(&member, root),
            registry_next_index: root.next_index,
        })
    }
}

struct StagedKeyRegistration {
    ring: CustomRing,
    member: Address,
    auditor: P256Pubkey,
    envelope: NullifierKeyEnvelope,
    secret: Zeroizing<[u8; 32]>,
    query: RingMemberProofRequest,
    registry_next_index: u64,
}

/// The registry witness holds only under the root the staged insert names.
struct Witnessed {
    staged: StagedKeyRegistration,
    registration: KeyRegistration,
}

impl StagedKeyRegistration {
    fn witnessed(
        self,
        response: GetRingKeyRegistryRegisterProofResponse,
    ) -> Result<Witnessed, KeyRegistrationError> {
        let registration = KeySeal {
            envelope: &self.envelope,
            auditor: self.auditor,
            secret: self.secret.clone(),
        }
        .register(&self.query, response)?;
        Ok(Witnessed {
            staged: self,
            registration,
        })
    }

    fn finish(
        self,
        transition: KeyRegistryTransition,
        proof: CustomRingProof,
    ) -> ProvenKeyRegistration {
        ProvenKeyRegistration {
            ring: self.ring,
            member: self.member,
            transition,
            registry_next_index: self.registry_next_index,
            nullifier_pk: self.envelope.nullifier_pk,
            eph_pk: *self.envelope.sealed.eph_pk.as_bytes(),
            ciphertext: self.envelope.sealed.ciphertext,
            proof,
        }
    }
}

#[must_use]
pub struct ProvenKeyRegistration {
    ring: CustomRing,
    member: Address,
    transition: KeyRegistryTransition,
    registry_next_index: u64,
    nullifier_pk: [u8; 32],
    eph_pk: [u8; COMPRESSED_P256_KEY_LEN],
    ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
    proof: CustomRingProof,
}

impl ProvenKeyRegistration {
    pub fn instruction(self) -> Result<Instruction, KeyRegistrationError> {
        let mut data = vec![tag::REGISTER_KEY];
        data.extend_from_slice(&wincode::serialize(&RegisterKeyIxData {
            proof: self.proof,
            registry_old_root: self.transition.old_root,
            registry_new_root: self.transition.new_root,
            registry_next_index: self.registry_next_index,
            nullifier_pk: self.nullifier_pk,
            eph_pk: self.eph_pk,
            ciphertext: self.ciphertext,
        })?);
        Ok(Instruction {
            program_id: self.ring.program_id(),
            accounts: vec![
                AccountMeta::new_readonly(self.member, true),
                AccountMeta::new_readonly(self.ring.config_pda(), false),
                AccountMeta::new(self.ring.key_registry_root_pda(), false),
            ],
            data,
        })
    }
}

#[must_use]
pub struct ReadSealedKey {
    pub ring: CustomRing,
    pub member: Member,
    pub root: CurrentKeyRegistryRoot,
}

/// Membership requires the recovered or expected nullifier public key to verify
/// the leaf.
pub struct SealedKeyEntry {
    pub sealed: SealedNullifierKey,
    member: Member,
    root: [u8; 32],
    next: [u8; 32],
    index: u64,
    proof: Vec<[u8; 32]>,
}

impl ReadSealedKey {
    pub fn read<I: Rpc>(self, indexer: &I) -> Result<SealedKeyEntry, KeyRegistrationError> {
        let query = self.ring.member_proof_request(&self.member, self.root);
        let response = indexer.get_ring_key_registry_entry(query.clone())?;
        self.decode_entry(&query, response)
    }

    pub async fn read_async<I: AsyncRpc>(
        self,
        indexer: &I,
    ) -> Result<SealedKeyEntry, KeyRegistrationError> {
        let query = self.ring.member_proof_request(&self.member, self.root);
        let response = indexer.get_ring_key_registry_entry(query.clone()).await?;
        self.decode_entry(&query, response)
    }

    fn decode_entry(
        self,
        query: &RingMemberProofRequest,
        response: GetRingKeyRegistryEntryResponse,
    ) -> Result<SealedKeyEntry, KeyRegistrationError> {
        if response.root != query.expected_root
            || response.member != query.member
            || response.next_index != query.expected_next_index
            || response.index == 0
            || response.index >= response.next_index
            || response.next_index > KEY_REGISTRY_CAPACITY
            || response.proof.len() != KEY_REGISTRY_HEIGHT
        {
            return Err(KeyRegistrationError::InvalidEntryProof);
        }
        let eph_pk: [u8; COMPRESSED_P256_KEY_LEN] = response
            .eph_pk
            .0
            .as_slice()
            .try_into()
            .map_err(|_| KeyRegistrationError::InvalidEntryProof)?;
        let sealed = SealedNullifierKey {
            eph_pk: P256Pubkey::from_bytes(eph_pk)
                .map_err(|_| KeyRegistrationError::InvalidEntryProof)?,
            ciphertext: response
                .ciphertext
                .0
                .as_slice()
                .try_into()
                .map_err(|_| KeyRegistrationError::InvalidEntryProof)?,
        };
        Ok(SealedKeyEntry {
            sealed,
            member: self.member,
            root: response.root.0,
            next: response.next.0,
            index: response.index,
            proof: response.proof.into_iter().map(|hash| hash.0).collect(),
        })
    }
}

impl SealedKeyEntry {
    /// The opened key must reproduce the leaf under the root read from Solana.
    pub fn open(&self, auditor: &ViewingKey) -> Result<NullifierKey, KeyRegistrationError> {
        // 1. The auditor recovers the nullifier key without an owner signing
        // key.
        let nullifier_key = self.sealed.open(auditor)?;
        self.verify_nullifier_pubkey(&nullifier_key.pubkey()?)?;
        Ok(nullifier_key)
    }

    pub fn opening(
        &self,
        nullifier_pubkey: &[u8; 32],
    ) -> Result<RegistryKeyOpening, KeyRegistrationError> {
        let path = self
            .proof
            .as_slice()
            .try_into()
            .map_err(|_| KeyRegistrationError::InvalidEntryProof)?;
        // `decode_entry` pinned the path and index, only another key misses the root.
        self.verify_nullifier_pubkey(nullifier_pubkey)
            .map_err(|error| match error {
                KeyRegistrationError::InvalidEntryProof => {
                    KeyRegistrationError::UnregisteredOutputKey { owner: self.member }
                }
                error => error,
            })?;
        Ok(RegistryKeyOpening {
            next: self.next,
            ct_hash: ciphertext_hash(&self.sealed.ciphertext)
                .map_err(|_| KeyRegistrationError::Hashing)?,
            index: self.index,
            path,
        })
    }

    /// Verifies membership for a known nullifier public key without the auditor
    /// read key.
    pub fn verify_nullifier_pubkey(
        &self,
        nullifier_pubkey: &[u8; 32],
    ) -> Result<(), KeyRegistrationError> {
        // 1. The expected key and ciphertext must reproduce the pinned registry
        // root.
        let key = RegisteredKey {
            nullifier_pk: nullifier_pubkey,
            ciphertext: &self.sealed.ciphertext,
        }
        .hash()
        .map_err(|_| KeyRegistrationError::Hashing)?;
        let leaf = KeyRegistryLeaf {
            member: self.member.as_bytes(),
            next: &self.next,
            key: &key,
        }
        .hash()
        .map_err(|_| KeyRegistrationError::Hashing)?;
        let root = MerklePath {
            index: self.index,
            siblings: &self.proof,
        }
        .root_of(leaf)
        .map_err(|_| KeyRegistrationError::InvalidEntryProof)?;
        if root != self.root {
            return Err(KeyRegistrationError::InvalidEntryProof);
        }
        Ok(())
    }
}

impl CustomRing {
    fn member_proof_request(
        self,
        member: &Member,
        root: CurrentKeyRegistryRoot,
    ) -> RingMemberProofRequest {
        RingMemberProofRequest {
            ring_program_id: SerializablePubkey::from(self.program_id().to_bytes()),
            member: Hash(*member.as_bytes()),
            expected_root: Hash(root.root),
            expected_next_index: root.next_index,
        }
    }
}

pub(crate) struct KeySeal<'a> {
    pub envelope: &'a NullifierKeyEnvelope,
    pub auditor: P256Pubkey,
    /// The 31-byte secret right aligned, high byte zero pins it below the field order.
    pub secret: Zeroizing<[u8; 32]>,
}

pub(crate) struct KeyRegistration {
    pub request: RegisterKeyProofRequest,
    pub transition: KeyRegistryTransition,
}

impl KeySeal<'_> {
    pub(crate) fn register(
        self,
        query: &RingMemberProofRequest,
        response: GetRingKeyRegistryRegisterProofResponse,
    ) -> Result<KeyRegistration, KeyRegistrationError> {
        let key = RegisteredKey {
            nullifier_pk: &self.envelope.nullifier_pk,
            ciphertext: &self.envelope.sealed.ciphertext,
        }
        .hash()
        .map_err(|_| KeyRegistrationError::Hashing)?;
        if response.root != query.expected_root
            || response.member != query.member
            || response.next_index != query.expected_next_index
            || response.low_index >= response.next_index
        {
            return Err(KeyRegistrationError::InvalidRegisterProof);
        }
        let low_proof: Vec<_> = response.low_proof.iter().map(|hash| hash.0).collect();
        let new_proof: Vec<_> = response.new_proof.iter().map(|hash| hash.0).collect();
        let new_root = KeyRegistryInsert {
            root: &response.root.0,
            append_index: response.next_index,
            member: &response.member.0,
            key: &key,
            low_member: &response.low_member.0,
            low_next: &response.low_next.0,
            low_key: &response.low_key_hash.0,
            low_index: response.low_index,
            low_proof: &low_proof,
            new_proof: &new_proof,
        }
        .verify()
        .map_err(|_| KeyRegistrationError::InvalidRegisterProof)?;
        let transition = KeyRegistryTransition {
            old_root: response.root.0,
            new_root,
        };
        let public_input = RegisterKeyPublicInput {
            registry_old_root: &transition.old_root,
            registry_new_root: &transition.new_root,
            member: &response.member.0,
            nullifier_pk: &self.envelope.nullifier_pk,
            auditor_pk: self.auditor.as_bytes(),
            eph_pk: self.envelope.sealed.eph_pk.as_bytes(),
            ciphertext: &self.envelope.sealed.ciphertext,
            new_index: response.next_index,
        }
        .hash()
        .map_err(|_| KeyRegistrationError::Hashing)?;
        // The circuit witnesses the auditor key SEC1 uncompressed, the packing hashes it compressed.
        let auditor_uncompressed = self.auditor.to_p256()?.to_encoded_point(false);
        Ok(KeyRegistration {
            request: RegisterKeyProofRequest {
                public_input_hash: field_hex(&public_input),
                registry_old_root: field_hex(&transition.old_root),
                registry_new_root: field_hex(&transition.new_root),
                member: field_hex(&response.member.0),
                new_index: index_hex(response.next_index),
                nullifier_secret: self.secret,
                eph_sk: self.envelope.ephemeral_sk.clone(),
                auditor_pk: bytes_to_hex(auditor_uncompressed.as_bytes()),
                low_member: field_hex(&response.low_member.0),
                low_next: field_hex(&response.low_next.0),
                low_key: field_hex(&response.low_key_hash.0),
                low_index: index_hex(response.low_index),
                low_proof: low_proof.iter().map(field_hex).collect(),
                new_proof: new_proof.iter().map(field_hex).collect(),
            },
            transition,
        })
    }
}

pub(crate) struct RegisterKeyProofRequest {
    public_input_hash: String,
    registry_old_root: String,
    registry_new_root: String,
    member: String,
    new_index: String,
    nullifier_secret: Zeroizing<[u8; 32]>,
    eph_sk: Zeroizing<[u8; 32]>,
    auditor_pk: String,
    low_member: String,
    low_next: String,
    low_key: String,
    low_index: String,
    low_proof: Vec<String>,
    new_proof: Vec<String>,
}

impl ProveRequest for RegisterKeyProofRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        json_body(&RegisterKeyProofRequestJson {
            circuit_type: "custom-ring-register-key",
            public_input_hash: &self.public_input_hash,
            registry_old_root: &self.registry_old_root,
            registry_new_root: &self.registry_new_root,
            member: &self.member,
            new_index: &self.new_index,
            nullifier_secret: SecretHex::new(self.nullifier_secret.as_slice()),
            eph_sk: SecretHex::new(self.eph_sk.as_slice()),
            auditor_pk: &self.auditor_pk,
            low_member: &self.low_member,
            low_next: &self.low_next,
            low_key: &self.low_key,
            low_index: &self.low_index,
            low_proof: &self.low_proof,
            new_proof: &self.new_proof,
        })
    }

    fn delivery(&self) -> Delivery {
        Delivery::Queued
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterKeyProofRequestJson<'a> {
    circuit_type: &'static str,
    public_input_hash: &'a str,
    registry_old_root: &'a str,
    registry_new_root: &'a str,
    member: &'a str,
    new_index: &'a str,
    nullifier_secret: SecretHex,
    eph_sk: SecretHex,
    auditor_pk: &'a str,
    low_member: &'a str,
    low_next: &'a str,
    low_key: &'a str,
    low_index: &'a str,
    low_proof: &'a [String],
    new_proof: &'a [String],
}

#[cfg(test)]
mod tests {
    use zolana_indexer_api::{Base64String, Context};
    use zolana_keypair::{NullifierKey, ViewingKey};
    use zolana_ring_key_registry::{KeyRegistryTree, Registration};
    use zolana_ring_policy::ZERO_NULLIFIER_PK;

    use super::*;
    use crate::{
        escrow::{KeyRegistry, OutputKey},
        ReadEnvironment,
    };

    struct Fixture {
        ring: CustomRing,
        member: Member,
        query: RingMemberProofRequest,
        response: GetRingKeyRegistryRegisterProofResponse,
        auditor: ViewingKey,
        nullifier_key: NullifierKey,
        envelope: NullifierKeyEnvelope,
        tree: KeyRegistryTree,
        new_root: [u8; 32],
    }

    impl Fixture {
        /// One sealed key at index 1 above the sentinel, the response an indexer serves for it.
        fn new() -> Self {
            let ring = CustomRing::new(Address::new_from_array([5; 32]));
            let auditor = ViewingKey::new();
            let nullifier_key = NullifierKey::from_secret([7u8; 31]);
            let envelope =
                NullifierKeyEnvelope::new(&nullifier_key, &auditor.pubkey()).expect("seal");
            let member = Member::owner_tag(&[9; 32]).expect("member");
            let key = RegisteredKey {
                nullifier_pk: &envelope.nullifier_pk,
                ciphertext: &envelope.sealed.ciphertext,
            }
            .hash()
            .expect("key hash");
            let mut tree = KeyRegistryTree::new().expect("tree");
            let proof_inputs = tree
                .register(Registration {
                    member: *member.as_bytes(),
                    key,
                })
                .expect("register");
            let query = ring.member_proof_request(
                &member,
                CurrentKeyRegistryRoot {
                    root: proof_inputs.old_root,
                    next_index: proof_inputs.new_index,
                    history_index: 0,
                },
            );
            let response = GetRingKeyRegistryRegisterProofResponse {
                context: Context::default(),
                root: Hash(proof_inputs.old_root),
                next_index: proof_inputs.new_index,
                member: Hash(proof_inputs.member),
                low_member: Hash(proof_inputs.low_member),
                low_next: Hash(proof_inputs.low_next),
                low_key_hash: Hash(proof_inputs.low_key),
                low_index: proof_inputs.low_index,
                low_proof: proof_inputs.low_proof.into_iter().map(Hash).collect(),
                new_proof: proof_inputs.new_proof.into_iter().map(Hash).collect(),
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
                new_root: proof_inputs.new_root,
            }
        }

        fn seal(&self) -> KeySeal<'_> {
            KeySeal {
                envelope: &self.envelope,
                auditor: self.auditor.pubkey(),
                secret: Zeroizing::new(right_align(&self.nullifier_key.secret())),
            }
        }

        /// The registered slot as the indexer serves it after the append.
        fn entry(&self) -> (RingMemberProofRequest, GetRingKeyRegistryEntryResponse) {
            let inclusion = self
                .tree
                .member_proof(self.member.as_bytes())
                .expect("inclusion");
            let query = self.ring.member_proof_request(
                &self.member,
                CurrentKeyRegistryRoot {
                    root: self.new_root,
                    next_index: 2,
                    history_index: 1,
                },
            );
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
                root: CurrentKeyRegistryRoot {
                    root: self.new_root,
                    next_index: 2,
                    history_index: 1,
                },
            }
        }
    }

    #[test]
    fn registration_matches_the_reference_and_encodes_the_prover_wire() {
        let fixture = Fixture::new();
        let KeyRegistration {
            request,
            transition,
        } = fixture
            .seal()
            .register(&fixture.query, fixture.response.clone())
            .expect("build");
        assert_eq!(transition.old_root, fixture.query.expected_root.0);
        assert_eq!(transition.new_root, fixture.new_root);
        let json: serde_json::Value =
            serde_json::from_str(request.body().expect("body").as_str()).expect("json");
        assert_eq!(json["circuitType"], "custom-ring-register-key");
        assert_eq!(
            json["newIndex"],
            index_hex(fixture.query.expected_next_index)
        );
        assert_eq!(json["registryNewRoot"], field_hex(&fixture.new_root));
        assert_eq!(
            json["lowProof"].as_array().expect("low").len(),
            KEY_REGISTRY_HEIGHT
        );
        assert_eq!(
            json["newProof"].as_array().expect("new").len(),
            KEY_REGISTRY_HEIGHT
        );
        // The nullifier secret rides right aligned, its high byte pins it below the field order.
        let secret = json["nullifierSecret"].as_str().expect("secret");
        assert_eq!(secret.len(), 66);
        assert!(secret.starts_with("0x00"));
        // The auditor key is witnessed SEC1 uncompressed, 65 bytes behind the `0x`.
        assert_eq!(json["auditorPk"].as_str().expect("auditor").len(), 132);
        assert_eq!(json["ephSk"].as_str().expect("eph").len(), 66);
    }

    #[test]
    fn registration_rejects_response_substitution_and_malformed_paths() {
        let fixture = Fixture::new();
        let mutations: [fn(&mut GetRingKeyRegistryRegisterProofResponse); 5] = [
            |response| response.root.0[31] ^= 1,
            |response| response.member.0[31] ^= 1,
            |response| response.next_index += 1,
            |response| {
                response.low_proof.pop();
            },
            |response| response.new_proof[0].0[31] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = fixture.response.clone();
            mutate(&mut changed);
            assert!(matches!(
                fixture.seal().register(&fixture.query, changed),
                Err(KeyRegistrationError::InvalidRegisterProof)
            ));
        }
    }

    #[test]
    fn the_registered_entry_opens_to_the_sealed_key_under_the_root() {
        let fixture = Fixture::new();
        let (query, response) = fixture.entry();
        let entry = fixture
            .read()
            .decode_entry(&query, response)
            .expect("included");
        assert_eq!(entry.sealed, fixture.envelope.sealed);
        let opened = entry.open(&fixture.auditor).expect("open");
        assert_eq!(
            opened.secret().as_slice(),
            fixture.nullifier_key.secret().as_slice()
        );
        assert!(matches!(
            entry.open(&ViewingKey::new()),
            Err(
                KeyRegistrationError::Envelope(AuditEncryptionError::NullifierPad)
                    | KeyRegistrationError::InvalidEntryProof
            )
        ));
    }

    #[test]
    fn a_known_nullifier_public_key_authenticates_the_entry_without_decryption() {
        let fixture = Fixture::new();
        let (query, response) = fixture.entry();
        let public_key = fixture.nullifier_key.pubkey().unwrap();
        let entry = fixture
            .read()
            .decode_entry(&query, response.clone())
            .unwrap();
        entry.verify_nullifier_pubkey(&public_key).unwrap();
        assert!(matches!(
            entry.verify_nullifier_pubkey(&NullifierKey::from_secret([8; 31]).pubkey().unwrap()),
            Err(KeyRegistrationError::InvalidEntryProof)
        ));

        let mutations: [fn(&mut GetRingKeyRegistryEntryResponse); 2] = [
            |response| response.ciphertext.0[31] ^= 1,
            |response| response.proof[0].0[31] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = response.clone();
            mutate(&mut changed);
            let entry = fixture.read().decode_entry(&query, changed).unwrap();
            assert!(matches!(
                entry.verify_nullifier_pubkey(&public_key),
                Err(KeyRegistrationError::InvalidEntryProof)
            ));
        }
    }

    #[test]
    fn a_substituted_entry_or_path_is_refused() {
        let mutations: [fn(&mut GetRingKeyRegistryEntryResponse); 6] = [
            |response| response.root.0[31] ^= 1,
            |response| response.member.0[31] ^= 1,
            |response| response.next_index += 1,
            |response| response.index = 0,
            |response| {
                response.proof.pop();
            },
            |response| response.eph_pk.0.pop().map(drop).unwrap_or(()),
        ];
        for mutate in mutations {
            let fixture = Fixture::new();
            let (query, mut response) = fixture.entry();
            mutate(&mut response);
            assert!(matches!(
                fixture.read().decode_entry(&query, response),
                Err(KeyRegistrationError::InvalidEntryProof)
            ));
        }
        // A path that verifies but under another leaf opens to nothing.
        let fixture = Fixture::new();
        let (query, mut response) = fixture.entry();
        response.proof[0].0[31] ^= 1;
        let entry = fixture
            .read()
            .decode_entry(&query, response)
            .expect("shape checks pass");
        assert!(matches!(
            entry.open(&fixture.auditor),
            Err(KeyRegistrationError::InvalidEntryProof)
        ));
    }

    /// Serves the registry root and the fixture's entry, every other member is unregistered.
    struct EntryIndexer {
        ring: CustomRing,
        entry: (RingMemberProofRequest, GetRingKeyRegistryEntryResponse),
        calls: std::cell::Cell<usize>,
        root_reads: std::cell::Cell<usize>,
        /// Answered in order before the entry.
        lag: std::cell::RefCell<Vec<ClientError>>,
    }

    impl Rpc for EntryIndexer {
        fn get_account(
            &self,
            address: Address,
        ) -> Result<Option<solana_account::Account>, ClientError> {
            let (expected, bump) =
                custom_ring_interface::pda::key_registry_root(&self.ring.program_id());
            assert_eq!(address, expected);
            self.root_reads.set(self.root_reads.get() + 1);
            let mut history = [[0; 32]; custom_ring_interface::KEY_REGISTRY_ROOT_HISTORY];
            history[1] = self.entry.1.root.0;
            let root = custom_ring_interface::KeyRegistryRoot {
                discriminator: custom_ring_interface::KEY_REGISTRY_ROOT,
                next_index: self.entry.1.next_index.to_le_bytes(),
                bump,
                history_cursor: 1,
                history,
            };
            Ok(Some(solana_account::Account {
                lamports: 1,
                data: bytemuck::bytes_of(&root).to_vec(),
                owner: self.ring.program_id(),
                executable: false,
                rent_epoch: 0,
            }))
        }

        fn get_ring_key_registry_entry(
            &self,
            request: RingMemberProofRequest,
        ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
            self.calls.set(self.calls.get() + 1);
            if !self.lag.borrow().is_empty() {
                return Err(self.lag.borrow_mut().remove(0));
            }
            if request == self.entry.0 {
                return Ok(self.entry.1.clone());
            }
            Err(ClientError::RingKeyRegistryMemberUnregistered)
        }
    }

    impl EntryIndexer {
        fn env(&self) -> ReadEnvironment<'_, Self, Self> {
            ReadEnvironment {
                indexer: self,
                rpc: self,
            }
        }
    }

    fn escrow(fixture: &Fixture) -> (KeyRegistry, EntryIndexer) {
        let entry = fixture.entry();
        (
            KeyRegistry { ring: fixture.ring },
            EntryIndexer {
                ring: fixture.ring,
                entry,
                calls: std::cell::Cell::new(0),
                root_reads: std::cell::Cell::new(0),
                lag: std::cell::RefCell::new(Vec::new()),
            },
        )
    }

    fn output_key(owner: &Member, nullifier_pk: [u8; 32]) -> Option<OutputKey> {
        Some(OutputKey {
            owner_pk_hash: *owner.as_bytes(),
            nullifier_pk,
        })
    }

    #[test]
    fn an_enrolled_output_key_opens_its_registry_leaf_once_per_owner() {
        let fixture = Fixture::new();
        let (registry, indexer) = escrow(&fixture);
        let key = output_key(&fixture.member, fixture.envelope.nullifier_pk);
        let escrowed = registry
            .openings(indexer.env(), &[key, None, key])
            .expect("enrolled");
        assert_eq!(escrowed.root, fixture.read().root);
        let openings = escrowed.keys;
        assert_eq!(indexer.calls.get(), 1);
        assert_eq!(openings[1], None);
        let opening = openings[0].expect("opening");
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

    #[test]
    fn a_zero_key_output_is_refused_before_proving() {
        let fixture = Fixture::new();
        let (registry, indexer) = escrow(&fixture);
        let stranger = Member::owner_tag(&[4; 32]).unwrap();
        for owner in [stranger, fixture.member] {
            assert!(matches!(
                registry.openings(indexer.env(), &[output_key(&owner, ZERO_NULLIFIER_PK)]),
                Err(KeyRegistrationError::UnregisteredOutputKey { owner: refused }) if refused == owner
            ));
        }
    }

    #[test]
    fn an_unregistered_owner_or_another_key_is_refused_before_proving() {
        let fixture = Fixture::new();
        let (registry, indexer) = escrow(&fixture);
        let stranger = Member::owner_tag(&[4; 32]).unwrap();
        assert!(matches!(
            registry.openings(indexer.env(), &[output_key(&stranger, [7; 32])]),
            Err(KeyRegistrationError::UnregisteredOutputKey { owner }) if owner == stranger
        ));
        let other_key = NullifierKey::from_secret([8; 31]).pubkey().unwrap();
        assert!(matches!(
            registry.openings(indexer.env(), &[output_key(&fixture.member, other_key)]),
            Err(KeyRegistrationError::UnregisteredOutputKey { owner }) if owner == fixture.member
        ));
    }

    #[test]
    fn a_lagging_projection_is_asked_again_under_a_fresh_root() {
        let fixture = Fixture::new();
        let (registry, indexer) = escrow(&fixture);
        indexer.lag.replace(vec![
            ClientError::RingKeyRegistryRootChanged,
            ClientError::RingKeyRegistryOutOfSync,
        ]);
        let key = output_key(&fixture.member, fixture.envelope.nullifier_pk);
        let escrowed = registry.openings(indexer.env(), &[key]).expect("caught up");
        assert!(escrowed.keys[0].is_some());
        assert_eq!(indexer.calls.get(), 3);
        assert_eq!(indexer.root_reads.get(), 3);
    }
}
