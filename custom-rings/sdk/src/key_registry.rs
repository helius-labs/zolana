//! Seals a member's nullifier key to the ring auditor and appends it to the key registry.

use custom_ring_interface::{
    tag, CustomRingProof, HeadMapLeaf, HeadMapTransition, MerklePath, RegisterKeyIxData,
    RegisterKeyPublicInput, RegisteredKey, AUDIT_CIPHERTEXT_LEN, COMPRESSED_P256_KEY_LEN,
    HEAD_MAP_CAPACITY, HEAD_MAP_HEIGHT,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Serialize;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_client::{
    prover::{Delivery, ProveRequest},
    AsyncRpc, ClientError, Rpc,
};
use zolana_hasher::primitives::right_align;
use zolana_indexer_api::{
    GetRingKeyRegistryEntryResponse, GetRingKeyRegistryRegisterProofResponse,
    RingMemberProofRequest,
};
use zolana_keypair::{KeypairError, NullifierKey, P256Pubkey, ShieldedKeypair, ViewingKey};
use zolana_ring_client::{AuditEncryptionError, NullifierKeyEnvelope, SealedNullifierKey};
use zolana_ring_policy::Member;

use crate::{
    head_map::{IndexedInsert, VerifiedInsert},
    instructions::transact::request::{bytes_to_hex, field_hex, index_hex, json_body, SecretHex},
    to_instruction_proof, AccountReadError, AsyncTransferProofEnvironment, CustomRing,
    CustomRingProofError, IndexedMapRoot, TransferProofEnvironment,
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
    #[error(transparent)]
    Proof(#[from] CustomRingProofError),
    #[error(transparent)]
    Encoding(#[from] wincode::WriteError),
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
        let root = self
            .ring
            .read_key_registry_root(env.rpc)?
            .ok_or(KeyRegistrationError::MissingKeyRegistry)?;
        let staged = self.stage(auditor, root)?;
        let response = env
            .indexer
            .get_ring_key_registry_register_proof(staged.query.clone())?;
        let KeyRegistration {
            request,
            transition,
        } = staged.request(response)?;
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
        let root = self
            .ring
            .read_key_registry_root_async(env.rpc)
            .await?
            .ok_or(KeyRegistrationError::MissingKeyRegistry)?;
        let staged = self.stage(auditor, root)?;
        let response = env
            .indexer
            .get_ring_key_registry_register_proof(staged.query.clone())
            .await?;
        let KeyRegistration {
            request,
            transition,
        } = staged.request(response)?;
        let proof = to_instruction_proof(env.prover.prove(&request).await?)?;
        Ok(staged.finish(transition, proof))
    }

    /// Registration binds the submitted key, not the keys of future notes.
    fn stage(
        self,
        auditor: P256Pubkey,
        root: IndexedMapRoot,
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

impl StagedKeyRegistration {
    fn request(
        &self,
        response: GetRingKeyRegistryRegisterProofResponse,
    ) -> Result<KeyRegistration, KeyRegistrationError> {
        KeySeal {
            envelope: &self.envelope,
            auditor: self.auditor,
            secret: self.secret.clone(),
        }
        .register(&self.query, response)
    }

    fn finish(
        self,
        transition: HeadMapTransition,
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
    transition: HeadMapTransition,
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
    pub root: IndexedMapRoot,
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
            || response.next_index > HEAD_MAP_CAPACITY
            || response.proof.len() != HEAD_MAP_HEIGHT
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

    /// Verifies membership for a known nullifier public key without the auditor
    /// read key.
    pub fn verify_nullifier_pubkey(
        &self,
        nullifier_pubkey: &[u8; 32],
    ) -> Result<(), KeyRegistrationError> {
        // 1. The expected key and ciphertext must reproduce the pinned registry
        // root.
        let commitment = RegisteredKey {
            nullifier_pk: nullifier_pubkey,
            ciphertext: &self.sealed.ciphertext,
        }
        .commitment()
        .map_err(|_| KeyRegistrationError::Hashing)?;
        let leaf = HeadMapLeaf {
            member: self.member.as_bytes(),
            next: &self.next,
            nullifier: &commitment,
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

pub(crate) struct KeySeal<'a> {
    pub envelope: &'a NullifierKeyEnvelope,
    pub auditor: P256Pubkey,
    /// The 31-byte secret right aligned, high byte zero pins it below the field order.
    pub secret: Zeroizing<[u8; 32]>,
}

pub(crate) struct KeyRegistration {
    pub request: RegisterKeyProofRequest,
    pub transition: HeadMapTransition,
}

impl KeySeal<'_> {
    pub(crate) fn register(
        self,
        query: &RingMemberProofRequest,
        response: GetRingKeyRegistryRegisterProofResponse,
    ) -> Result<KeyRegistration, KeyRegistrationError> {
        let genesis = RegisteredKey {
            nullifier_pk: &self.envelope.nullifier_pk,
            ciphertext: &self.envelope.sealed.ciphertext,
        }
        .commitment()
        .map_err(|_| KeyRegistrationError::Hashing)?;
        let VerifiedInsert {
            transition,
            low_proof,
            new_proof,
        } = IndexedInsert {
            query,
            response: (&response).into(),
            genesis: &genesis,
        }
        .verify()
        .map_err(|_| KeyRegistrationError::InvalidRegisterProof)?;
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
                head_old_root: field_hex(&transition.old_root),
                head_new_root: field_hex(&transition.new_root),
                member: field_hex(&response.member.0),
                new_index: index_hex(response.next_index),
                nullifier_secret: self.secret,
                eph_sk: self.envelope.ephemeral_sk.clone(),
                auditor_pk: bytes_to_hex(auditor_uncompressed.as_bytes()),
                low_member: field_hex(&response.low_member.0),
                low_next: field_hex(&response.low_next.0),
                low_nullifier: field_hex(&response.low_ct_commitment.0),
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
    head_old_root: String,
    head_new_root: String,
    member: String,
    new_index: String,
    nullifier_secret: Zeroizing<[u8; 32]>,
    eph_sk: Zeroizing<[u8; 32]>,
    auditor_pk: String,
    low_member: String,
    low_next: String,
    low_nullifier: String,
    low_index: String,
    low_proof: Vec<String>,
    new_proof: Vec<String>,
}

impl ProveRequest for RegisterKeyProofRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        json_body(&RegisterKeyProofRequestJson {
            circuit_type: "custom-ring-register-key",
            public_input_hash: &self.public_input_hash,
            head_old_root: &self.head_old_root,
            head_new_root: &self.head_new_root,
            member: &self.member,
            new_index: &self.new_index,
            nullifier_secret: SecretHex::new(self.nullifier_secret.as_slice()),
            eph_sk: SecretHex::new(self.eph_sk.as_slice()),
            auditor_pk: &self.auditor_pk,
            low_member: &self.low_member,
            low_next: &self.low_next,
            low_nullifier: &self.low_nullifier,
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
    head_old_root: &'a str,
    head_new_root: &'a str,
    member: &'a str,
    new_index: &'a str,
    nullifier_secret: SecretHex,
    eph_sk: SecretHex,
    auditor_pk: &'a str,
    low_member: &'a str,
    low_next: &'a str,
    low_nullifier: &'a str,
    low_index: &'a str,
    low_proof: &'a [String],
    new_proof: &'a [String],
}

#[cfg(test)]
mod tests {
    use zolana_indexer_api::{Base64String, Context, Hash};
    use zolana_keypair::{NullifierKey, ViewingKey};
    use zolana_ring_head_map::{HeadMap, HeadTransfer, Registration};

    use super::*;

    struct Fixture {
        ring: CustomRing,
        member: Member,
        query: RingMemberProofRequest,
        response: GetRingKeyRegistryRegisterProofResponse,
        auditor: ViewingKey,
        nullifier_key: NullifierKey,
        envelope: NullifierKeyEnvelope,
        map: HeadMap,
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
            let genesis = RegisteredKey {
                nullifier_pk: &envelope.nullifier_pk,
                ciphertext: &envelope.sealed.ciphertext,
            }
            .commitment()
            .expect("commitment");
            let mut map = HeadMap::new().expect("map");
            let proof_inputs = map
                .register(Registration {
                    member: *member.as_bytes(),
                    genesis,
                })
                .expect("register");
            let query = ring.member_proof_request(
                &member,
                IndexedMapRoot {
                    root: proof_inputs.old_root,
                    next_index: proof_inputs.new_index,
                },
            );
            let response = GetRingKeyRegistryRegisterProofResponse {
                context: Context::default(),
                root: Hash(proof_inputs.old_root),
                next_index: proof_inputs.new_index,
                member: Hash(proof_inputs.member),
                low_member: Hash(proof_inputs.low_member),
                low_next: Hash(proof_inputs.low_next),
                low_ct_commitment: Hash(proof_inputs.low_nullifier),
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
                map,
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
        fn entry(&mut self) -> (RingMemberProofRequest, GetRingKeyRegistryEntryResponse) {
            let genesis = RegisteredKey {
                nullifier_pk: &self.envelope.nullifier_pk,
                ciphertext: &self.envelope.sealed.ciphertext,
            }
            .commitment()
            .expect("commitment");
            let inclusion = self
                .map
                .transfer(HeadTransfer {
                    member: *self.member.as_bytes(),
                    spent: genesis,
                    successor: genesis,
                })
                .expect("inclusion");
            let query = self.ring.member_proof_request(
                &self.member,
                IndexedMapRoot {
                    root: self.new_root,
                    next_index: 2,
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
                root: IndexedMapRoot {
                    root: self.new_root,
                    next_index: 2,
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
        assert_eq!(json["headNewRoot"], field_hex(&fixture.new_root));
        assert_eq!(
            json["lowProof"].as_array().expect("low").len(),
            HEAD_MAP_HEIGHT
        );
        assert_eq!(
            json["newProof"].as_array().expect("new").len(),
            HEAD_MAP_HEIGHT
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
        let mut fixture = Fixture::new();
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
        let mut fixture = Fixture::new();
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
            let mut fixture = Fixture::new();
            let (query, mut response) = fixture.entry();
            mutate(&mut response);
            assert!(matches!(
                fixture.read().decode_entry(&query, response),
                Err(KeyRegistrationError::InvalidEntryProof)
            ));
        }
        // A path that verifies but under another leaf opens to nothing.
        let mut fixture = Fixture::new();
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
}
