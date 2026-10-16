//! Seals a member's nullifier key to the ring auditor and appends it to the key registry.

use custom_ring_interface::{
    tag, CustomRingProof, KeyRegistryInsert, KeyRegistryLeaf, KeyRegistryTransition, MerklePath,
    RegisterKeyIxData, RegisterKeyPublicInput, RegisteredKey, KEY_REGISTRY_CAPACITY,
    KEY_REGISTRY_HEIGHT,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zeroize::Zeroizing;
use zolana_client::{AsyncIndexer, AsyncRpc, AsyncZolanaClient};
use zolana_hasher::primitives::right_align;
use zolana_indexer_api::{
    GetRingKeyRegistryEntryResponse, GetRingKeyRegistryRegisterProofResponse, Hash,
    RingMemberProofRequest, SerializablePubkey,
};
use zolana_interface::merge_utils::ciphertext_hash;
use zolana_keypair::{NullifierKey, ShieldedKeypair, X25519Pubkey, X25519Secret};
use zolana_ring_client::{NullifierKeyEnvelope, SealedNullifierKey};
use zolana_ring_policy::Member;

use crate::{
    escrow::RegistryKeyOpening,
    projection::retry_projection_lag,
    prover::{RingCircuit, RingRequest},
    request::RegisterKeyBody,
    to_instruction_proof, CurrentKeyRegistryRoot, CustomRing, RingError,
};

#[must_use]
#[derive(Clone, Copy)]
pub struct RegisterKey<'a> {
    pub ring: CustomRing,
    /// Also the payer, the member identity derives from it.
    pub member: &'a ShieldedKeypair,
}

#[must_use]
pub struct ProvenKeyRegistration {
    ring: CustomRing,
    member: Address,
    transition: KeyRegistryTransition,
    registry_next_index: u64,
    envelope: NullifierKeyEnvelope,
    proof: CustomRingProof,
}

impl RegisterKey<'_> {
    /// Proves key disclosure under the current root, it authorizes no transfer.
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<ProvenKeyRegistration, RingError> {
        let auditor = self
            .ring
            .config(client)
            .await?
            .ok_or(RingError::MissingRingConfig)?
            .auditor_pubkey;
        let member = Address::new_from_array(self.member.signing_pubkey().as_ed25519()?);
        let nullifier_key = &self.member.nullifier_key;
        if nullifier_key.pubkey()? != self.member.shielded_address()?.nullifier_pubkey {
            return Err(RingError::NullifierKeyMismatch);
        }
        let owner = Member::owner_tag(member.as_array())?;
        let (envelope, body, transition, root) = retry_projection_lag(|| async {
            let root = self
                .ring
                .key_registry_root(client)
                .await?
                .ok_or(RingError::MissingKeyRegistry)?;
            let envelope = NullifierKeyEnvelope::new(nullifier_key, &auditor)?;
            let query = self.ring.member_proof_request(&owner, root);
            let response = client
                .get_ring_key_registry_register_proof(query.clone())
                .await?;
            let secret = Zeroizing::new(right_align(&nullifier_key.secret()));
            let (body, transition) = register(&envelope, auditor, secret, &query, response)?;
            Ok((envelope, body, transition, root))
        })
        .await?;
        let proof = client.prove_request(&RingRequest(&body)).await?;
        Ok(ProvenKeyRegistration {
            ring: self.ring,
            member,
            transition,
            registry_next_index: root.next_index,
            envelope,
            proof: to_instruction_proof(proof)?,
        })
    }
}

/// The insert must hold under the root the query names.
pub(crate) fn register(
    envelope: &NullifierKeyEnvelope,
    auditor: X25519Pubkey,
    secret: Zeroizing<[u8; 32]>,
    query: &RingMemberProofRequest,
    response: GetRingKeyRegistryRegisterProofResponse,
) -> Result<(RegisterKeyBody, KeyRegistryTransition), RingError> {
    let key = RegisteredKey {
        nullifier_pk: &envelope.nullifier_pk,
        ciphertext: &envelope.sealed.ciphertext,
    }
    .hash()?;
    if response.root != query.expected_root
        || response.member != query.member
        || response.next_index != query.expected_next_index
        || response.low_index >= response.next_index
    {
        return Err(RingError::InvalidRegisterProof);
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
    .map_err(|_| RingError::InvalidRegisterProof)?;
    let transition = KeyRegistryTransition {
        old_root: response.root.0,
        new_root,
    };
    let public_input_hash = RegisterKeyPublicInput {
        registry_old_root: &transition.old_root,
        registry_new_root: &transition.new_root,
        member: &response.member.0,
        nullifier_pk: &envelope.nullifier_pk,
        auditor_pk: auditor.as_bytes(),
        eph_pk: envelope.sealed.eph_pk.as_bytes(),
        ciphertext: &envelope.sealed.ciphertext,
        new_index: response.next_index,
    }
    .hash()?;
    let body = RegisterKeyBody {
        circuit_type: RingCircuit::RegisterKey,
        public_input_hash,
        registry_old_root: transition.old_root,
        registry_new_root: transition.new_root,
        member: response.member.0,
        new_index: response.next_index,
        nullifier_secret: secret,
        eph_sk: envelope.ephemeral_sk.clone(),
        auditor_pk: auditor,
        low_member: response.low_member.0,
        low_next: response.low_next.0,
        low_key: response.low_key_hash.0,
        low_index: response.low_index,
        low_proof,
        new_proof,
    };
    Ok((body, transition))
}

impl ProvenKeyRegistration {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let mut data = vec![tag::REGISTER_KEY];
        data.extend(wincode::serialize(&RegisterKeyIxData {
            proof: self.proof,
            registry_old_root: self.transition.old_root,
            registry_new_root: self.transition.new_root,
            registry_next_index: self.registry_next_index,
            nullifier_pk: self.envelope.nullifier_pk,
            eph_pk: *self.envelope.sealed.eph_pk.as_bytes(),
            ciphertext: self.envelope.sealed.ciphertext,
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

/// [`ReadSealedKey`] under the on-chain root, read again while the indexer trails it.
#[must_use]
pub struct ReadCurrentSealedKey {
    pub ring: CustomRing,
    pub member: Member,
}

/// Membership requires the recovered or expected nullifier public key to verify the leaf.
pub struct SealedKeyEntry {
    pub sealed: SealedNullifierKey,
    member: Member,
    root: [u8; 32],
    next: [u8; 32],
    index: u64,
    proof: [[u8; 32]; KEY_REGISTRY_HEIGHT],
}

impl ReadCurrentSealedKey {
    /// `None` when the ring has no key registry.
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<SealedKeyEntry>, RingError> {
        retry_projection_lag(|| async {
            let Some(root) = self.ring.key_registry_root(rpc).await? else {
                return Ok(None);
            };
            let read = ReadSealedKey {
                ring: self.ring,
                member: self.member,
                root,
            };
            read.read(rpc).await.map(Some)
        })
        .await
    }
}

impl ReadSealedKey {
    pub async fn read(
        self,
        indexer: &(impl AsyncRpc + ?Sized),
    ) -> Result<SealedKeyEntry, RingError> {
        let query = self.ring.member_proof_request(&self.member, self.root);
        let response = indexer.get_ring_key_registry_entry(query.clone()).await?;
        self.decode(&query, response)
    }

    pub(crate) fn decode(
        self,
        query: &RingMemberProofRequest,
        response: GetRingKeyRegistryEntryResponse,
    ) -> Result<SealedKeyEntry, RingError> {
        if response.root != query.expected_root
            || response.member != query.member
            || response.next_index != query.expected_next_index
            || response.index == 0
            || response.index >= response.next_index
            || response.next_index > KEY_REGISTRY_CAPACITY
        {
            return Err(RingError::InvalidEntryProof);
        }
        let proof: Vec<_> = response.proof.iter().map(|hash| hash.0).collect();
        let Ok(proof) = <[[u8; 32]; KEY_REGISTRY_HEIGHT]>::try_from(proof) else {
            return Err(RingError::InvalidEntryProof);
        };
        let sealed = response
            .eph_pk
            .0
            .as_slice()
            .try_into()
            .ok()
            .and_then(|eph_pk| X25519Pubkey::from_bytes(eph_pk).ok())
            .zip(response.ciphertext.0.as_slice().try_into().ok())
            .map(|(eph_pk, ciphertext)| SealedNullifierKey { eph_pk, ciphertext })
            .ok_or(RingError::InvalidEntryProof)?;
        Ok(SealedKeyEntry {
            sealed,
            member: self.member,
            root: response.root.0,
            next: response.next.0,
            index: response.index,
            proof,
        })
    }
}

impl SealedKeyEntry {
    /// The opened key must reproduce the leaf under the root read from Solana.
    pub fn open(&self, auditor: &X25519Secret) -> Result<NullifierKey, RingError> {
        let nullifier_key = self.sealed.open(auditor)?;
        self.verify_nullifier_pubkey(&nullifier_key.pubkey()?)?;
        Ok(nullifier_key)
    }

    pub fn opening(&self, nullifier_pubkey: &[u8; 32]) -> Result<RegistryKeyOpening, RingError> {
        match self.verify_nullifier_pubkey(nullifier_pubkey) {
            Err(RingError::InvalidEntryProof) => {
                return Err(RingError::UnregisteredOutputKey { owner: self.member })
            }
            result => result?,
        }
        Ok(RegistryKeyOpening {
            next: self.next,
            ct_hash: ciphertext_hash(&self.sealed.ciphertext)?,
            index: self.index,
            path: self.proof,
        })
    }

    /// Membership of a known nullifier public key, without the auditor's key.
    pub fn verify_nullifier_pubkey(&self, nullifier_pubkey: &[u8; 32]) -> Result<(), RingError> {
        let key = RegisteredKey {
            nullifier_pk: nullifier_pubkey,
            ciphertext: &self.sealed.ciphertext,
        }
        .hash()?;
        let leaf = KeyRegistryLeaf {
            member: self.member.as_bytes(),
            next: &self.next,
            key: &key,
        }
        .hash()?;
        let root = MerklePath {
            index: self.index,
            siblings: &self.proof,
        }
        .root_of(leaf);
        match root {
            Ok(root) if root == self.root => Ok(()),
            _ => Err(RingError::InvalidEntryProof),
        }
    }
}

impl CustomRing {
    pub(crate) fn member_proof_request(
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
