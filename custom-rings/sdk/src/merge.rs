//! The custom-ring binding of SPP's owner-preserving merge.

use custom_ring_interface::{
    merge_disclosure_field_count, CustomRingMergeIxData, MergeAnonymousPublicInput,
    MergeDisclosure, RingMode, ANONYMOUS_MERGE_WIDTHS, AUDIT_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zeroize::Zeroizing;
use zolana_client::{
    prover::{
        indexed::{IndexedMergePreparation, ProvenIndexedMerge},
        requests, MergeRegistration,
    },
    AsyncIndexer, AsyncRpc, AsyncWitnessReader, AsyncZolanaClient, ClientError, MergeProver,
    ProofCompressed, ProofInputUtxo,
};
use zolana_hasher::primitives::{hash_bytes, pack_be, right_align};
use zolana_interface::tree_slot::tree_id_field;
use zolana_interface::{
    instruction::instruction_data::{
        merge_ring::MergeRingIxData,
        merge_transact::{MergeOutputEncryption, MergeProof, MergeTransactIxData},
    },
    instruction::tag::RING_MERGE_TRANSACT,
    merge_utils::ciphertext_hash,
};
use zolana_keypair::{NullifierKey, X25519Pubkey};
use zolana_program::instruction::MergeRing;
use zolana_ring_client::{MergeDisclosureEncryption, MergeOpening};
use zolana_transaction::{
    error::TransactionError,
    instructions::merge::{MergeProofInputs, MergeTransaction},
    utxo::SppProofInputUtxo,
    ShieldedKeys, SppProofOutputUtxo, WalletUtxo,
};

pub use zolana_transaction::instructions::merge::MERGE_DEFAULT_INPUT_COUNT;
/// Custom forwarding leaves room for 50 real inputs in a minimal v1 transaction.
/// The proof still uses the shared 52-slot circuit with compact padding.
pub const MAX_MERGE_INPUTS: usize = 50;

use zolana_ring_policy::Member;

use crate::{
    member_registry::{ReadMemberRecord, RecordOpening},
    prover::{RingCircuit, RingRequest},
    request::{MergeAnonymousBody, MergeSlot, RecordWitness},
    to_instruction_proof,
    transact_ix::ring_prefix,
    tree_id, CustomRing, RingError,
};

/// A merge plan whose inputs and output are bound to one custom ring.
#[must_use]
#[derive(Clone)]
pub struct CustomRingMerge {
    ring: CustomRing,
    inner: MergeTransaction,
}

impl CustomRingMerge {
    pub fn new(
        ring: CustomRing,
        inputs: Vec<WalletUtxo>,
        output_ring_data_hash: Option<[u8; 32]>,
    ) -> Result<Self, TransactionError> {
        if inputs.len() > MAX_MERGE_INPUTS {
            return Err(TransactionError::TooManyInputs {
                got: inputs.len(),
                max: MAX_MERGE_INPUTS,
            });
        }
        let inner =
            MergeTransaction::new_with_ring(inputs, ring.program_id(), output_ring_data_hash)?;
        Ok(Self { ring, inner })
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.inner = self.inner.with_expiry(expiry_unix_ts);
        self
    }

    pub fn with_output_tree_id(mut self, tree_id: u16) -> Self {
        self.inner = self.inner.with_output_tree_id(tree_id);
        self
    }

    pub fn encrypt<K: ShieldedKeys + ?Sized>(
        self,
        keys: &K,
    ) -> Result<PreparedCustomRingMerge, TransactionError> {
        Ok(PreparedCustomRingMerge {
            ring: self.ring,
            inner: self.inner.encrypt(keys)?,
        })
    }
}

/// A custom-ring merge, compact-padded to its circuit width, ready for tree proofs.
#[must_use]
#[derive(Clone)]
pub struct PreparedCustomRingMerge {
    ring: CustomRing,
    inner: MergeProofInputs,
}

#[derive(Clone)]
pub struct MergeProofInput {
    pub nullifier_key: NullifierKey,
    pub input_tree: Address,
    pub output_tree: Address,
}

pub struct ProvenCustomRingMerge {
    input_tree: Address,
    output_tree: Address,
    ring: CustomRing,
    cosigner: Option<Address>,
    pub data: CustomRingMergeIxData,
    pub output_hash: [u8; 32],
    pub input_count: usize,
    pub merged_amount: u64,
}

struct RegisteredMerge {
    root_index: u8,
    proof: MergeRegistration,
}

/// The member record the merge opens, with its escrow unless the ring is anonymous.
#[must_use]
struct MemberMerge<'a> {
    ring: CustomRing,
    inputs: &'a MergeProofInputs,
    nullifier_key: &'a NullifierKey,
    anonymous: bool,
}

impl MemberMerge<'_> {
    async fn read<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<RegisteredMerge, RingError> {
        let member = Member::from_bytes(self.inputs.signing_pubkey.owner_proof_input_hash()?)?;
        let read = ReadMemberRecord {
            ring: self.ring,
            member,
        }
        .read(client)
        .await?
        .ok_or(RingError::MissingMemberRegistry)?;
        // An anonymous member escrows nothing, its merge proof discloses the owner to the auditor.
        let ciphertext_hash = match self.anonymous {
            true => None,
            false => {
                let sealed = read.sealed_key().ok_or(RingError::InvalidRecordOpening)?;
                sealed.verify_nullifier_pubkey(&self.nullifier_key.pubkey()?)?;
                Some(ciphertext_hash(&sealed.sealed.ciphertext)?)
            }
        };
        let RecordOpening::Present {
            record,
            index,
            path,
            ..
        } = read.opening
        else {
            return Err(RingError::InvalidRecordOpening);
        };
        Ok(RegisteredMerge {
            root_index: read.root.history_index,
            proof: MergeRegistration {
                root: read.root.root,
                ciphertext_hash,
                next: record.next,
                lists: record.lists,
                escrow_key: record.escrow_key,
                index,
                path,
            },
        })
    }
}

/// The auditor's opening of an anonymous merge, proven against the SPP merge it precedes.
#[must_use]
struct AnonymousMergeDisclosure<'a> {
    ring: CustomRing,
    auditor: X25519Pubkey,
    merge: &'a MergeProofInputs,
    nullifier_key: &'a NullifierKey,
    registration: &'a MergeRegistration,
    spp: &'a MergeTransactIxData,
}

/// The prover body and the instruction half of one disclosure, sealed under one key.
struct SealedMergeDisclosure {
    body: Box<MergeAnonymousBody>,
    eph_pk: [u8; TAGGED_X25519_KEY_LEN],
    ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
    fields: Vec<[u8; 32]>,
}

impl AnonymousMergeDisclosure<'_> {
    async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<MergeDisclosure, RingError> {
        let sealed = self.seal()?;
        let proof = client.prove_request(&RingRequest(&*sealed.body)).await?;
        sealed
            .body
            .circuit_type
            .verify(&proof, sealed.body.public_input_hash)?;
        Ok(MergeDisclosure {
            proof: to_instruction_proof(proof)?,
            eph_pk: sealed.eph_pk,
            ciphertext: sealed.ciphertext,
            fields: sealed.fields,
        })
    }

    fn seal(&self) -> Result<SealedMergeDisclosure, RingError> {
        let merge = self.merge;
        let width =
            u8::try_from(merge.input_utxos.len()).map_err(|_| ClientError::UnsupportedShape {
                n_in: merge.input_utxos.len(),
                n_out: 1,
            })?;
        let owner_key = merge.signing_pubkey.as_ed25519()?;
        let output = &merge.output_utxo;
        let opening = MergeOpening {
            owner_key,
            nullifier_pk: self.nullifier_key.pubkey()?,
            mint: *output.asset.asset.as_array(),
            amount: output.amount,
            output_blinding: output.blinding,
            input_commitments: merge
                .input_utxos
                .iter()
                .map(|input| {
                    if input.is_dummy() {
                        [0; 32]
                    } else {
                        input.utxo_hash
                    }
                })
                .collect(),
        };
        let sealed =
            MergeDisclosureEncryption::new(&opening, merge.output_ciphertext_salt, &self.auditor)?;
        let first_nullifier = *self.spp.nullifiers.first().ok_or(ClientError::NoInputs)?;
        let ring_program_id = hash_bytes(self.ring.program_id().as_array())?;
        let public_input_hash = MergeAnonymousPublicInput {
            private_tx_hash: &self.spp.private_tx_hash,
            output_utxo_hash: &self.spp.output_utxo_hash,
            first_nullifier: &first_nullifier,
            ring_id: &ring_program_id,
            member_registry_root: &self.registration.root,
            auditor_pk: self.auditor.as_bytes(),
            eph_pk: sealed.eph_pk.as_bytes(),
            ciphertext: &sealed.ciphertext,
            salt: &merge.output_ciphertext_salt,
            fields: &sealed.fields,
        }
        .hash()?;
        let inputs = merge
            .input_utxos
            .iter()
            .map(|input| {
                let utxo = ProofInputUtxo::try_from(input)?;
                Ok(MergeSlot {
                    domain: utxo.domain,
                    tree_id: utxo.tree_id,
                    amount: utxo.amount,
                    blinding: utxo.blinding,
                    ring_data_hash: utxo.ring_data_hash,
                })
            })
            .collect::<Result<_, TransactionError>>()?;
        let registration = self.registration;
        let body = Box::new(MergeAnonymousBody {
            circuit_type: RingCircuit::MergeAnonymous { inputs: width },
            public_input_hash,
            private_tx_hash: self.spp.private_tx_hash,
            output_utxo_hash: self.spp.output_utxo_hash,
            first_nullifier,
            ring_program_id,
            member_registry_root: registration.root,
            auditor_pk: self.auditor,
            salt: right_align(&merge.output_ciphertext_salt),
            eph_sk: sealed.ephemeral_sk,
            disclosure_key: sealed.disclosure_key,
            owner_key,
            nullifier_secret: Zeroizing::new(right_align(&self.nullifier_key.secret())),
            mint_chunks: pack_be::<32, 2>(output.asset.asset.as_array()),
            inputs,
            output_tree_id: tree_id_field(merge.output_tree_id),
            output_ring_data_hash: output.ring_data_hash.unwrap_or_default(),
            member_record: RecordWitness {
                next: registration.next,
                lists: registration.lists,
                escrow_key: registration.escrow_key,
                index: registration.index,
                path: registration.path.clone(),
            },
        });
        Ok(SealedMergeDisclosure {
            body,
            eph_pk: *sealed.eph_pk.as_bytes(),
            ciphertext: sealed.ciphertext,
            fields: sealed.fields,
        })
    }
}

impl PreparedCustomRingMerge {
    pub const fn ring(&self) -> CustomRing {
        self.ring
    }

    pub fn inputs(&self) -> &[SppProofInputUtxo] {
        &self.inner.input_utxos
    }

    pub const fn output(&self) -> &SppProofOutputUtxo {
        &self.inner.output_utxo
    }

    /// Preserve the real accounts and published nullifiers for exact wire sizing.
    /// Proof, root indexes and commitment placeholders have their final fixed widths.
    pub(crate) fn preview_instruction(
        &self,
        input: &MergeProofInput,
        payer: Address,
        cosigner: Option<Address>,
    ) -> Instruction {
        self.preview(input, payer, cosigner, None)
    }

    /// An anonymous ring's preview also carries the disclosure of its width.
    pub(crate) fn anonymous_preview_instruction(
        &self,
        input: &MergeProofInput,
        payer: Address,
        cosigner: Option<Address>,
    ) -> Result<Instruction, RingError> {
        let disclosure = MergeDisclosure {
            proof: bytemuck::Zeroable::zeroed(),
            eph_pk: [0; TAGGED_X25519_KEY_LEN],
            ciphertext: [0; AUDIT_CIPHERTEXT_LEN],
            fields: vec![[0; 32]; merge_disclosure_field_count(self.anonymous_width()?)],
        };
        Ok(self.preview(input, payer, cosigner, Some(disclosure)))
    }

    fn anonymous_width(&self) -> Result<usize, RingError> {
        let width = self.inner.input_utxos.len();
        if ANONYMOUS_MERGE_WIDTHS.contains(&width) {
            Ok(width)
        } else {
            Err(RingError::AnonymousMergeTooWide { width })
        }
    }

    fn preview(
        &self,
        input: &MergeProofInput,
        payer: Address,
        cosigner: Option<Address>,
        disclosure: Option<MergeDisclosure>,
    ) -> Instruction {
        CustomRingMergeInstruction {
            ring: self.ring,
            input_tree: input.input_tree,
            output_tree: input.output_tree,
            payer,
            cosigner,
            data: CustomRingMergeIxData {
                registry_root_index: 0,
                output_ring_data_hash: self.inner.output_utxo.ring_data_hash.unwrap_or_default(),
                disclosure,
                merge: MergeTransactIxData {
                    expiry_unix_ts: self.inner.expiry_unix_ts,
                    proof: MergeProof::zeroed(),
                    output_utxo_hash: [0; 32],
                    output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                        salt: self.inner.output_ciphertext_salt,
                        ciphertext: self.inner.output_ciphertext,
                    },
                    private_tx_hash: [0; 32],
                    nullifiers: self
                        .inner
                        .input_utxos
                        .iter()
                        .filter(|input| !input.is_compact())
                        .map(|input| input.nullifier)
                        .collect(),
                    utxo_tree_root_index: 0,
                    nullifier_tree_root_index: 0,
                    cache_slot: None,
                },
            },
        }
        .instruction()
    }

    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        mut self,
        input: MergeProofInput,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<ProvenCustomRingMerge, RingError> {
        let config = self
            .ring
            .config(client)
            .await?
            .ok_or(RingError::MissingRingConfig)?;
        let anonymous = config.mode == RingMode::Anonymous;
        if anonymous {
            self.anonymous_width()?;
        }
        let input_tree_id = tree_id(client, input.input_tree).await?;
        if self
            .inner
            .input_utxos
            .iter()
            .any(|utxo| !utxo.is_dummy() && utxo.tree_id != input_tree_id)
        {
            return Err(RingError::InputTreeMismatch);
        }
        self.inner.output_tree_id = tree_id(client, input.output_tree).await?;
        let registered = MemberMerge {
            ring: self.ring,
            inputs: &self.inner,
            nullifier_key: &input.nullifier_key,
            anonymous,
        }
        .read(client)
        .await?;
        let data: MergeRingIxData = match client.indexed_prover() {
            Some(prover) => {
                let prepared = IndexedMergePreparation {
                    merge: self.inner.clone(),
                    nullifier_key: input.nullifier_key.clone(),
                }
                .prepare_registered(registered.proof.clone())?;
                match prover.prove_indexed(&prepared).await? {
                    ProvenIndexedMerge::Ring(data) => data,
                    _ => return Err(ClientError::InvalidIndexedRequest.into()),
                }
            }
            None => {
                let commitments = self.inner.input_utxo_hashes()?;
                let witnesses = AsyncWitnessReader::input_witnesses(
                    client.indexer(),
                    &commitments,
                    &self.inner.dummy_nullifiers(),
                    None,
                )
                .await?;
                let result = MergeProver {
                    transaction: self.inner.clone(),
                    nullifier_key: input.nullifier_key.clone(),
                    proofs: witnesses.spend_proofs,
                    dummy_nullifier_proofs: witnesses.dummy_nullifier_proofs,
                    cache: None,
                }
                .build_registered(registered.proof.clone())?;
                let proof = client
                    .prove_request(&requests::merge_ring(&result.inputs)?)
                    .await?;
                result.ring_instruction_data(ProofCompressed::try_from(proof)?.to_merge_proof()?)
            }
        };
        let disclosure = match anonymous {
            true => Some(
                AnonymousMergeDisclosure {
                    ring: self.ring,
                    auditor: config.auditor_pubkey,
                    merge: &self.inner,
                    nullifier_key: &input.nullifier_key,
                    registration: &registered.proof,
                    spp: &data.merge,
                }
                .prove(client)
                .await?,
            ),
            false => None,
        };
        let data = CustomRingMergeIxData {
            registry_root_index: registered.root_index,
            output_ring_data_hash: data.output_ring_data_hash,
            disclosure,
            merge: data.merge,
        };
        let inner = self.inner;
        Ok(ProvenCustomRingMerge {
            input_tree: input.input_tree,
            output_tree: input.output_tree,
            ring: self.ring,
            cosigner: None,
            data,
            output_hash: inner.output_hash()?,
            input_count: inner
                .input_utxos
                .iter()
                .filter(|utxo| !utxo.is_dummy())
                .count(),
            merged_amount: inner.output_utxo.amount,
        })
    }
}

impl ProvenCustomRingMerge {
    #[must_use = "use the updated merge"]
    pub fn with_cosigner(mut self, cosigner: Address) -> Self {
        self.cosigner = Some(cosigner);
        self
    }

    pub fn instruction(self, payer: Address) -> Instruction {
        CustomRingMergeInstruction {
            ring: self.ring,
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            payer,
            cosigner: self.cosigner,
            data: self.data,
        }
        .instruction()
    }
}

/// A proven merge, the ring's `[config, cosigner_pda, cosigner]` prefix precedes SPP's list.
#[must_use]
pub struct CustomRingMergeInstruction {
    pub ring: CustomRing,
    pub input_tree: Address,
    pub output_tree: Address,
    pub payer: Address,
    pub cosigner: Option<Address>,
    pub data: CustomRingMergeIxData,
}

impl CustomRingMergeInstruction {
    pub fn instruction(self) -> Instruction {
        let compact_data = self
            .data
            .serialize()
            .expect("fixed merge request serializes");
        let mut instruction = MergeRing {
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            ring_program_id: self.ring.program_id(),
            payer: self.payer,
            data: self.data.merge,
            output_ring_data_hash: self.data.output_ring_data_hash,
            member_registry_root: [0; 32],
            anonymous: false,
            cache: None,
        }
        .instruction();
        instruction.data.clear();
        instruction.data.push(RING_MERGE_TRANSACT);
        instruction.data.extend_from_slice(&compact_data);
        instruction
            .accounts
            .splice(0..0, ring_prefix(self.ring, self.cosigner));
        instruction.accounts.insert(
            3,
            AccountMeta::new_readonly(self.ring.member_registry_root_pda(), false),
        );
        instruction
    }
}
