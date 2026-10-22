//! The custom-ring binding of SPP's owner-preserving merge.

use custom_ring_interface::{
    cosign::CoSignDemand, key_catalog::RingCircuit, merge_disclosure_field_count,
    CustomRingMergeIxData, MergeAnonymousPublicInput, MergeDisclosure, RingMode,
    ANONYMOUS_MERGE_WIDTHS, AUDIT_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zeroize::Zeroizing;
use zolana_client::{
    prover::{requests, MergeRegistration},
    AsyncIndexer, AsyncRpc, AsyncWitnessReader, AsyncZolanaClient, ClientError, MergeProver,
    ProofCompressed,
};
use zolana_hasher::primitives::{pack_be, right_align};
use zolana_interface::{
    instruction::instruction_data::merge_transact::{
        MergeOutputEncryption, MergeProof, MergeTransactIxData,
    },
    instruction::tag::RING_MERGE_TRANSACT,
    tree_slot::tree_id_field,
};
use zolana_keypair::{NullifierKey, X25519Pubkey};
use zolana_program::instruction::MergeRing;
use zolana_ring_client::{MergeDisclosureEncryption, MergeOpening};
use zolana_transaction::{
    error::TransactionError,
    instructions::merge::{MergeProofInputs, MergeTransaction},
    utxo::{ProofInputUtxo, SppProofInputUtxo},
    ShieldedKeys, SppProofOutputUtxo, WalletUtxo,
};

pub use zolana_transaction::instructions::merge::MERGE_DEFAULT_INPUT_COUNT;
/// Custom forwarding leaves room for 50 real inputs in a minimal v1 transaction.
pub const MAX_MERGE_INPUTS: usize = 50;

use crate::{
    pipeline::HiddenOwner,
    prover::{to_instruction_proof, RingRequest},
    records::{MemberRead, OwnerRead},
    request::{MergeAnonymous, MergeSlot},
    submission::BoundRoot,
    tree_id, CustomRing, CustomRingConfig, RingError,
};

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

/// Compact-padded to its circuit width.
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
    co_signer: Option<Address>,
    /// `None` on an anonymous ring, its merge binds no registry root.
    bound: Option<BoundRoot>,
    pub data: CustomRingMergeIxData,
    pub output_hash: [u8; 32],
    pub input_count: usize,
    pub merged_amount: u64,
}

struct RegisteredMerge {
    bound: BoundRoot,
    proof: MergeRegistration,
}

#[must_use]
struct MemberMerge<'a> {
    ring: CustomRing,
    inputs: &'a MergeProofInputs,
    nullifier_key: &'a NullifierKey,
}

impl MemberMerge<'_> {
    async fn read<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<RegisteredMerge, RingError> {
        let identity = self.inputs.signing_pubkey.owner_proof_input_hash()?;
        let bound = BoundRoot::newest(self.ring, client).await?;
        let read = MemberRead {
            root: bound,
            member: identity,
        }
        .read(client)
        .await?;
        let escrowed = OwnerRead {
            owner: identity,
            read: &read,
        }
        .escrowed(&self.nullifier_key.pubkey()?)?;
        let record = escrowed.record;
        Ok(RegisteredMerge {
            bound,
            proof: MergeRegistration {
                root: bound.root,
                ciphertext_hash: Some(escrowed.ct_hash()?),
                next: record.next,
                lists: record.lists,
                escrow_key: record.escrow_key,
                index: escrowed.path.index,
                path: escrowed.path.siblings.iter().flatten().copied().collect(),
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
    spp: &'a MergeTransactIxData,
}

impl AnonymousMergeDisclosure<'_> {
    async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<MergeDisclosure, RingError> {
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
                .map(|input| match input.is_dummy() {
                    true => [0; 32],
                    false => input.utxo_hash,
                })
                .collect(),
        };
        let sealed =
            MergeDisclosureEncryption::new(&opening, merge.output_ciphertext_salt, &self.auditor)?;
        let first_nullifier = *self.spp.nullifiers.first().ok_or(ClientError::NoInputs)?;
        let ring_program_id = self.ring.ring_id()?;
        let public_input_hash = MergeAnonymousPublicInput {
            private_tx_hash: &self.spp.private_tx_hash,
            output_utxo_hash: &self.spp.output_utxo_hash,
            first_nullifier: &first_nullifier,
            ring_id: &ring_program_id,
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
        let body = MergeAnonymous {
            public_input_hash,
            private_tx_hash: self.spp.private_tx_hash,
            output_utxo_hash: self.spp.output_utxo_hash,
            first_nullifier,
            ring_program_id,
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
        };
        let proof = RingRequest::new(RingCircuit::AnonymousMerge { width }, &body)?
            .prove(client, public_input_hash)
            .await?;
        Ok(MergeDisclosure {
            proof: to_instruction_proof(proof)?,
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

    pub(crate) fn check_public_signers(
        &self,
        signers: impl IntoIterator<Item = Address>,
        config: &CustomRingConfig,
    ) -> Result<(), RingError> {
        if config.mode != RingMode::Anonymous {
            return Ok(());
        }
        HiddenOwner::of(&self.inner.signing_pubkey)?
            .check_signers(signers.into_iter().chain(merge_co_signer(config)?))
    }

    fn anonymous_width(&self) -> Result<usize, RingError> {
        let width = self.inner.input_utxos.len();
        match ANONYMOUS_MERGE_WIDTHS.contains(&width) {
            true => Ok(width),
            false => Err(RingError::AnonymousMergeTooWide { width }),
        }
    }

    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        mut self,
        input: MergeProofInput,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<ProvenCustomRingMerge, RingError> {
        let config = self.ring.require_config(client).await?;
        self.ring.require_active(client).await?;
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
        let registered = match anonymous {
            true => None,
            false => Some(
                MemberMerge {
                    ring: self.ring,
                    inputs: &self.inner,
                    nullifier_key: &input.nullifier_key,
                }
                .read(client)
                .await?,
            ),
        };
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
        .build_registered(
            registered
                .as_ref()
                .map_or_else(MergeRegistration::anonymous, |registered| {
                    registered.proof.clone()
                }),
        )?;
        let proof = client
            .prove_request(&requests::merge_ring(&result.inputs)?)
            .await?;
        let data =
            result.ring_instruction_data(ProofCompressed::try_from(proof)?.to_merge_proof()?);
        let disclosure = match anonymous {
            true => Some(
                AnonymousMergeDisclosure {
                    ring: self.ring,
                    auditor: config.auditor_pubkey,
                    merge: &self.inner,
                    nullifier_key: &input.nullifier_key,
                    spp: &data.merge,
                }
                .prove(client)
                .await?,
            ),
            false => None,
        };
        let co_signer = merge_co_signer(&config)?;
        let inner = self.inner;
        Ok(ProvenCustomRingMerge {
            input_tree: input.input_tree,
            output_tree: input.output_tree,
            ring: self.ring,
            co_signer,
            bound: registered.as_ref().map(|registered| registered.bound),
            data: CustomRingMergeIxData {
                registry_root_index: registered.map_or(0, |registered| registered.bound.index),
                output_ring_data_hash: data.output_ring_data_hash,
                disclosure,
                merge: data.merge,
            },
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
    /// `Some` when the config's scope covers transfers, it signs the transaction.
    pub fn co_signer(&self) -> Option<Address> {
        self.co_signer
    }

    pub(crate) fn bound_root(&self) -> Option<BoundRoot> {
        self.bound
    }

    pub fn instruction(&self, payer: Address) -> Result<Instruction, RingError> {
        CustomRingMergeInstruction {
            ring: self.ring,
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            payer,
            co_signer: self.co_signer,
            data: self.data.clone(),
        }
        .instruction()
    }
}

#[must_use]
pub struct RingMergeOperation {
    pub(crate) prepared: PreparedCustomRingMerge,
    pub(crate) input: MergeProofInput,
}

impl RingMergeOperation {
    pub fn new(prepared: PreparedCustomRingMerge, input: MergeProofInput) -> Self {
        Self { prepared, input }
    }

    /// The instruction under zeroed proofs, the size of the proven one.
    pub(crate) fn preview_instruction(
        &self,
        payer: Address,
        config: &CustomRingConfig,
    ) -> Result<Instruction, RingError> {
        let merge = &self.prepared;
        let disclosure = match config.mode == RingMode::Anonymous {
            true => Some(MergeDisclosure {
                proof: bytemuck::Zeroable::zeroed(),
                eph_pk: [0; TAGGED_X25519_KEY_LEN],
                ciphertext: [0; AUDIT_CIPHERTEXT_LEN],
                fields: vec![[0; 32]; merge_disclosure_field_count(merge.anonymous_width()?)],
            }),
            false => None,
        };
        CustomRingMergeInstruction {
            ring: merge.ring,
            input_tree: self.input.input_tree,
            output_tree: self.input.output_tree,
            payer,
            co_signer: merge_co_signer(config)?,
            data: CustomRingMergeIxData {
                registry_root_index: 0,
                output_ring_data_hash: merge.inner.output_utxo.ring_data_hash.unwrap_or_default(),
                disclosure,
                merge: MergeTransactIxData {
                    expiry_unix_ts: merge.inner.expiry_unix_ts,
                    proof: MergeProof::zeroed(),
                    output_utxo_hash: [0; 32],
                    output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                        salt: merge.inner.output_ciphertext_salt,
                        ciphertext: merge.inner.output_ciphertext,
                    },
                    private_tx_hash: [0; 32],
                    nullifiers: merge
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
}

/// `[config, registry?, co-signer?]` ahead of SPP's merge list, no registry on an anonymous ring.
#[must_use]
pub struct CustomRingMergeInstruction {
    pub ring: CustomRing,
    pub input_tree: Address,
    pub output_tree: Address,
    pub payer: Address,
    pub co_signer: Option<Address>,
    pub data: CustomRingMergeIxData,
}

impl CustomRingMergeInstruction {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let mut data = vec![RING_MERGE_TRANSACT];
        data.extend(
            self.data
                .serialize()
                .map_err(|_| custom_ring_interface::CustomRingError::InvalidInstructionData)?,
        );
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
        instruction.data = data;
        let mut prefix = vec![AccountMeta::new_readonly(self.ring.config_pda(), false)];
        if self.data.disclosure.is_none() {
            prefix.push(AccountMeta::new_readonly(self.ring.registry_pda(), false));
        }
        prefix.extend(
            self.co_signer
                .map(|co_signer| AccountMeta::new_readonly(co_signer, true)),
        );
        instruction.accounts.splice(0..0, prefix);
        Ok(instruction)
    }
}

/// A merge is a transfer, no public leg adds a class.
fn merge_co_signer(config: &CustomRingConfig) -> Result<Option<Address>, RingError> {
    Ok(CoSignDemand::transact(false, &[]).signer(config.account())?)
}
