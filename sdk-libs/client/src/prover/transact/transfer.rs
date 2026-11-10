//! The one transfer proof builder. Every transfer circuit assembles the same
//! inputs, outputs and private transaction hash; a [`TransferRail`] supplies
//! what differs: how input owners authorize, which ring the proof binds,
//! which output owners it publishes and the in-circuit owner signature, if
//! any.

use num_bigint::BigUint;
use solana_address::Address;
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::{
    instruction::instruction_data::transact::{Bsb22Commitment, CircuitId, TreeContext},
    verifying_keys::{AnonymousRingEddsaProofData, CacheAccess},
    N_PUBLIC_SLOTS,
};
use spr_transaction::{
    instructions::transact::{CacheAccounts, PublicTransfers, SppProofInputs, TransactRail},
    utxo::program_id_proof_input_hash,
    ExternalData, SppProofOutputUtxo,
};

use crate::{
    error::ClientError,
    prover::{
        cache::CacheSelection,
        field::be,
        json::OwnerSignatureJson,
        transact::{
            anonymous_ring_eddsa::{
                anonymous_signer_pk_hashes, AnonymousAuthorizationPreparation,
                AnonymousEddsaAuthorization, AnonymousEddsaTransferInputs,
            },
            assembly::{
                assemble_transaction, confidential_marked_output_owner_pk_hashes, validate_shape,
                AssembledTransaction, OwnerMode, PublicInputs, TransferInputUtxo,
            },
            confidential_eddsa::{
                confidential_eddsa_circuit, confidential_eddsa_signer_pk_hashes,
                ConfidentialEddsaTransferInputs, EddsaAuthorization,
            },
            OwnerAuthorization,
        },
        Shape, TransferInputs, TreeSlotFields,
    },
};

/// The default ring, where every input owner signs the transaction
/// (`CircuitId::ConfidentialSigner`).
#[derive(Clone, Copy, Debug, Default)]
pub struct SignerRail;

/// A ring-bound transfer whose input owners sign the transaction
/// (`CircuitId::ConfidentialRingEddsa`). Input owners are matched privately
/// against the public signer set; output owner hashes stay private except on
/// confidential-encryption-marked slots.
#[derive(Clone, Copy, Debug)]
pub struct RingSignerRail {
    /// Bound to the public `ring_program_id` and to each non-dummy UTXO's
    /// ring field by the circuit.
    pub ring_program_id: Option<Address>,
}

/// A state transition the ring authority authorizes on chain, the
/// `ring_config` PDA signing (`CircuitId::RingAuthority`). Owners are opaque
/// field elements bound through their nullifier secrets and stay private; the
/// public signer vector holds only the payer. The transaction's
/// `instruction_discriminator` must be `RING_AUTHORITY_TRANSACT`, so its
/// external data hash matches the one SPP recomputes.
#[derive(Clone, Copy, Debug)]
pub struct RingAuthorityRail {
    pub ring_program_id: Option<Address>,
    pub payer: Address,
}

/// The default ring with one owner signing the transaction message digest
/// with its Ed25519 key; the proof verifies that signature, so that owner does
/// not sign the transaction (`CircuitId::ConfidentialEddsa`). Every other
/// input owner still does.
#[derive(Clone, Copy)]
pub struct ConfidentialEddsaRail<'a> {
    pub owner: OwnerAuthorization<'a>,
}

/// A custom-ring transfer whose hidden owner signs the transaction message
/// digest inside the proof (`CircuitId::AnonymousRingEddsa`). Every input the
/// hidden owner spends carries the zero owner tag.
#[derive(Clone, Copy)]
pub struct AnonymousRingEddsaRail<'a> {
    pub owner: OwnerAuthorization<'a>,
    pub ring_program_id: Option<Address>,
}

/// The circuit a [`TransferProver`] builds for. Implemented by the rail types
/// of this module only.
pub trait TransferRail: rail::Sealed {
    /// The proof request inputs a built transfer carries: the transfer
    /// witness, and the in-circuit owner's signature on the rails that verify
    /// one.
    type Inputs;
    #[doc(hidden)]
    type Authorization: rail::InCircuitOwner;

    #[doc(hidden)]
    fn kind(&self) -> rail::RailKind<'_>;

    #[doc(hidden)]
    fn authorize(
        &self,
        statement: &rail::OwnerStatement<'_>,
    ) -> Result<Self::Authorization, ClientError>;

    #[doc(hidden)]
    fn inputs(transfer: TransferInputs, authorization: Self::Authorization) -> Self::Inputs;
}

pub(crate) mod rail {
    use super::*;

    pub trait Sealed {}
    impl Sealed for SignerRail {}
    impl Sealed for RingSignerRail {}
    impl Sealed for RingAuthorityRail {}
    impl Sealed for ConfidentialEddsaRail<'_> {}
    impl Sealed for AnonymousRingEddsaRail<'_> {}

    /// What a rail's in-circuit owner adds to the statement and the request.
    pub trait InCircuitOwner {
        /// The public input hash fields that follow `private_tx_hash`.
        fn public_fields(&self) -> Result<Vec<[u8; 32]>, ClientError>;
        /// The owner fields of the indexed witness.
        fn json(&self) -> Option<OwnerSignatureJson>;
        /// The raw Ed25519 key `CircuitId::AnonymousRingEddsa` carries.
        fn default_owner_tag(&self) -> Option<[u8; 32]>;
    }

    impl InCircuitOwner for () {
        fn public_fields(&self) -> Result<Vec<[u8; 32]>, ClientError> {
            Ok(Vec::new())
        }

        fn json(&self) -> Option<OwnerSignatureJson> {
            None
        }

        fn default_owner_tag(&self) -> Option<[u8; 32]> {
            None
        }
    }

    impl InCircuitOwner for EddsaAuthorization {
        fn public_fields(&self) -> Result<Vec<[u8; 32]>, ClientError> {
            Ok(EddsaAuthorization::public_fields(self)?.to_vec())
        }

        fn json(&self) -> Option<OwnerSignatureJson> {
            Some(OwnerSignatureJson::new(self, None))
        }

        fn default_owner_tag(&self) -> Option<[u8; 32]> {
            None
        }
    }

    impl InCircuitOwner for PreparedAnonymousAuthorization {
        fn public_fields(&self) -> Result<Vec<[u8; 32]>, ClientError> {
            Ok(self.authorization.public_fields()?.to_vec())
        }

        fn json(&self) -> Option<OwnerSignatureJson> {
            Some(self.authorization.json())
        }

        fn default_owner_tag(&self) -> Option<[u8; 32]> {
            self.default_owner_tag
        }
    }

    /// The hidden owner's signature and, when it spends a default-ring UTXO,
    /// the key the selector publishes.
    pub struct PreparedAnonymousAuthorization {
        pub authorization: AnonymousEddsaAuthorization,
        pub default_owner_tag: Option<[u8; 32]>,
    }

    /// What an in-circuit owner signs and checks its spend against.
    pub struct OwnerStatement<'a> {
        pub inputs: &'a [TransferInputUtxo],
        pub private_tx: &'a [u8; 32],
        pub external_data_hash: &'a [u8; 32],
        pub published_owners: &'a [[u8; 32]],
    }

    /// The parts of a rail the shared pipeline branches on.
    #[derive(Clone, Copy)]
    pub enum RailKind<'a> {
        Signer,
        RingSigner {
            ring: Option<Address>,
        },
        RingAuthority {
            ring: Option<Address>,
            payer: Address,
        },
        ConfidentialEddsa {
            owner: OwnerAuthorization<'a>,
        },
        AnonymousRingEddsa {
            ring: Option<Address>,
            owner: OwnerAuthorization<'a>,
        },
    }

    impl RailKind<'_> {
        pub(crate) fn is_ring_authority(&self) -> bool {
            matches!(self, Self::RingAuthority { .. })
        }

        /// The rail whose shape set a transaction must fall in.
        pub(crate) fn transact_rail(&self) -> TransactRail {
            match self {
                Self::ConfidentialEddsa { .. } => TransactRail::ConfidentialEddsa,
                _ => TransactRail::ConfidentialSigner,
            }
        }

        pub(crate) fn check_shape(
            &self,
            shape: Shape,
            n_in: usize,
            n_out: usize,
        ) -> Result<(), ClientError> {
            match self {
                Self::ConfidentialEddsa { .. } => {
                    if !shape.is_confidential_eddsa()
                        || shape.n_inputs() != n_in
                        || shape.n_outputs() != n_out
                    {
                        return Err(ClientError::UnsupportedShape { n_in, n_out });
                    }
                    Ok(())
                }
                _ => validate_shape(shape, n_in, n_out),
            }
        }

        pub(crate) fn owner_mode(&self) -> OwnerMode {
            match self {
                Self::RingAuthority { .. } => OwnerMode::RingAuthority,
                Self::AnonymousRingEddsa { owner, .. } => {
                    OwnerMode::AnonymousEddsa(owner.public_key())
                }
                _ => OwnerMode::SolanaEddsa,
            }
        }

        /// The hidden owner whose inputs carry the zero owner tag.
        pub(crate) fn hidden_owner(&self) -> Option<spr_keypair::PublicKey> {
            match self {
                Self::AnonymousRingEddsa { owner, .. } => Some(owner.public_key()),
                _ => None,
            }
        }

        pub(crate) fn ring(&self) -> Option<Address> {
            match self {
                Self::Signer | Self::ConfidentialEddsa { .. } => None,
                Self::RingSigner { ring }
                | Self::RingAuthority { ring, .. }
                | Self::AnonymousRingEddsa { ring, .. } => *ring,
            }
        }

        /// The public signer vector a builder is handed: none on the ring
        /// authority rail, whose one signer is the payer.
        pub(crate) fn given_signer_width(&self, shape: Shape) -> usize {
            match self {
                Self::RingAuthority { .. } => 0,
                _ => shape.signer_width(),
            }
        }

        /// The public signer vector of `transaction` on this rail, without
        /// the in-circuit owner.
        pub(crate) fn transaction_signers(
            &self,
            transaction: &SppProofInputs,
            shape: Shape,
        ) -> Result<Vec<[u8; 32]>, ClientError> {
            match self {
                Self::Signer | Self::RingSigner { .. } => {
                    Ok(transaction.signer_pk_hashes(shape.signer_width())?)
                }
                Self::RingAuthority { .. } => Ok(Vec::new()),
                Self::ConfidentialEddsa { owner } => {
                    confidential_eddsa_signer_pk_hashes(transaction, &owner.public_key())
                }
                Self::AnonymousRingEddsa { owner, .. } => {
                    anonymous_signer_pk_hashes(transaction, &owner.public_key())
                }
            }
        }

        /// The public signer vector the statement binds.
        pub(crate) fn signers(&self, given: Vec<[u8; 32]>) -> Result<Vec<[u8; 32]>, ClientError> {
            match self {
                Self::RingAuthority { payer, .. } => {
                    Ok(vec![solana_owner_identity(payer.as_array())?])
                }
                _ => Ok(given),
            }
        }

        /// The output owner hashes the statement publishes: every slot on the
        /// default ring, only the confidential-encryption-marked slots on a
        /// custom ring, none for the ring authority.
        pub(crate) fn published_owners(
            &self,
            external_data: &ExternalData,
            output_owner_pk_hashes: &[[u8; 32]],
        ) -> Result<Option<Vec<[u8; 32]>>, ClientError> {
            match self {
                Self::Signer | Self::ConfidentialEddsa { .. } => {
                    Ok(Some(output_owner_pk_hashes.to_vec()))
                }
                Self::RingSigner { .. } | Self::AnonymousRingEddsa { .. } => {
                    Ok(Some(confidential_marked_output_owner_pk_hashes(
                        external_data,
                        output_owner_pk_hashes.len(),
                    )?))
                }
                Self::RingAuthority { .. } => Ok(None),
            }
        }

        /// The selector the instruction carries, before any commitment.
        pub(crate) fn circuit(
            &self,
            shape: Shape,
            cache_access: Option<CacheAccess>,
            default_owner_tag: Option<[u8; 32]>,
        ) -> Result<CircuitId, ClientError> {
            let unsupported = || ClientError::UnsupportedShape {
                n_in: shape.n_inputs(),
                n_out: shape.n_outputs(),
            };
            let n_in = u8::try_from(shape.n_inputs()).map_err(|_| unsupported())?;
            let n_out = u8::try_from(shape.n_outputs()).map_err(|_| unsupported())?;
            let slots = N_PUBLIC_SLOTS as u8;
            Ok(match (self, cache_access) {
                (Self::Signer, Some(access)) => {
                    CircuitId::ConfidentialSignerCached(n_in, n_out, slots, access)
                }
                (Self::Signer, None) => CircuitId::ConfidentialSigner(n_in, n_out, slots),
                (Self::RingSigner { .. }, Some(access)) => {
                    CircuitId::ConfidentialRingEddsaCached(n_in, n_out, slots, access)
                }
                (Self::RingSigner { .. }, None) => {
                    CircuitId::ConfidentialRingEddsa(n_in, n_out, slots)
                }
                (Self::RingAuthority { .. }, _) => CircuitId::RingAuthority(n_in, n_out, slots),
                (Self::ConfidentialEddsa { owner }, access) => {
                    confidential_eddsa_circuit(shape, owner.public_key().as_ed25519()?, access)
                }
                (Self::AnonymousRingEddsa { .. }, access) => {
                    let data = AnonymousRingEddsaProofData {
                        default_owner_tag,
                        bsb22_commitment: Bsb22Commitment {
                            commitment: [0; 32],
                            commitment_pok: [0; 32],
                        },
                    };
                    match access {
                        Some(access) => {
                            CircuitId::AnonymousRingEddsaCached(n_in, n_out, slots, data, access)
                        }
                        None => CircuitId::AnonymousRingEddsa(n_in, n_out, slots, data),
                    }
                }
            })
        }
    }
}

impl TransferRail for SignerRail {
    type Inputs = TransferInputs;
    type Authorization = ();

    fn kind(&self) -> rail::RailKind<'_> {
        rail::RailKind::Signer
    }

    fn authorize(&self, _: &rail::OwnerStatement<'_>) -> Result<(), ClientError> {
        Ok(())
    }

    fn inputs(transfer: TransferInputs, (): ()) -> TransferInputs {
        transfer
    }
}

impl TransferRail for RingSignerRail {
    type Inputs = TransferInputs;
    type Authorization = ();

    fn kind(&self) -> rail::RailKind<'_> {
        rail::RailKind::RingSigner {
            ring: self.ring_program_id,
        }
    }

    fn authorize(&self, _: &rail::OwnerStatement<'_>) -> Result<(), ClientError> {
        Ok(())
    }

    fn inputs(transfer: TransferInputs, (): ()) -> TransferInputs {
        transfer
    }
}

impl TransferRail for RingAuthorityRail {
    type Inputs = TransferInputs;
    type Authorization = ();

    fn kind(&self) -> rail::RailKind<'_> {
        rail::RailKind::RingAuthority {
            ring: self.ring_program_id,
            payer: self.payer,
        }
    }

    fn authorize(&self, _: &rail::OwnerStatement<'_>) -> Result<(), ClientError> {
        Ok(())
    }

    fn inputs(transfer: TransferInputs, (): ()) -> TransferInputs {
        transfer
    }
}

impl TransferRail for ConfidentialEddsaRail<'_> {
    type Inputs = ConfidentialEddsaTransferInputs;
    type Authorization = EddsaAuthorization;

    fn kind(&self) -> rail::RailKind<'_> {
        rail::RailKind::ConfidentialEddsa { owner: self.owner }
    }

    fn authorize(
        &self,
        statement: &rail::OwnerStatement<'_>,
    ) -> Result<EddsaAuthorization, ClientError> {
        self.owner
            .authorize(statement.private_tx, statement.external_data_hash)
    }

    fn inputs(
        transfer: TransferInputs,
        authorization: EddsaAuthorization,
    ) -> ConfidentialEddsaTransferInputs {
        ConfidentialEddsaTransferInputs {
            transfer,
            authorization,
        }
    }
}

impl TransferRail for AnonymousRingEddsaRail<'_> {
    type Inputs = AnonymousEddsaTransferInputs;
    type Authorization = rail::PreparedAnonymousAuthorization;

    fn kind(&self) -> rail::RailKind<'_> {
        rail::RailKind::AnonymousRingEddsa {
            ring: self.ring_program_id,
            owner: self.owner,
        }
    }

    fn authorize(
        &self,
        statement: &rail::OwnerStatement<'_>,
    ) -> Result<rail::PreparedAnonymousAuthorization, ClientError> {
        AnonymousAuthorizationPreparation {
            inputs: statement.inputs,
            owner: self.owner,
            private_tx: statement.private_tx,
            external_data_hash: statement.external_data_hash,
            published_owners: statement.published_owners,
        }
        .prepare()
    }

    fn inputs(
        transfer: TransferInputs,
        authorization: rail::PreparedAnonymousAuthorization,
    ) -> AnonymousEddsaTransferInputs {
        AnonymousEddsaTransferInputs {
            transfer,
            authorization: authorization.authorization,
        }
    }
}

/// A transfer whose inputs and outputs are already padded to `shape`, built
/// for `rail`.
pub struct TransferProver<R = SignerRail> {
    pub inputs: Vec<TransferInputUtxo>,
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The transaction's private random root seed. The output blinding seed
    /// and the private transaction blinding derive from it and the first
    /// nullifier; the circuit repeats both derivations.
    pub blinding_seed: [u8; 32],
    /// Raw id of the tree every output is appended to.
    pub output_tree_id: u16,
    pub external_data: ExternalData,
    pub public_transfers: PublicTransfers,
    /// The Solana owner signers, padded to the shape's signer width, without
    /// the in-circuit owner. The ring authority rail takes none: its one
    /// signer is the payer.
    pub signer_pk_hashes: Vec<[u8; 32]>,
    pub allow_dummy_inputs: bool,
    pub shape: Shape,
    /// The ring authority rail reads and writes no cache.
    pub cache_accounts: CacheAccounts,
    pub rail: R,
}

#[derive(Debug, Clone)]
pub struct TransferProofResult<I = TransferInputs> {
    /// Assembled but not complete: every real input is still waiting for its
    /// owner's [`ProofAuthority`](crate::authority::ProofAuthority) to fill in
    /// the nullifier secret, which the prover request refuses without.
    pub inputs: I,
    pub public_input_hash: [u8; 32],
    /// Every circuit slot's published value, 0 for compact padding. The
    /// instruction carries only the slots before the compact padding, so derive
    /// nullifier PDAs from the instruction data, not from these.
    pub nullifiers: Vec<[u8; 32]>,
    pub output_hashes: Vec<[u8; 32]>,
    pub private_tx_hash: [u8; 32],
    /// One root-index pair per input tree, in the order the tree accounts are
    /// passed. An input selects its pair with its `tree_index`.
    pub tree_contexts: Vec<TreeContext>,
    /// The raw ids of those trees, parallel to `tree_contexts`. The `Transact`
    /// builder takes one tree account per context entry in the same order, and
    /// `pda::tree` of these is where that list comes from. Nothing else carries
    /// it: a `TreeContext` holds root indexes only.
    pub tree_ids: Vec<u16>,
    /// Each input's index into `tree_contexts`, parallel to `nullifiers`.
    pub input_tree_indexes: Vec<u8>,
    pub cache_access: Option<CacheAccess>,
    /// The selector the instruction carries, before the proof fills in any
    /// commitment.
    pub circuit: CircuitId,
    /// Raw Ed25519 key carried in `CircuitId::AnonymousRingEddsa` when the hidden
    /// owner spends a default-ring UTXO. Address slots never set it.
    pub default_owner_tag: Option<[u8; 32]>,
}

impl<R: TransferRail> TransferProver<R> {
    pub fn build(self) -> Result<TransferProofResult<R::Inputs>, ClientError> {
        use rail::InCircuitOwner;

        let Self {
            inputs,
            outputs,
            blinding_seed,
            output_tree_id,
            external_data,
            public_transfers,
            signer_pk_hashes,
            allow_dummy_inputs,
            shape,
            cache_accounts,
            rail,
        } = self;
        let kind = rail.kind();
        kind.check_shape(shape, inputs.len(), outputs.len())?;
        let expected = kind.given_signer_width(shape);
        if signer_pk_hashes.len() != expected {
            return Err(ClientError::WitnessInputCountMismatch {
                got: signer_pk_hashes.len(),
                expected,
            });
        }
        let cache = CacheSelection::derive(&inputs, &outputs, cache_accounts, &external_data)?;
        if kind.is_ring_authority() && cache.access.is_some() {
            return Err(ClientError::CacheUnsupported);
        }
        let AssembledTransaction {
            inputs: assembled_inputs,
            outputs: assembled_outputs,
            external_data_hash,
            private_tx_hash: private_tx,
            input_flags,
        } = assemble_transaction(
            &inputs,
            &outputs,
            &blinding_seed,
            output_tree_id,
            &cache.external_data_hash,
            &kind.owner_mode(),
            allow_dummy_inputs,
        )?;
        let published_owners =
            kind.published_owners(&external_data, &assembled_outputs.output_owner_pk_hashes)?;
        let authorization = rail.authorize(&rail::OwnerStatement {
            inputs: &inputs,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            published_owners: published_owners.as_deref().unwrap_or_default(),
        })?;
        let ring_program_id = program_id_proof_input_hash(&kind.ring())?;
        let signer_pk_hashes = kind.signers(signer_pk_hashes)?;
        let public_input = PublicInputs {
            nullifiers: &assembled_inputs.nullifiers,
            output_hashes: &assembled_outputs.output_hashes,
            tree_slots: &assembled_inputs.tree_slots,
            output_tree_id,
            private_tx: &private_tx,
            external_data_hash: &external_data_hash,
            public_transfers: &public_transfers,
            ring_program_id: &ring_program_id,
            input_flags: &input_flags,
            signer_pk_hashes: &signer_pk_hashes,
            output_owner_pk_hashes: published_owners.as_deref(),
            cached_inputs: cache.public_fields,
        }
        .hash_with_after_private_tx(&authorization.public_fields()?)?;

        let transfer = TransferInputs {
            inputs: assembled_inputs.inputs,
            outputs: assembled_outputs.outputs,
            tree_slots: TreeSlotFields::encode_all(&assembled_inputs.tree_slots),
            output_tree_id: BigUint::from(output_tree_id),
            blinding_seed: be(&blinding_seed),
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            public_assets: public_transfers.assets.map(|asset| be(&asset)),
            public_amounts: public_transfers.amounts.map(|amount| be(&amount)),
            ring_program_id: be(&ring_program_id),
            signer_pk_hashes: signer_pk_hashes.iter().map(be).collect(),
            input_flags: be(&input_flags),
            published_output_owner_pk_hashes: published_owners
                .unwrap_or_default()
                .iter()
                .map(be)
                .collect(),
            // The ring authority circuit carries no cache selection; the
            // prover ignores these for that rail.
            cache: if kind.is_ring_authority() {
                Default::default()
            } else {
                cache.proof_inputs
            },
            public_input_hash: be(&public_input),
        };
        let default_owner_tag = authorization.default_owner_tag();
        Ok(TransferProofResult {
            inputs: R::inputs(transfer, authorization),
            public_input_hash: public_input,
            nullifiers: assembled_inputs.nullifiers,
            output_hashes: assembled_outputs.output_hashes,
            private_tx_hash: private_tx,
            tree_contexts: assembled_inputs.tree_contexts,
            tree_ids: assembled_inputs.tree_ids,
            input_tree_indexes: assembled_inputs.input_tree_indexes,
            cache_access: cache.access,
            circuit: kind.circuit(shape, cache.access, default_owner_tag)?,
            default_owner_tag,
        })
    }
}
