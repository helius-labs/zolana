//! What an audit returns, the slot openings and an anonymous transfer's sender and inputs.

use custom_ring_interface::stream::RingTag;
#[cfg(feature = "rpc")]
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signature::Signature;
use zolana_client::ProofInputUtxo;
use zolana_hasher::{
    primitives::{right_align, solana_owner_identity},
    Hasher, Poseidon,
};
use zolana_interface::tree_slot::tree_id_field;
use zolana_keypair::X25519Pubkey;
use zolana_transaction::{
    utxo::{program_id_proof_input_hash, UTXO_DOMAIN},
    OutputContext,
};

use crate::AuditError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditedTransaction {
    pub tx_signature: Signature,
    pub slot: u64,
    /// Checked against the key the auditor envelope seals.
    pub tx_viewing_pk: X25519Pubkey,
    /// Published order, a slot that did not open sits in `payload_errors` instead.
    pub outputs: Vec<AuditedOutput>,
    pub payload_errors: Vec<OutputPayloadError>,
    /// `None` outside the anonymous rail.
    pub sender: Option<AuditedSender>,
    /// One per published nullifier of an anonymous transfer.
    pub inputs: Vec<AuditedInput>,
}

/// One opened slot, its note rebuilt to the published commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditedOutput {
    pub slot_index: u32,
    pub context: OutputContext,
    pub opening: OutputOpening,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputOpening {
    Ring {
        note: AuditedNote,
        recipient_u: [u8; 32],
        /// `None` outside the anonymous rail.
        tag: Option<RingTag>,
    },
    /// A default-ring note, its owner the published owner tag.
    Exit(AuditedNote),
    Dummy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditedNote {
    /// The raw Solana key whose owner identity the commitment binds.
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    /// `hash_bytes(mint)`.
    pub asset: [u8; 32],
    /// `None` until the asset registry knows the asset.
    pub mint: Option<Address>,
    pub amount: u64,
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
}

/// A ring note an earlier audit opened, what a spend of it names by its UTXO hash alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownNote {
    pub owner_key: [u8; 32],
    /// `None` for a deposit, its capsule discloses the owner hash.
    pub nullifier_pk: Option<[u8; 32]>,
    pub asset: [u8; 32],
    pub mint: Option<Address>,
    pub amount: u64,
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
}

/// The sender every spent UTXO of an anonymous transfer belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditedSender {
    pub owner_key: [u8; 32],
    /// Spent UTXO 0's key, every input's under the entry key, `None` for a deposited note.
    pub nullifier_pk: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditedInput {
    pub nullifier: [u8; 32],
    /// `None` for a dummy input.
    pub opening: Option<AuditedInputOpening>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditedInputOpening {
    pub asset: [u8; 32],
    pub mint: Option<Address>,
    pub amount: u64,
    pub blinding: [u8; 32],
    /// `None` without the input's tree id, every commitment binds it.
    pub ring: Option<InputRing>,
}

/// SPP spends a UTXO of the ring or of the default ring, an entry disclosure names neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputRing {
    Ring {
        commitment: [u8; 32],
    },
    Default {
        commitment: [u8; 32],
    },
    /// No known commitment told the candidates apart.
    Unresolved {
        ring: [u8; 32],
        default: [u8; 32],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputPayloadError {
    pub slot_index: u32,
    pub kind: OutputPayloadErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "rpc", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rpc", serde(rename_all = "camelCase"))]
pub enum OutputPayloadErrorKind {
    /// No body of the layout's scheme and length, or no tag in the owner tag.
    Frame,
    /// The recipient key admits no X25519 agreement.
    RecipientKey,
    /// The rebuilt opening hashes to another commitment.
    Commitment,
    /// The auditor holds no escrowed key for the owner.
    EscrowUnknown,
}

impl AuditedTransaction {
    /// Every opened note by its commitment, the entries a [`crate::KnownNotes`] index keeps.
    pub fn notes(&self) -> impl Iterator<Item = ([u8; 32], KnownNote)> + '_ {
        self.outputs.iter().filter_map(|output| {
            output
                .opening
                .note()
                .map(|note| (output.context.hash, KnownNote::from(*note)))
        })
    }

    /// An unknown mint leaves the opening verified, a registry refresh may name it.
    pub fn has_unknown_assets(&self) -> bool {
        let outputs = self
            .outputs
            .iter()
            .filter_map(|output| output.opening.note())
            .map(|note| note.mint);
        let inputs = self
            .inputs
            .iter()
            .filter_map(|input| input.opening)
            .map(|opening| opening.mint);
        outputs.chain(inputs).any(|mint| mint.is_none())
    }
}

impl OutputOpening {
    pub fn note(&self) -> Option<&AuditedNote> {
        match self {
            Self::Ring { note, .. } | Self::Exit(note) => Some(note),
            Self::Dummy => None,
        }
    }
}

impl From<AuditedNote> for KnownNote {
    fn from(note: AuditedNote) -> Self {
        Self {
            owner_key: note.owner_key,
            nullifier_pk: Some(note.nullifier_pk),
            asset: note.asset,
            mint: note.mint,
            amount: note.amount,
            blinding: note.blinding,
            data_hash: note.data_hash,
            ring_data_hash: note.ring_data_hash,
        }
    }
}

impl AuditedNote {
    /// `Poseidon(owner_identity(owner_key), nullifier_pk)`.
    pub fn owner_hash(&self) -> Result<[u8; 32], AuditError> {
        Ok(Poseidon::hashv(&[
            &solana_owner_identity(&self.owner_key)?,
            &self.nullifier_pk,
        ])?)
    }

    /// The commitment of the note in `tree_id`, `ring` `None` for the default ring.
    pub(crate) fn commitment(
        &self,
        tree_id: u16,
        ring: Option<Address>,
    ) -> Result<[u8; 32], AuditError> {
        Ok(ProofInputUtxo {
            domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
            tree_id: tree_id_field(tree_id),
            owner_hash: self.owner_hash()?,
            asset: self.asset,
            amount: right_align(&self.amount.to_be_bytes()),
            blinding: self.blinding,
            data_hash: self.data_hash,
            ring_data_hash: self.ring_data_hash,
            ring_program_id: program_id_proof_input_hash(&ring)?,
        }
        .hash()?)
    }
}
