use core::fmt;

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
        utxo: AuditedUtxo,
        recipient_u: [u8; 32],
        /// `None` outside the anonymous rail.
        tag: Option<RingTag>,
    },
    /// A default-ring note, its owner the published owner tag.
    Exit(AuditedUtxo),
    Dummy,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuditedUtxo {
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

/// A ring or default-ring note an earlier audit opened, indexed by its UTXO hash.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KnownUtxo {
    pub owner_key: [u8; 32],
    pub owner: UtxoOwner,
    pub asset: [u8; 32],
    pub mint: Option<Address>,
    pub amount: u64,
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub tree_id: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UtxoOwner {
    Keyed {
        nullifier_pk: [u8; 32],
    },
    /// A deposit capsule discloses the owner hash alone.
    Deposited {
        owner_hash: [u8; 32],
    },
}

/// A note one transaction created, at its slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatedUtxo {
    pub commitment: [u8; 32],
    pub slot_index: u32,
    pub utxo: KnownUtxo,
}

/// The sender every spent UTXO of an anonymous transfer belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditedSender {
    pub owner_key: [u8; 32],
    /// Spent UTXO 0's key, every input's under the entry key, `None` when UTXO 0 was deposited.
    pub nullifier_pk: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditedInput {
    pub nullifier: [u8; 32],
    /// `None` for a dummy input.
    pub opening: Option<AuditedInputOpening>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
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
    /// The slot's disclosure bytes do not parse under the layout.
    Disclosure,
    /// The recipient key admits no X25519 agreement.
    RecipientKey,
    /// The rebuilt opening hashes to another commitment.
    Commitment,
    /// The auditor holds no escrowed key for the owner.
    EscrowUnknown,
}

impl AuditedTransaction {
    /// The ring and exit notes its outputs opened, the index a [`crate::KnownUtxos`] keeps.
    pub fn utxos(&self) -> impl Iterator<Item = CreatedUtxo> + '_ {
        self.outputs.iter().filter_map(|output| {
            output.opening.utxo().map(|utxo| CreatedUtxo {
                commitment: output.context.hash,
                slot_index: output.slot_index,
                utxo: KnownUtxo::opened(*utxo, output.context.tree_id),
            })
        })
    }

    /// An unknown mint leaves the opening verified, a registry refresh may name it.
    pub fn has_unknown_assets(&self) -> bool {
        let outputs = self
            .outputs
            .iter()
            .filter_map(|output| output.opening.utxo())
            .map(|utxo| utxo.mint);
        let inputs = self
            .inputs
            .iter()
            .filter_map(|input| input.opening)
            .map(|opening| opening.mint);
        outputs.chain(inputs).any(|mint| mint.is_none())
    }
}

impl OutputOpening {
    pub fn utxo(&self) -> Option<&AuditedUtxo> {
        match self {
            Self::Ring { utxo, .. } | Self::Exit(utxo) => Some(utxo),
            Self::Dummy => None,
        }
    }
}

impl AuditedUtxo {
    /// `Poseidon(owner_identity(owner_key), nullifier_pk)`.
    pub fn owner_hash(&self) -> Result<[u8; 32], AuditError> {
        UtxoOwner::Keyed {
            nullifier_pk: self.nullifier_pk,
        }
        .hash(&self.owner_key)
    }

    /// The commitment of the note in `tree_id`, `ring` `None` for the default ring.
    pub(crate) fn commitment(
        &self,
        tree_id: u16,
        ring: Option<Address>,
    ) -> Result<[u8; 32], AuditError> {
        KnownUtxo::opened(*self, tree_id).commitment(ring)
    }
}

impl KnownUtxo {
    pub fn opened(utxo: AuditedUtxo, tree_id: u16) -> Self {
        Self {
            owner_key: utxo.owner_key,
            owner: UtxoOwner::Keyed {
                nullifier_pk: utxo.nullifier_pk,
            },
            asset: utxo.asset,
            mint: utxo.mint,
            amount: utxo.amount,
            blinding: utxo.blinding,
            data_hash: utxo.data_hash,
            ring_data_hash: utxo.ring_data_hash,
            tree_id,
        }
    }

    pub fn owner_hash(&self) -> Result<[u8; 32], AuditError> {
        self.owner.hash(&self.owner_key)
    }

    /// The UTXO hash, `ring` `None` for the default ring.
    pub fn commitment(&self, ring: Option<Address>) -> Result<[u8; 32], AuditError> {
        Ok(ProofInputUtxo {
            domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
            tree_id: tree_id_field(self.tree_id),
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

impl UtxoOwner {
    pub fn nullifier_pk(self) -> Option<[u8; 32]> {
        match self {
            Self::Keyed { nullifier_pk } => Some(nullifier_pk),
            Self::Deposited { .. } => None,
        }
    }

    fn hash(self, owner_key: &[u8; 32]) -> Result<[u8; 32], AuditError> {
        match self {
            Self::Keyed { nullifier_pk } => Ok(Poseidon::hashv(&[
                &solana_owner_identity(owner_key)?,
                &nullifier_pk,
            ])?),
            Self::Deposited { owner_hash } => Ok(owner_hash),
        }
    }
}

const REDACTED: &str = "<redacted>";

impl fmt::Debug for AuditedUtxo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            owner_key,
            nullifier_pk,
            asset,
            mint,
            amount,
            blinding: _,
            data_hash,
            ring_data_hash,
        } = self;
        f.debug_struct("AuditedNote")
            .field("owner_key", owner_key)
            .field("nullifier_pk", nullifier_pk)
            .field("asset", asset)
            .field("mint", mint)
            .field("amount", amount)
            .field("blinding", &REDACTED)
            .field("data_hash", data_hash)
            .field("ring_data_hash", ring_data_hash)
            .finish()
    }
}

impl fmt::Debug for KnownUtxo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            owner_key,
            owner,
            asset,
            mint,
            amount,
            blinding: _,
            data_hash,
            ring_data_hash,
            tree_id,
        } = self;
        f.debug_struct("KnownNote")
            .field("owner_key", owner_key)
            .field("owner", owner)
            .field("asset", asset)
            .field("mint", mint)
            .field("amount", amount)
            .field("blinding", &REDACTED)
            .field("data_hash", data_hash)
            .field("ring_data_hash", ring_data_hash)
            .field("tree_id", tree_id)
            .finish()
    }
}

impl fmt::Debug for AuditedInputOpening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            asset,
            mint,
            amount,
            blinding: _,
            ring,
        } = self;
        f.debug_struct("AuditedInputOpening")
            .field("asset", asset)
            .field("mint", mint)
            .field("amount", amount)
            .field("blinding", &REDACTED)
            .field("ring", ring)
            .finish()
    }
}
