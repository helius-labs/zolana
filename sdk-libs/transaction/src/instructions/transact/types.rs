use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_event::OutputData;
use zolana_keypair::hash::poseidon;
use zolana_keypair::{P256Pubkey, ShieldedAddress};

use crate::error::TransactionError;
use crate::utxo::{owner_utxo_hash, utxo_hash, Blinding, Utxo};

use super::external_data::ExternalData;

/// A spent input UTXO and the owner `nullifier_pk` its hash commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputUtxo {
    pub utxo: Utxo,
    pub nullifier_pk: [u8; 32],
    pub zone_data_hash: Option<[u8; 32]>,
    pub program_data_hash: Option<[u8; 32]>,
}

impl InputUtxo {
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        self.utxo.hash(
            &self.nullifier_pk,
            &self.program_data_hash.unwrap_or_default(),
            &self.zone_data_hash.unwrap_or_default(),
        )
    }
}

/// A new output UTXO. In the confidential default zone the sender knows the
/// recipient's [`ShieldedAddress`], so the output carries it and the proof
/// recomputes `owner_hash` from it and exposes `signing_pubkey.hash()` as the
/// public owner tag. A `None` address is a dummy slot (empty SOL/SPL change or
/// padding to the fixed proof shape).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct OutputUtxo {
    pub asset: Address,
    pub amount: u64,
    pub blinding: Blinding,
    pub zone_program_id: Option<Address>,
    pub zone_data_hash: Option<[u8; 32]>,
    pub program_data_hash: Option<[u8; 32]>,
    pub owner_address: Option<ShieldedAddress>,
    /// Confidential owner tag for a dummy recipient slot: the random `view_tag`
    /// the builder also writes to the slot's `OutputCiphertext`, so the proof's
    /// `output_owner_pk_hashes` entry is a real-looking Poseidon hash (not `0`)
    /// that matches the published tag and never flags the slot as padding.
    /// `None` for real outputs (the tag derives from `owner_address`) and for the
    /// fixed change slots.
    pub owner_tag: Option<[u8; 32]>,
}

impl OutputUtxo {
    /// `owner_hash = Poseidon(signing_pubkey.hash(), nullifier_pubkey)` derived
    /// from the recipient address; `0` (permanently unspendable) for a dummy slot.
    pub fn owner_hash(&self) -> Result<[u8; 32], TransactionError> {
        match &self.owner_address {
            Some(address) => Ok(address.owner_hash()?),
            None => Ok([0u8; 32]),
        }
    }

    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        utxo_hash(
            self.asset,
            self.amount,
            &self.program_data_hash.unwrap_or_default(),
            &self.zone_data_hash.unwrap_or_default(),
            self.zone_program_id,
            &owner_utxo_hash(&self.owner_hash()?, &self.blinding)?,
        )
    }

    /// A dummy slot has no owner address: its `owner_hash` is `0`, so it holds no
    /// value and contributes `0` to the private-tx hash chain (it still gets a
    /// distinct `utxo_hash`).
    pub fn is_dummy(&self) -> bool {
        self.owner_address.is_none()
    }
}

/// A transaction ready to be proved: the spent inputs, the new outputs, and the
/// [`ExternalData`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedTransaction {
    pub inputs: Vec<InputUtxo>,
    pub outputs: Vec<OutputUtxo>,
    pub external_data: ExternalData,
}

impl EncryptedTransaction {
    /// `private_tx_hash = Poseidon(HashChain(inputs), HashChain(outputs), external_data_hash)`.
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        let input_hashes = self
            .inputs
            .iter()
            .map(InputUtxo::hash)
            .collect::<Result<Vec<_>, _>>()?;
        let output_hashes = self
            .outputs
            .iter()
            .map(OutputUtxo::hash)
            .collect::<Result<Vec<_>, _>>()?;
        private_tx_hash(&input_hashes, &output_hashes, &self.external_data.hash()?)
    }
}

pub fn private_tx_hash(
    input_hashes: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
    external_data_hash: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    let input_chain = hash_chain(input_hashes)?;
    let output_chain = hash_chain(output_hashes)?;
    Ok(poseidon(&[
        &input_chain,
        &output_chain,
        external_data_hash,
    ])?)
}

/// Hashes left-to-right: `h = items[0]; h = Poseidon(h, items[i])`. Empty returns zero.
fn hash_chain(items: &[[u8; 32]]) -> Result<[u8; 32], TransactionError> {
    let mut iter = items.iter();
    let mut acc = match iter.next() {
        Some(first) => *first,
        None => return Ok([0u8; 32]),
    };
    for item in iter {
        acc = poseidon(&[&acc, item])?;
    }
    Ok(acc)
}

/// Identifies an output commitment and where it lives in the UTXO tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputContext {
    pub hash: [u8; 32],
    pub tree: Address,
    pub leaf_index: u64,
}
/// One output of a shielded transaction: its view tag and encrypted/plaintext payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputSlot {
    pub view_tag: [u8; 32],
    pub output_context: OutputContext,
    pub payload: Vec<u8>,
}

impl OutputSlot {
    pub fn output_data(&self) -> Option<OutputData> {
        OutputData::try_from_slice(&self.payload).ok()
    }
}

/// A shielded transaction with every output slot in UTXO-tree-append order and the
/// nullifiers it consumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedTransaction {
    pub slot: u64,
    pub tx_signature: solana_signature::Signature,
    /// `None` when there is nothing to decrypt (proofless or plaintext transfer).
    pub tx_viewing_pk: Option<P256Pubkey>,
    /// Transaction-level AES salt shared by every output ciphertext; `None` for
    /// proofless or plaintext transfers.
    pub salt: Option<[u8; 16]>,
    pub output_slots: Vec<OutputSlot>,
    pub nullifiers: Vec<[u8; 32]>,
    pub proofless: bool,
}
