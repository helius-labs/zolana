use borsh::BorshDeserialize;
use solana_address::Address;
use zolana_event::OutputData;
use zolana_keypair::{hash::poseidon, P256Pubkey, ShieldedAddress};

use super::external_data::ExternalData;
use crate::{
    data::{Data, DataRecord},
    error::TransactionError,
    utxo::{owner_utxo_hash, program_id_field, utxo_hash, Blinding, Utxo},
};

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
    /// Program Address governing `program_data`, carried into the recipient
    /// plaintext so the receiver can reconstruct the leaf. NOT folded directly
    /// into the commitment; the commitment uses the derived [`Self::address`].
    pub program_id: Option<Address>,
    /// Derived persistent address field element (see [`crate::utxo::address`])
    /// folded into `program_hash`. Filled by the builder at assemble time once the
    /// address tree pubkey is known (the tree-pubkey seam); `None` (folded as `0`)
    /// for user outputs.
    pub address: Option<[u8; 32]>,
    pub zone_program_id: Option<Address>,
    pub zone_data_hash: Option<[u8; 32]>,
    pub program_data_hash: Option<[u8; 32]>,
    pub owner_address: Option<ShieldedAddress>,
    /// Confidential owner tag for a dummy recipient slot: the random `view_tag`
    /// the builder also writes to the slot's `OutputCiphertext`, so the proof's
    /// `output_owner_pk_hashes` entry is a real-looking Poseidon hash (not `0`)
    /// that matches the published tag and never flags the slot as padding.
    /// `None` for real outputs (the tag derives from `owner_address`). Empty
    /// change slots set it to the sender's `confidential_view_tag` so the proof
    /// folds the sender's `owner_pk_field`, matching the program's bundle
    /// reconstruction.
    pub owner_tag: Option<[u8; 32]>,
    /// `Some(program_id)` marks a program-owned value output: its owner is the
    /// invoking program rather than a user keypair, so the owner field for hashing
    /// is `program_id`'s `pk_field` (not `owner_hash`), and it may carry program
    /// data. The leaf's persistent `address` (set via [`Self::create_address`]) is
    /// the discovery tag; the confidential ciphertext owner tag is set to that
    /// `address` (contract section 9), so `owner_address` / `owner_tag` are ignored
    /// when set. Mirrors the program-owned output path of `constrainOutput` in the
    /// spp_transaction circuit.
    pub program_owner: Option<Address>,
    /// The cleartext zone/program data bytes whose digests populate
    /// `zone_data_hash` / `program_data_hash`. Carried so the recipient can
    /// reconstruct the same `Utxo` (and its leaf hash) the proof committed to;
    /// the on-chain hash semantics use only the digests, not these bytes.
    pub data: Data,
}

impl OutputUtxo {
    /// Bind zone data to this output: set `zone_program_id`, store the cleartext
    /// `zone_data`, and set `zone_data_hash` to its `Sha256BE` field-element
    /// digest (the protocol's byte-preimage-to-field hash). The recipient
    /// recovers identical bytes and recomputes the same `zone_hash`.
    pub fn with_zone_data(
        mut self,
        zone_program_id: Address,
        zone_data: Vec<u8>,
        zone_data_hash: [u8; 32],
    ) -> Self {
        self.zone_data_hash = Some(zone_data_hash);
        self.zone_program_id = Some(zone_program_id);
        self.set_data_record(DataRecord::ZoneData(zone_data));
        self
    }

    /// Bind program data to this output, mirroring [`Self::with_zone_data`] for
    /// the `program_id` / `program_data` / `program_data_hash` triple.
    ///
    /// Sets the program `program_id` (carried into the plaintext) and
    /// `program_data_hash`. It does NOT set the persistent [`Self::address`]: that
    /// is the derived field element `address(tree_pubkey, program_data_hash)` and
    /// the address-tree pubkey is unknown here. Callers that produce a
    /// program-owned output (i.e. that also set `program_owner`) MUST call
    /// [`Self::create_address`] at assemble time, once the tree is known, to fill it.
    /// User outputs leave `address = None` (pinned `0`).
    pub fn with_program_data(
        mut self,
        program_id: Address,
        program_data: Vec<u8>,
        data_hash: [u8; 32],
    ) -> Self {
        self.program_data_hash = Some(data_hash);
        self.program_id = Some(program_id);
        self.set_data_record(DataRecord::ProgramData(program_data));
        self
    }

    pub fn create_address(
        mut self,
        tree_pubkey: &Address,
        seed: [u8; 32],
    ) -> Result<Self, TransactionError> {
        self.address = Some(crate::utxo::address(
            tree_pubkey, // TODO: harcode address tree.
            &seed,
        )?);
        Ok(self)
    }

    /// Replace any existing record of the same kind, then re-order to the
    /// canonical `[ZoneData, ProgramData]` sequence `Data::validate` requires.
    fn set_data_record(&mut self, record: DataRecord) {
        let is_zone = matches!(record, DataRecord::ZoneData(_));
        self.data
            .records
            .retain(|existing| matches!(existing, DataRecord::ZoneData(_)) != is_zone);
        self.data.records.push(record);
        self.data.records.sort_by_key(|record| match record {
            DataRecord::ZoneData(_) => 0u8,
            DataRecord::ProgramData(_) => 1u8,
        });
    }

    /// The owner field folded into `owner_utxo_hash`. For a program-owned output
    /// it is the program's `pk_field`; otherwise
    /// `owner_hash = Poseidon(signing_pubkey.hash(), nullifier_pubkey)` derived
    /// from the recipient address, or `0` (permanently unspendable) for a dummy slot.
    pub fn owner_hash(&self) -> Result<[u8; 32], TransactionError> {
        if let Some(program_id) = self.program_owner {
            return program_id_field(&Some(program_id));
        }
        match &self.owner_address {
            Some(address) => Ok(address.owner_hash()?),
            None => Ok([0u8; 32]),
        }
    }

    /// The persistent address field element committed in the leaf's `program_hash`.
    /// User outputs pin it to `None` (folded as `0`); a program-owned output carries
    /// the derived `address` (set via [`Self::create_address`]).
    pub fn commitment_address(&self) -> Option<[u8; 32]> {
        self.address
    }

    /// The confidential ciphertext owner tag for this output. For a program-owned
    /// output it is the persistent `address` (the discovery tag the circuit binds
    /// to `program_hash`, per contract section 9); otherwise the recipient/dummy
    /// `owner_tag` if set. `None` lets the builder derive it from `owner_address`.
    pub fn ciphertext_owner_tag(&self) -> Option<[u8; 32]> {
        if self.program_owner.is_some() {
            return self.address;
        }
        self.owner_tag
    }

    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        utxo_hash(
            self.asset,
            self.amount,
            &self.program_data_hash.unwrap_or_default(),
            self.commitment_address(),
            &self.zone_data_hash.unwrap_or_default(),
            self.zone_program_id,
            &owner_utxo_hash(&self.owner_hash()?, &self.blinding)?,
        )
    }

    /// A dummy slot has no owner address: its `owner_hash` is `0`, so it holds no
    /// value and contributes `0` to the private-tx hash chain (it still gets a
    /// distinct `utxo_hash`). A program-owned output is never a dummy.
    pub fn is_dummy(&self) -> bool {
        self.program_owner.is_none() && self.owner_address.is_none()
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
    /// `private_tx_hash = Poseidon(HashChain(inputs), HashChain(outputs), HashChain(addresses), external_data_hash)`.
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
        private_tx_hash(
            &input_hashes,
            &output_hashes,
            &no_address_hashes(input_hashes.len()),
            &self.external_data.hash()?,
        )
    }
}

/// `private_tx_hash = Poseidon(HashChain(inputs), HashChain(outputs), HashChain(addresses), external_data_hash)`.
/// `address_hashes` is the address category: the `utxo_hash` of each address slot
/// the transaction creates, `0` for every other input. It has the same length as
/// `input_hashes` (one entry per input slot).
pub fn private_tx_hash(
    input_hashes: &[[u8; 32]],
    output_hashes: &[[u8; 32]],
    address_hashes: &[[u8; 32]],
    external_data_hash: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    let input_chain = hash_chain(input_hashes)?;
    let output_chain = hash_chain(output_hashes)?;
    let address_chain = hash_chain(address_hashes)?;
    Ok(poseidon(&[
        &input_chain,
        &output_chain,
        &address_chain,
        external_data_hash,
    ])?)
}

/// The address category for a transaction that creates no addresses: one zero per
/// input slot, matching the circuit's per-input address chain. Pass an empty slice
/// only for an empty input set -- the chain folds one entry per input.
pub fn no_address_hashes(n_inputs: usize) -> Vec<[u8; 32]> {
    vec![[0u8; 32]; n_inputs]
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
