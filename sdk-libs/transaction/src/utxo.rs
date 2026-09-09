use solana_address::Address;
use zolana_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, Poseidon,
};
use zolana_interface::tree_slot::tree_id_field;
pub use zolana_interface::{DUMMY_DOMAIN, UTXO_DOMAIN};
use zolana_keypair::{NullifierKey, PublicKey};

use crate::{
    data::Data, error::TransactionError, serialization::confidential::ConfidentialOutputPlaintext,
    AssetRegistry,
};

/// A UTXO blinding: a 32-byte big-endian BN254 field element. Poseidon-derived
/// blindings use the full field width; random values right-align 31 bytes to
/// stay below the field modulus.
pub type Blinding = [u8; 32];

// The blinding seed derivations live in `zolana_program::derivation` so
// programs can recompute them on-chain; this module keeps the SDK entry points
// and maps the hasher error into `TransactionError`.
pub use zolana_program::derivation::{
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};

/// `Poseidon(TXOS, first_nullifier, blinding_seed)`: the seed every physical output
/// blinding of one transaction comes from. `blinding_seed` is the transaction's
/// private random root seed. The derived output seed is disclosed to the reader
/// of an anonymous Sender bundle, a plaintext transfer, or a split bundle, which
/// is why it is domain-separated from [`derive_private_tx_blinding`].
pub fn derive_output_blinding_seed(
    first_nullifier: &[u8; 32],
    blinding_seed: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    Ok(zolana_program::derive_output_blinding_seed(
        first_nullifier,
        blinding_seed,
    )?)
}

/// `Poseidon(TXPB, first_nullifier, secret)`: the final `private_tx_hash`
/// preimage element. It is never published: every other preimage element is
/// public or computable, so a known blinding would let an observer test
/// candidate input UTXO hashes against the published hash. `secret` is the
/// blinding seed on the transact rails and the owner's nullifier secret on
/// the merge rails.
pub fn derive_private_tx_blinding(
    first_nullifier: &[u8; 32],
    secret: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    Ok(zolana_program::derive_private_tx_blinding(
        first_nullifier,
        secret,
    )?)
}

/// `Poseidon(TXOB, first_nullifier, seed, output_index)`: the final blinding of
/// one physical SPP transaction output slot. The first nullifier makes the
/// derivation unique across accepted transactions, while `output_index` makes
/// every slot unique within one transaction. Only the final result is shared
/// with the output recipient.
pub fn derive_transact_output_blinding(
    first_nullifier: &[u8; 32],
    seed: &Blinding,
    output_index: u32,
) -> Result<Blinding, TransactionError> {
    Ok(zolana_program::derive_transact_output_blinding(
        first_nullifier,
        seed,
        output_index,
    )?)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub owner: PublicKey,
    pub asset: Address,
    pub amount: u64,
    pub blinding: Blinding,
    pub ring_program_id: Option<Address>,
    pub data: Data,
}

pub(crate) fn resolve_ring_program_id(
    ring_program_id: Option<Address>,
    data: &Data,
) -> Result<Option<Address>, TransactionError> {
    if data.ring_data().is_none() {
        return Ok(None);
    }
    if ring_program_id.is_none() {
        return Err(TransactionError::MissingRingProgramId);
    }
    Ok(ring_program_id)
}

pub fn ring_program_id_proof_input_hash(
    ring_program_id: &Option<Address>,
) -> Result<[u8; 32], TransactionError> {
    program_id_proof_input_hash(ring_program_id)
}

pub fn program_id_proof_input_hash(
    program_id: &Option<Address>,
) -> Result<[u8; 32], TransactionError> {
    match program_id {
        Some(id) => Ok(hash_bytes(id.as_array())?),
        None => Ok([0u8; 32]),
    }
}

pub fn owner_utxo_hash(
    owner_hash: &[u8; 32],
    blinding: &Blinding,
) -> Result<[u8; 32], TransactionError> {
    let blinding = right_align(blinding);
    Ok(Poseidon::hashv(&[owner_hash, &blinding])?)
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ProofInputUtxo {
    pub domain: [u8; 32],
    /// The raw `u16` id of the tree holding this UTXO, right-aligned. This is
    /// transaction context rather than a UTXO body field: an input is hashed
    /// under the id of the tree it is spent from, an output under the id of the
    /// tree it is appended to.
    pub tree_id: [u8; 32],
    pub owner_hash: [u8; 32],
    pub asset: [u8; 32],
    pub amount: [u8; 32],
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub ring_program_id: [u8; 32],
}

impl ProofInputUtxo {
    pub fn new(
        owner_hash: [u8; 32],
        asset: &Address,
        amount: u64,
        blinding: &Blinding,
        tree_id: u16,
    ) -> Result<Self, TransactionError> {
        Ok(Self {
            domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
            tree_id: tree_id_field(tree_id),
            owner_hash,
            asset: hash_bytes(asset.as_array())?,
            amount: right_align(&amount.to_be_bytes()),
            blinding: right_align(blinding),
            data_hash: [0u8; 32],
            ring_data_hash: [0u8; 32],
            ring_program_id: [0u8; 32],
        })
    }

    /// Padding (dummy) slot: the circuit requires every field except the domain
    /// tag and blinding to be zero, so dummy hashes are indistinguishable from
    /// real ones while the slot provably carries nothing. The tree id is not a
    /// UTXO field, so a dummy is hashed under its slot's tree id like any other.
    pub fn new_dummy(blinding: &Blinding, tree_id: u16) -> Self {
        Self {
            domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
            tree_id: tree_id_field(tree_id),
            blinding: right_align(blinding),
            ..Default::default()
        }
    }

    pub fn with_data_hash(mut self, data_hash: [u8; 32]) -> Self {
        self.data_hash = data_hash;
        self
    }

    pub fn with_ring(
        mut self,
        ring_data_hash: [u8; 32],
        ring_program_id: &Option<Address>,
    ) -> Result<Self, TransactionError> {
        self.ring_data_hash = ring_data_hash;
        self.ring_program_id = program_id_proof_input_hash(ring_program_id)?;
        Ok(self)
    }

    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        let ring_hash = Poseidon::hashv(&[&self.ring_data_hash, &self.ring_program_id])?;
        let owner_utxo_hash = Poseidon::hashv(&[&self.owner_hash, &self.blinding])?;
        Ok(Poseidon::hashv(&[
            &self.domain,
            &self.tree_id,
            &self.asset,
            &self.amount,
            &self.data_hash,
            &ring_hash,
            &owner_utxo_hash,
        ])?)
    }
}

impl Utxo {
    pub fn proof_input(
        &self,
        nullifier_pk: &[u8; 32],
        data_hash: &[u8; 32],
        ring_data_hash: &[u8; 32],
        tree_id: u16,
    ) -> Result<ProofInputUtxo, TransactionError> {
        let owner_hash = zolana_keypair::hash::owner_hash(&self.owner, nullifier_pk)?;
        ProofInputUtxo::new(
            owner_hash,
            &self.asset,
            self.amount,
            &self.blinding,
            tree_id,
        )?
        .with_data_hash(*data_hash)
        .with_ring(*ring_data_hash, &self.ring_program_id)
    }

    pub fn hash(
        &self,
        nullifier_pk: &[u8; 32],
        data_hash: &[u8; 32],
        ring_data_hash: &[u8; 32],
        tree_id: u16,
    ) -> Result<[u8; 32], TransactionError> {
        self.proof_input(nullifier_pk, data_hash, ring_data_hash, tree_id)?
            .hash()
    }

    pub fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        nullifier_key: &NullifierKey,
    ) -> Result<[u8; 32], TransactionError> {
        Ok(nullifier_key.nullifier(utxo_hash, &self.blinding)?)
    }

    pub fn to_confidential_output_plaintext(
        &self,
        assets: &AssetRegistry,
    ) -> Result<ConfidentialOutputPlaintext, TransactionError> {
        Ok(ConfidentialOutputPlaintext {
            asset_id: assets.asset_id(&self.asset)?,
            amount: self.amount,
            blinding: self.blinding,
            ring_program_id: self.ring_program_id,
            data: self.data.clone(),
        })
    }
}
