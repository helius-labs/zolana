use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use solana_address::Address;
pub use zolana_interface::UTXO_DOMAIN;
use zolana_keypair::{
    constants::BLINDING_LEN,
    hash::{sha256_be, split_be_128},
    NullifierKey, PublicKey,
};

/// Domain separator for the persistent-address derivation Poseidon preimage.
/// Distinct from [`UTXO_DOMAIN`] (the per-UTXO `Domain` field); used ONLY inside
/// [`address`].
pub const ADDRESS_DOMAIN: u8 = 2;

use crate::{
    data::Data, error::TransactionError, serialization::confidential::TransferRecipientPlaintext,
    AssetRegistry,
};

fn poseidon(inputs: &[&[u8]]) -> Result<[u8; 32], TransactionError> {
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
        .map_err(|e| TransactionError::Poseidon(e.to_string()))?;
    hasher
        .hash_bytes_be(inputs)
        .map_err(|e| TransactionError::Poseidon(e.to_string()))
}

pub type Blinding = [u8; BLINDING_LEN];

pub fn derive_blinding(seed: &[u8; BLINDING_LEN], position: u8) -> Blinding {
    let mut preimage = [0u8; BLINDING_LEN + 1];
    preimage[..BLINDING_LEN].copy_from_slice(seed);
    preimage[BLINDING_LEN] = position;
    let digest = sha256_be(&preimage);
    let mut out = [0u8; BLINDING_LEN];
    out.copy_from_slice(&digest[1..]);
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub owner: PublicKey,
    pub asset: Address,
    pub amount: u64,
    pub blinding: Blinding,
    /// Persistent address field element (derived via [`address`]) that pairs with
    /// `program_data_hash` in the commitment's `program_hash`. `None` (folded as
    /// `0`) for user-owned UTXOs. NOT a Solana `Address`; a BN254 field element.
    pub address: Option<[u8; 32]>,
    pub zone_program_id: Option<Address>,
    pub data: Data,
}

fn right_align<const N: usize>(bytes: &[u8; N]) -> [u8; 32] {
    const { assert!(N <= 32) }
    let mut out = [0u8; 32];
    out[32 - N..].copy_from_slice(bytes);
    out
}

pub(crate) fn resolve_zone_program_id(
    zone_program_id: Option<Address>,
    data: &Data,
) -> Result<Option<Address>, TransactionError> {
    if data.zone_data().is_none() {
        return Ok(None);
    }
    if zone_program_id.is_none() {
        return Err(TransactionError::MissingZoneProgramId);
    }
    Ok(zone_program_id)
}

pub fn zone_program_id_field(
    zone_program_id: &Option<Address>,
) -> Result<[u8; 32], TransactionError> {
    program_id_field(zone_program_id)
}

/// `pk_field` of an optional program identifier; `0` (not `pk_field(0)`) when
/// absent. Used for both `program_id` and `zone_program_id`.
pub fn program_id_field(program_id: &Option<Address>) -> Result<[u8; 32], TransactionError> {
    match program_id {
        Some(id) => zolana_keypair::hash::hash_field(id.as_array()).map_err(TransactionError::from),
        None => Ok([0u8; 32]),
    }
}

/// Derive a persistent address field element bound to the address tree and the
/// program data: `Poseidon(ADDRESS_DOMAIN, tpk_low, tpk_high, program_data_hash)`
/// where `(tpk_low, tpk_high) = split_be_128(sha256_be(tree_pubkey))`. The address
/// tree is the nullifier tree, so `tree_pubkey` is that account's address.
pub fn address(
    tree_pubkey: &Address,
    program_data_hash: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    let domain = right_align(&[ADDRESS_DOMAIN]);
    let tpk = sha256_be(tree_pubkey.as_array());
    let (tpk_low, tpk_high) = split_be_128(&tpk);
    poseidon(&[&domain, &tpk_low, &tpk_high, program_data_hash])
}

/// Owner commitment carried by transaction outputs and proofless deposits.
pub fn owner_utxo_hash(
    owner_hash: &[u8; 32],
    blinding: &Blinding,
) -> Result<[u8; 32], TransactionError> {
    let blinding = right_align(blinding);
    poseidon(&[owner_hash, &blinding])
}

/// Full UTXO commitment used as the state-tree leaf.
#[allow(clippy::too_many_arguments)]
pub fn utxo_hash(
    asset: Address,
    amount: u64,
    program_data_hash: &[u8; 32],
    address: Option<[u8; 32]>,
    zone_data_hash: &[u8; 32],
    zone_program_id: Option<Address>,
    owner_utxo_hash: &[u8; 32],
) -> Result<[u8; 32], TransactionError> {
    let domain = right_align(&UTXO_DOMAIN.to_be_bytes());
    let asset =
        zolana_keypair::hash::hash_field(asset.as_array()).map_err(TransactionError::from)?;
    let amount = right_align(&amount.to_be_bytes());
    // address (field element) pairs with program_data_hash in program_hash, ordered
    // address FIRST; zone_data_hash pairs with zone_program_id (spec: UTXO Hash).
    let program_hash = poseidon(&[&address.unwrap_or_default(), program_data_hash])?;
    let zone_hash = poseidon(&[zone_data_hash, &program_id_field(&zone_program_id)?])?;
    poseidon(&[
        &domain,
        &asset,
        &amount,
        &program_hash,
        &zone_hash,
        owner_utxo_hash,
    ])
}

impl Utxo {
    /// Owner commitment derived from this wallet's keys.
    pub fn owner_utxo_hash(&self, nullifier_pk: &[u8; 32]) -> Result<[u8; 32], TransactionError> {
        let owner_hash = zolana_keypair::hash::owner_hash(&self.owner, nullifier_pk)?;
        owner_utxo_hash(&owner_hash, &self.blinding)
    }

    /// State-tree leaf commitment for this UTXO.
    pub fn hash(
        &self,
        nullifier_pk: &[u8; 32],
        program_data_hash: &[u8; 32],
        zone_data_hash: &[u8; 32],
    ) -> Result<[u8; 32], TransactionError> {
        utxo_hash(
            self.asset,
            self.amount,
            program_data_hash,
            self.address,
            zone_data_hash,
            self.zone_program_id,
            &self.owner_utxo_hash(nullifier_pk)?,
        )
    }

    pub fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        nullifier_key: &NullifierKey,
    ) -> Result<[u8; 32], TransactionError> {
        Ok(nullifier_key.nullifier(utxo_hash, &self.blinding)?)
    }

    pub fn to_recipient_plaintext(
        &self,
        assets: &AssetRegistry,
    ) -> Result<TransferRecipientPlaintext, TransactionError> {
        Ok(TransferRecipientPlaintext {
            asset_id: assets.asset_id(&self.asset)?,
            amount: self.amount,
            blinding: self.blinding,
            // `Utxo` carries the derived `address` field element, not the program
            // Address; the plaintext's program Address is populated by the builder's
            // program-owned output path, not via this user-utxo helper.
            program_id: None,
            zone_program_id: self.zone_program_id,
            data: self.data.clone(),
        })
    }

    pub fn to_confidential_recipient_plaintext(
        &self,
        assets: &AssetRegistry,
    ) -> Result<TransferRecipientPlaintext, TransactionError> {
        Ok(TransferRecipientPlaintext {
            asset_id: assets.asset_id(&self.asset)?,
            amount: self.amount,
            blinding: self.blinding,
            // `Utxo` carries the derived `address` field element, not the program
            // Address; the plaintext's program Address is populated by the builder's
            // program-owned output path, not via this user-utxo helper.
            program_id: None,
            zone_program_id: self.zone_program_id,
            data: self.data.clone(),
        })
    }
}
