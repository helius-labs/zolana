//! The client-side transaction: the spent input UTXO hashes, the new output
//! UTXO hashes, and the transaction-level [`ExternalData`]. [`EncryptedTransaction::hash`]
//! produces the `private_tx_hash` shared as a public input by the SPP and zone proofs.

use solana_address::Address;
use zolana_keypair::hash::{poseidon, sha256_be};

use crate::error::TransactionError;
use crate::utxo::{owner_utxo_hash, utxo_hash, Blinding, Utxo};

/// Transaction-level public data bound into the proofs through its hash. SPP
/// recomputes the hash on-chain, so the field order in [`ExternalData::hash`]
/// must match the on-chain layout byte-for-byte.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExternalData {
    pub instruction_discriminator: u8,
    pub expiry_unix_ts: u64,
    pub sender_view_tag: [u8; 32],
    pub relayer_fee: u16,
    pub public_sol_amount: u64,
    pub public_spl_amount: u64,
    pub user_sol_account: Address,
    pub user_spl_token: Address,
    pub spl_token_interface: Address,
    pub encrypted_utxos: Vec<u8>,
}

impl ExternalData {
    /// `external_data_hash`: SHA-256 over the concatenated fields, reduced to the
    /// field by zeroing the most-significant byte (see [`sha256_be`]).
    pub fn hash(&self) -> [u8; 32] {
        let mut preimage =
            Vec::with_capacity(1 + 8 + 32 + 2 + 8 + 8 + 32 + 32 + 32 + self.encrypted_utxos.len());
        preimage.push(self.instruction_discriminator);
        preimage.extend_from_slice(&self.expiry_unix_ts.to_be_bytes());
        preimage.extend_from_slice(&self.sender_view_tag);
        preimage.extend_from_slice(&self.relayer_fee.to_be_bytes());
        preimage.extend_from_slice(&self.public_sol_amount.to_be_bytes());
        preimage.extend_from_slice(&self.public_spl_amount.to_be_bytes());
        preimage.extend_from_slice(self.user_sol_account.as_array());
        preimage.extend_from_slice(self.user_spl_token.as_array());
        preimage.extend_from_slice(self.spl_token_interface.as_array());
        preimage.extend_from_slice(&self.encrypted_utxos);
        sha256_be(&preimage)
    }
}

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

/// A new output UTXO. The sender commits to the recipient's `owner_hash`
/// directly, since it only knows the recipient's identity, not its keys.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct OutputUtxo {
    pub owner_hash: [u8; 32],
    pub asset: Address,
    pub amount: u64,
    pub blinding: Blinding,
    pub zone_program_id: Option<Address>,
    pub zone_data_hash: Option<[u8; 32]>,
    pub program_data_hash: Option<[u8; 32]>,
}

impl OutputUtxo {
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        utxo_hash(
            self.asset,
            self.amount,
            &self.program_data_hash.unwrap_or_default(),
            &self.zone_data_hash.unwrap_or_default(),
            self.zone_program_id,
            &owner_utxo_hash(&self.owner_hash, &self.blinding)?,
        )
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
        private_tx_hash(&input_hashes, &output_hashes, &self.external_data.hash())
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
