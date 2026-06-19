//! The client-side transaction: the spent input UTXO hashes, the new output
//! UTXO hashes, and the transaction-level [`ExternalData`]. [`EncryptedTransaction::hash`]
//! produces the `private_tx_hash` shared as a public input by the SPP and zone proofs.

use solana_address::Address;
use zolana_interface::event::OutputUtxo as OutputSlot;
use zolana_interface::instruction::instruction_data::deposit::CpiSignerData;
use zolana_interface::instruction::instruction_data::transact::ExternalDataHash;
use zolana_keypair::hash::poseidon;

use crate::error::TransactionError;
use crate::utxo::{owner_utxo_hash, utxo_hash, Blinding, Utxo};

/// Transaction-level public data bound into the proofs through `external_data_hash`.
/// The hash is computed by the canonical [`ExternalDataHash`] from the interface
/// crate, so the client and the on-chain program agree byte-for-byte. The output
/// ciphertexts live per slot in `output_slots` (slot 0 is the sender bundle).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalData {
    pub instruction_discriminator: u8,
    pub expiry_unix_ts: u64,
    pub relayer_fee: u16,
    pub public_sol_amount: Option<i64>,
    pub public_spl_amount: Option<i64>,
    pub user_sol_account: Address,
    pub user_spl_token: Address,
    pub spl_token_interface: Address,
    pub cpi_signer: Option<CpiSignerData>,
    pub tx_viewing_pk: [u8; 33],
    pub salt: [u8; 16],
    /// Per-output slots in tree-append order, length equal to the proof shape's
    /// output count. Slot 0 is `sender_utxo_data`; the rest are `recipient_utxo_data`.
    pub output_slots: Vec<OutputSlot>,
}

impl ExternalData {
    /// `external_data_hash` via the canonical interface [`ExternalDataHash`].
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        let (sender, recipients) = self
            .output_slots
            .split_first()
            .ok_or(TransactionError::MissingOutput)?;
        Ok(ExternalDataHash {
            spp_instruction_discriminator: self.instruction_discriminator,
            expiry_unix_ts: self.expiry_unix_ts,
            relayer_fee: self.relayer_fee,
            public_sol_amount: self.public_sol_amount,
            public_spl_amount: self.public_spl_amount,
            user_sol_account: self.user_sol_account.as_array(),
            user_spl_token_account: self.user_spl_token.as_array(),
            spl_token_interface: self.spl_token_interface.as_array(),
            cpi_signer: self.cpi_signer,
            sender_utxo_data: sender,
            recipient_utxo_data: recipients,
        }
        .hash()
        .map_err(|e| TransactionError::Hash(format!("{e:?}")))?)
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
