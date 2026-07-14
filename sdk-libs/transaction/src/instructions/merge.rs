//! High-level merge build: [`Merge`] names which UTXOs to consolidate and the
//! derived single output; [`PreparedMerge`] pads to [`MERGE_INPUTS`] and yields
//! the input commitments to fetch Merkle proofs for. Merge proves ownership
//! in-circuit from the nullifier secret, so there is no signing step.

use p256::SecretKey;
use zolana_keypair::{viewing_key::random_blinding, P256Pubkey, PublicKey, ShieldedKeypairTrait};

use crate::{
    error::TransactionError,
    instructions::types::{InputUtxoContext, SppProofInputUtxo},
    OutputUtxo,
};

/// Fixed input arity of the merge circuit (`merge_8_1`). Real inputs sit at the
/// front; padding fills the rest with dummies.
pub const MERGE_INPUTS: usize = 8;

/// A merge plan: the real UTXOs to consolidate (no Merkle proofs, no padding), the
/// derived single output, and the owner identity. Every input must share one owner
/// (P256 or Solana) and asset.
pub struct Merge {
    inputs: Vec<SppProofInputUtxo>,
    output: OutputUtxo,
    expiry_unix_ts: u64,
    signing_pubkey: PublicKey,
    user_viewing_pk: P256Pubkey,
    tx_viewing_sk: SecretKey,
}

impl Merge {
    /// Validate the inputs, derive the merged output, and bind the owner identity
    /// and a fresh ephemeral viewing scalar from the keypair.
    pub fn new<K: ShieldedKeypairTrait>(
        keypair: &K,
        inputs: Vec<SppProofInputUtxo>,
    ) -> Result<Self, TransactionError> {
        if inputs.is_empty() {
            return Err(TransactionError::NoInputs);
        }
        if inputs.len() > MERGE_INPUTS {
            return Err(TransactionError::TooManyInputs {
                got: inputs.len(),
                max: MERGE_INPUTS,
            });
        }

        let asset = inputs.first().ok_or(TransactionError::NoInputs)?.utxo.asset;
        // The proof binds every input to one shared owner identity, so the merge
        // rail is the owner's rail and every input must match it.
        let owner_rail = keypair.curve()?;
        let mut total = 0u64;
        for (index, spend) in inputs.iter().enumerate() {
            if spend.utxo.owner.signature_type()? != owner_rail {
                return Err(TransactionError::MergeInputRailMismatch { index });
            }
            if spend.utxo.asset != asset {
                return Err(TransactionError::MergeInputAssetMismatch { index });
            }
            total = total
                .checked_add(spend.utxo.amount)
                .ok_or(TransactionError::SelectedBalanceOverflow)?;
        }

        let output = OutputUtxo::new(asset, total, keypair.shielded_address()?)?;

        // Ephemeral viewing scalar: 31 random bytes are < BN254 modulus, so the
        // value is both a valid P-256 scalar and a valid circuit witness.
        let mut sk_bytes = [0u8; 32];
        sk_bytes[1..].copy_from_slice(&random_blinding());
        let tx_viewing_sk =
            SecretKey::from_slice(&sk_bytes).map_err(|e| TransactionError::P256(e.to_string()))?;

        Ok(Self {
            inputs,
            output,
            // Never expires by default; `merge_transact` rejects `current_ts >
            // expiry`, so set this explicitly for a relayer deadline.
            expiry_unix_ts: u64::MAX,
            signing_pubkey: keypair.signing_pubkey(),
            user_viewing_pk: keypair.viewing_pubkey(),
            tx_viewing_sk,
        })
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.expiry_unix_ts = expiry_unix_ts;
        self
    }

    /// Pad to [`MERGE_INPUTS`] with dummy inputs (real inputs first), producing the
    /// proofless [`PreparedMerge`].
    pub fn prepare(self) -> PreparedMerge {
        let Merge {
            mut inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            user_viewing_pk,
            tx_viewing_sk,
        } = self;
        while inputs.len() < MERGE_INPUTS {
            inputs.push(SppProofInputUtxo::new_dummy());
        }
        PreparedMerge {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            user_viewing_pk,
            tx_viewing_sk,
        }
    }
}

/// A merge padded to [`MERGE_INPUTS`] (real inputs first, dummies at the tail),
/// still proofless. [`Self::input_utxo_hashes`] yields what to fetch Merkle proofs
/// for.
pub struct PreparedMerge {
    pub inputs: Vec<SppProofInputUtxo>,
    pub output: OutputUtxo,
    pub expiry_unix_ts: u64,
    pub signing_pubkey: PublicKey,
    pub user_viewing_pk: P256Pubkey,
    pub tx_viewing_sk: SecretKey,
}

impl PreparedMerge {
    /// Commitments for the real inputs only; dummy padding has a zero owner and no
    /// meaningful commitment to look up. Merge assembly only supports clean inputs,
    /// so an input that committed to program or zone data is rejected.
    pub fn input_utxo_hashes(&self) -> Result<Vec<InputUtxoContext>, TransactionError> {
        self.inputs
            .iter()
            .filter(|spend| !spend.is_dummy())
            .enumerate()
            .map(|(index, spend)| {
                if spend.data_hash.unwrap_or_default() != [0u8; 32]
                    || spend.zone_data_hash.unwrap_or_default() != [0u8; 32]
                {
                    return Err(TransactionError::MergeInputHasData { index });
                }
                Ok(InputUtxoContext {
                    index,
                    utxo_hash: spend.hash()?,
                    nullifier: spend.nullifier()?,
                })
            })
            .collect()
    }
}
