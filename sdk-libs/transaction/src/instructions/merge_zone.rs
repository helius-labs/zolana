//! High-level policy-zone merge build: [`MergeZone`] names which UTXOs to
//! consolidate, the derived single output, and the zone program every input is
//! owned by; [`PreparedMergeZone`] pads to [`MERGE_INPUTS`] and yields the input
//! commitments to fetch Merkle proofs for. Like the default merge, the merge-zone
//! proof proves ownership in-circuit from the nullifier secret, so there is no
//! signing step. The only delta vs the default merge is that every input (and the
//! merged output) is bound to a shared `zone_program_id`.

use p256::SecretKey;
use solana_address::Address;
use zolana_keypair::{viewing_key::random_blinding, P256Pubkey, PublicKey, ShieldedKeypairTrait};

use crate::{
    error::TransactionError,
    instructions::{
        merge::MERGE_INPUTS,
        types::{InputCommitment, SpendUtxo},
    },
    OutputUtxo,
};

/// A policy-zone merge plan: the real UTXOs to consolidate (no Merkle proofs, no
/// padding), the derived single output, the owner identity, and the zone program
/// every input is owned by. Every input must share one owner (P256 or Solana),
/// asset, and `zone_program_id`.
pub struct MergeZone {
    inputs: Vec<SpendUtxo>,
    output: OutputUtxo,
    expiry_unix_ts: u64,
    signing_pubkey: PublicKey,
    user_viewing_pk: P256Pubkey,
    tx_viewing_sk: SecretKey,
    zone_program_id: Address,
}

impl MergeZone {
    /// Validate the inputs, derive the merged output bound to `zone_program_id`,
    /// and bind the owner identity and a fresh ephemeral viewing scalar from the
    /// keypair.
    pub fn new<K: ShieldedKeypairTrait>(
        keypair: &K,
        inputs: Vec<SpendUtxo>,
        zone_program_id: Address,
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
            // The policy-zone merge consolidates only UTXOs already owned by the
            // calling zone, so every input must carry exactly this zone_program_id.
            if spend.utxo.zone_program_id != Some(zone_program_id) {
                return Err(TransactionError::MergeInputZoneMismatch { index });
            }
            total = total
                .checked_add(spend.utxo.amount)
                .ok_or(TransactionError::SelectedBalanceOverflow)?;
        }

        let output = OutputUtxo {
            owner_address: Some(keypair.shielded_address()?),
            asset,
            amount: total,
            blinding: random_blinding(),
            // The merged output preserves zone ownership.
            zone_program_id: Some(zone_program_id),
            ..Default::default()
        };

        // Ephemeral viewing scalar: 31 random bytes are < BN254 modulus, so the
        // value is both a valid P-256 scalar and a valid circuit witness.
        let mut sk_bytes = [0u8; 32];
        sk_bytes[1..].copy_from_slice(&random_blinding());
        let tx_viewing_sk =
            SecretKey::from_slice(&sk_bytes).map_err(|e| TransactionError::P256(e.to_string()))?;

        Ok(Self {
            inputs,
            output,
            // Never expires by default; `merge_zone` rejects `current_ts >
            // expiry`, so set this explicitly for a relayer deadline.
            expiry_unix_ts: u64::MAX,
            signing_pubkey: keypair.signing_pubkey(),
            user_viewing_pk: keypair.viewing_pubkey(),
            tx_viewing_sk,
            zone_program_id,
        })
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.expiry_unix_ts = expiry_unix_ts;
        self
    }

    /// Pad to [`MERGE_INPUTS`] with dummy inputs (real inputs first), producing the
    /// proofless [`PreparedMergeZone`].
    pub fn prepare(self) -> PreparedMergeZone {
        let MergeZone {
            mut inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            user_viewing_pk,
            tx_viewing_sk,
            zone_program_id,
        } = self;
        while inputs.len() < MERGE_INPUTS {
            inputs.push(SpendUtxo::new_dummy());
        }
        PreparedMergeZone {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
            user_viewing_pk,
            tx_viewing_sk,
            zone_program_id,
        }
    }
}

/// A policy-zone merge padded to [`MERGE_INPUTS`] (real inputs first, dummies at
/// the tail), still proofless. Carries the shared `zone_program_id` the proof
/// commits. [`Self::input_commitments`] yields what to fetch Merkle proofs for.
pub struct PreparedMergeZone {
    pub inputs: Vec<SpendUtxo>,
    pub output: OutputUtxo,
    pub expiry_unix_ts: u64,
    pub signing_pubkey: PublicKey,
    pub user_viewing_pk: P256Pubkey,
    pub tx_viewing_sk: SecretKey,
    pub zone_program_id: Address,
}

impl PreparedMergeZone {
    /// Commitments for the real inputs only; dummy padding has a zero owner and no
    /// meaningful commitment to look up. Merge assembly only supports clean inputs,
    /// so an input that committed to program or zone data is rejected.
    pub fn input_commitments(&self) -> Result<Vec<InputCommitment>, TransactionError> {
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
                let nullifier_pubkey = spend.nullifier_key.pubkey()?;
                let utxo_hash = spend.utxo.hash(&nullifier_pubkey, &[0u8; 32], &[0u8; 32])?;
                let nullifier = spend
                    .nullifier_key
                    .nullifier(&utxo_hash, &spend.utxo.blinding)?;
                Ok(InputCommitment {
                    index,
                    utxo_hash,
                    nullifier,
                })
            })
            .collect()
    }
}
