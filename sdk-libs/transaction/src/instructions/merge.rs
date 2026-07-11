//! High-level merge build: [`Merge`] names which UTXOs to consolidate and the
//! derived single output; [`PreparedMerge`] pads to [`MERGE_INPUTS`] and yields
//! the input commitments to fetch Merkle proofs for. Merge proves ownership
//! in-circuit from the nullifier secret, so there is no signing step.

use p256::SecretKey;
use zolana_keypair::{viewing_key::random_blinding, P256Pubkey, PublicKey, ShieldedKeypairTrait};

use crate::{
    error::TransactionError,
    instructions::types::{InputCommitment, SpendUtxo},
    OutputUtxo,
};

/// Fixed input arity of the merge circuit (`merge_8_1`). Real inputs sit at the
/// front; padding fills the rest with dummies.
pub const MERGE_INPUTS: usize = 8;

/// A merge plan: the real UTXOs to consolidate (no Merkle proofs, no padding), the
/// derived single output, and the owner identity. Every input must share one owner
/// (P256 or Solana) and asset.
pub struct Merge {
    inputs: Vec<SpendUtxo>,
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
        inputs: Vec<SpendUtxo>,
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
        let owner = keypair.signing_pubkey();
        let owner_rail = keypair.curve()?;
        let nullifier_pubkey = keypair.nullifier_key().pubkey()?;
        let mut total = 0u64;
        for (index, spend) in inputs.iter().enumerate() {
            if spend.utxo.owner.signature_type()? != owner_rail {
                return Err(TransactionError::MergeInputRailMismatch { index });
            }
            if spend.utxo.owner != owner {
                return Err(TransactionError::MergeInputOwnerMismatch { index });
            }
            if spend.nullifier_key.pubkey()? != nullifier_pubkey {
                return Err(TransactionError::MergeInputNullifierKeyMismatch { index });
            }
            if spend.utxo.asset != asset {
                return Err(TransactionError::MergeInputAssetMismatch { index });
            }
            if spend.utxo.zone_program_id.is_some() {
                return Err(TransactionError::MergeInputZoneMismatch { index });
            }
            if spend.data_hash.unwrap_or_default() != [0u8; 32]
                || spend.zone_data_hash.unwrap_or_default() != [0u8; 32]
                || spend.utxo.data.utxo_data().is_some()
                || spend.utxo.data.zone_data().is_some()
            {
                return Err(TransactionError::MergeInputHasData { index });
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
            inputs.push(SpendUtxo::new_dummy());
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
/// still proofless. [`Self::input_commitments`] yields what to fetch Merkle proofs
/// for.
pub struct PreparedMerge {
    pub inputs: Vec<SpendUtxo>,
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

#[cfg(test)]
mod tests {
    use solana_address::Address;
    use zolana_keypair::ShieldedKeypair;

    use super::*;
    use crate::{Data, DataRecord, Utxo, SOL_MINT};

    #[test]
    fn merge_rejects_another_p256_owners_note_before_proving() {
        let owner = ShieldedKeypair::new().unwrap();
        let other = ShieldedKeypair::new().unwrap();
        let input = SpendUtxo::from_keypair(
            Utxo {
                owner: other.signing_pubkey(),
                asset: SOL_MINT,
                amount: 10,
                blinding: [1u8; 31],
                zone_program_id: None,
                data: Data::default(),
            },
            &owner,
        );

        assert!(matches!(
            Merge::new(&owner, vec![input]),
            Err(TransactionError::MergeInputOwnerMismatch { index: 0 })
        ));
    }

    #[test]
    fn merge_rejects_another_nullifier_key_before_proving() {
        let owner = ShieldedKeypair::new().unwrap();
        let other = ShieldedKeypair::new().unwrap();
        let input = SpendUtxo::from_keypair(
            Utxo {
                owner: owner.signing_pubkey(),
                asset: SOL_MINT,
                amount: 10,
                blinding: [1u8; 31],
                zone_program_id: None,
                data: Data::default(),
            },
            &other,
        );

        assert!(matches!(
            Merge::new(&owner, vec![input]),
            Err(TransactionError::MergeInputNullifierKeyMismatch { index: 0 })
        ));
    }

    #[test]
    fn merge_rejects_zone_and_data_notes_before_proving() {
        let owner = ShieldedKeypair::new().unwrap();
        let input = |zone_program_id, data| {
            SpendUtxo::from_keypair(
                Utxo {
                    owner: owner.signing_pubkey(),
                    asset: SOL_MINT,
                    amount: 10,
                    blinding: [1u8; 31],
                    zone_program_id,
                    data,
                },
                &owner,
            )
        };

        assert!(matches!(
            Merge::new(
                &owner,
                vec![input(
                    Some(Address::new_from_array([9u8; 32])),
                    Data::default()
                )]
            ),
            Err(TransactionError::MergeInputZoneMismatch { index: 0 })
        ));
        assert!(matches!(
            Merge::new(
                &owner,
                vec![input(None, Data::new(vec![DataRecord::UtxoData(vec![1])]))]
            ),
            Err(TransactionError::MergeInputHasData { index: 0 })
        ));
    }
}
