//! High-level merge build: [`Merge`] names which UTXOs to consolidate and the
//! derived single output; [`PreparedMerge`] pads to [`MERGE_INPUTS`] and yields
//! the input commitments to fetch Merkle proofs for. Merge proves ownership
//! in-circuit from the nullifier secret, so there is no signing step.

use p256::SecretKey;
use zolana_keypair::{viewing_key::random_blinding, P256Pubkey, PublicKey, ShieldedKeypairTrait};

use crate::{
    error::TransactionError,
    instructions::types::{InputUtxoContext, SppProofInputUtxo},
    SppProofOutputUtxo,
};

/// Fixed input arity of the merge circuit (`merge_8_1`). Real inputs sit at the
/// front; padding fills the rest with dummies.
pub const MERGE_INPUTS: usize = 8;

/// A merge plan: the real UTXOs to consolidate (no Merkle proofs, no padding), the
/// derived single output, and the owner identity. Every input must share one owner
/// (P256 or Solana) and asset.
pub struct Merge {
    inputs: Vec<SppProofInputUtxo>,
    output: SppProofOutputUtxo,
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
        // rail is the owner's rail and every input must match it. It also proves
        // ownership from one nullifier secret and never consumes program/zone data,
        // so every input must carry exactly the keypair's owner and nullifier key
        // and be a plain, unbound utxo.
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
            // The default merge only consolidates plain utxos, so no input may be
            // bound to a zone.
            if spend.utxo.zone_program_id.is_some() {
                return Err(TransactionError::MergeInputZoneMismatch { index });
            }
            if has_data(spend) {
                return Err(TransactionError::MergeInputHasData { index });
            }
            total = total
                .checked_add(spend.utxo.amount)
                .ok_or(TransactionError::SelectedBalanceOverflow)?;
        }

        let output = SppProofOutputUtxo::new(asset, total, keypair.shielded_address()?)?;

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
    pub output: SppProofOutputUtxo,
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
                if has_data(spend) {
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

/// Whether an input carries program or zone data: an external `data_hash`,
/// `zone_data_hash`, or inline UTXO data. Default-zone merge and split consolidate
/// only plain utxos, so any of these disqualifies the input. Option semantics: a
/// `Some(_)` hash means "has data" regardless of the hash value (an all-zero hash
/// still binds committed data).
pub(crate) fn has_data(spend: &SppProofInputUtxo) -> bool {
    spend.data_hash.is_some() || spend.zone_data_hash.is_some() || !spend.utxo.data.is_empty()
}

/// Whether an input carries program-controlled UTXO data. Policy-zone merges may
/// consume `zone_data_hash` values after the zone has authorized their transition,
/// but `utxo_data` remains owner/program controlled and is never mergeable.
pub(crate) fn has_utxo_data(spend: &SppProofInputUtxo) -> bool {
    spend.data_hash.is_some() || spend.utxo.data.utxo_data().is_some()
}

#[cfg(test)]
mod tests {
    use solana_address::Address;
    use zolana_keypair::{viewing_key::random_blinding, ShieldedKeypair, ViewingKey};

    use super::*;
    use crate::{data::DataRecord, utxo::Utxo, Data};

    fn plain_input(keypair: &ShieldedKeypair, asset: Address, amount: u64) -> SppProofInputUtxo {
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset,
            amount,
            blinding: random_blinding(),
            zone_program_id: None,
            data: Data::default(),
        };
        SppProofInputUtxo::new(utxo, keypair)
    }

    #[test]
    fn accepts_matching_plain_inputs_and_pads_to_shape() {
        let keypair = ShieldedKeypair::new().expect("keypair");
        let inputs = vec![
            plain_input(&keypair, Address::default(), 10),
            plain_input(&keypair, Address::default(), 20),
        ];

        let prepared = Merge::new(&keypair, inputs).expect("merge plan").prepare();

        assert_eq!(prepared.inputs.len(), MERGE_INPUTS);
        assert_eq!(prepared.output.amount, 30);
    }

    #[test]
    fn rejects_input_owned_by_a_different_key() {
        let keypair = ShieldedKeypair::new().expect("keypair");
        let other = ShieldedKeypair::new().expect("other keypair");
        // Same rail (both P256), different owner: the exact-owner check fires.
        let mut input = plain_input(&keypair, Address::default(), 10);
        input.utxo.owner = other.signing_pubkey();

        let Err(error) = Merge::new(&keypair, vec![input]) else {
            panic!("foreign owner must be rejected");
        };

        assert_eq!(
            error,
            TransactionError::MergeInputOwnerMismatch { index: 0 }
        );
    }

    #[test]
    fn rejects_input_with_a_different_nullifier_key() {
        let keypair = ShieldedKeypair::new().expect("keypair");
        let other = ShieldedKeypair::new().expect("other keypair");
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: Address::default(),
            amount: 10,
            blinding: random_blinding(),
            zone_program_id: None,
            data: Data::default(),
        };
        let input = SppProofInputUtxo::new(utxo, &other);

        let Err(error) = Merge::new(&keypair, vec![input]) else {
            panic!("foreign nullifier key must be rejected");
        };

        assert_eq!(
            error,
            TransactionError::MergeInputNullifierKeyMismatch { index: 0 }
        );
    }

    #[test]
    fn rejects_zone_bound_input() {
        let keypair = ShieldedKeypair::new().expect("keypair");
        let mut input = plain_input(&keypair, Address::default(), 10);
        input.utxo.zone_program_id = Some(Address::new_from_array([3u8; 32]));

        let Err(error) = Merge::new(&keypair, vec![input]) else {
            panic!("zone-bound input must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputZoneMismatch { index: 0 });
    }

    #[test]
    fn rejects_input_carrying_inline_data() {
        let keypair = ShieldedKeypair::new().expect("keypair");
        let mut input = plain_input(&keypair, Address::default(), 10);
        input.utxo.data = Data::new(vec![DataRecord::Memo(b"utxo".to_vec())]);

        let Err(error) = Merge::new(&keypair, vec![input]) else {
            panic!("input carrying data must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputHasData { index: 0 });
    }

    #[test]
    fn rejects_input_carrying_a_committed_data_hash() {
        let keypair = ShieldedKeypair::new().expect("keypair");
        let input = plain_input(&keypair, Address::default(), 10).with_data_hash([1u8; 32]);

        let Err(error) = Merge::new(&keypair, vec![input]) else {
            panic!("committed data hash must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputHasData { index: 0 });
    }

    #[test]
    fn rejects_input_on_a_different_rail() {
        let mut seed = [0u8; 32];
        seed[1..].copy_from_slice(&random_blinding());
        let eddsa = ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("eddsa keypair");
        let p256 = ShieldedKeypair::new().expect("p256 keypair");
        // A P256-owned input under an ed25519 merging keypair mismatches the rail.
        let input = plain_input(&p256, Address::default(), 10);

        let Err(error) = Merge::new(&eddsa, vec![input]) else {
            panic!("rail mismatch must be rejected");
        };

        assert_eq!(error, TransactionError::MergeInputRailMismatch { index: 0 });
    }
}
