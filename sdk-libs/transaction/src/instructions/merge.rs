//! High-level merge build: [`Merge`] names which UTXOs to consolidate and the
//! derived single output; [`PreparedMerge`] pads to [`MERGE_INPUTS`] and yields
//! the input commitments to fetch Merkle proofs for. Merge proves ownership
//! in-circuit from the nullifier secret, so there is no signing step.

use solana_address::Address;
use zolana_keypair::{merge::merge_output_blinding, PublicKey, ShieldedKeypairTrait};

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
}

impl Merge {
    /// Validate the inputs, derive the merged output, and bind the owner identity
    /// and a fresh ephemeral viewing scalar from the keypair.
    pub fn new<K: ShieldedKeypairTrait>(
        keypair: &K,
        inputs: Vec<SppProofInputUtxo>,
    ) -> Result<Self, TransactionError> {
        // The default merge only consolidates plain utxos: no input may be bound
        // to a zone or carry program/zone data.
        let (asset, total) = validate_merge_inputs(keypair, &inputs, |index, spend| {
            if spend.utxo.zone_program_id.is_some() {
                return Err(TransactionError::MergeInputZoneMismatch { index });
            }
            if has_data(spend) {
                return Err(TransactionError::MergeInputHasData { index });
            }
            Ok(())
        })?;

        // The output blinding is derived, not random: slot 0 is always real
        // (validation rejects empty inputs), and the circuit derives the same
        // value from the first input's blinding and nullifier. The
        // wallet later reconstructs the output the same way.
        let first_nullifier = inputs[0].nullifier()?;
        let mut output = SppProofOutputUtxo::new(asset, total, keypair.shielded_address()?)?;
        output.blinding = merge_output_blinding(&inputs[0].utxo.blinding, &first_nullifier)?;

        Ok(Self {
            inputs,
            output,
            // Never expires by default; `merge_transact` rejects `current_ts >
            // expiry`, so set this explicitly for a relayer deadline.
            expiry_unix_ts: u64::MAX,
            signing_pubkey: keypair.signing_pubkey(),
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
        } = self;
        pad_with_dummies(&mut inputs);
        PreparedMerge {
            inputs,
            output,
            expiry_unix_ts,
            signing_pubkey,
        }
    }
}

/// The validation both merge rails share: 1..=[`MERGE_INPUTS`] inputs bound to
/// one owner identity -- the proof binds every input to a single rail, exact
/// owner, and nullifier key from `keypair` -- and one asset. `check` adds the
/// rail's zone-binding and data policy per input. Returns the shared asset and
/// the overflow-checked merged amount.
pub(crate) fn validate_merge_inputs<K: ShieldedKeypairTrait>(
    keypair: &K,
    inputs: &[SppProofInputUtxo],
    check: impl Fn(usize, &SppProofInputUtxo) -> Result<(), TransactionError>,
) -> Result<(Address, u64), TransactionError> {
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
        check(index, spend)?;
        total = total
            .checked_add(spend.utxo.amount)
            .ok_or(TransactionError::SelectedBalanceOverflow)?;
    }
    Ok((asset, total))
}

/// Pad to [`MERGE_INPUTS`] with dummy inputs, real inputs first.
pub(crate) fn pad_with_dummies(inputs: &mut Vec<SppProofInputUtxo>) {
    while inputs.len() < MERGE_INPUTS {
        inputs.push(SppProofInputUtxo::new_dummy());
    }
}

/// Commitments for the real inputs only; dummy padding has a zero owner and no
/// meaningful commitment to look up. `has_disqualifying_data` re-applies the
/// rail's data policy so a prepared plan cannot smuggle in an input its rail
/// rejects.
pub(crate) fn real_input_contexts(
    inputs: &[SppProofInputUtxo],
    has_disqualifying_data: impl Fn(&SppProofInputUtxo) -> bool,
) -> Result<Vec<InputUtxoContext>, TransactionError> {
    inputs
        .iter()
        .filter(|spend| !spend.is_dummy())
        .enumerate()
        .map(|(index, spend)| {
            if has_disqualifying_data(spend) {
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

/// A merge padded to [`MERGE_INPUTS`] (real inputs first, dummies at the tail),
/// still proofless. [`Self::input_utxo_hashes`] yields what to fetch Merkle proofs
/// for.
pub struct PreparedMerge {
    pub inputs: Vec<SppProofInputUtxo>,
    pub output: SppProofOutputUtxo,
    pub expiry_unix_ts: u64,
    pub signing_pubkey: PublicKey,
}

impl PreparedMerge {
    /// Commitments for the real inputs only. Merge assembly only supports clean
    /// inputs, so an input that committed to program or zone data is rejected.
    pub fn input_utxo_hashes(&self) -> Result<Vec<InputUtxoContext>, TransactionError> {
        real_input_contexts(&self.inputs, has_data)
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
        seed.copy_from_slice(&random_blinding());
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
